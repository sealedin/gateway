package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/sealedin/gateway/internal/egress/upstream"
	"github.com/sealedin/gateway/internal/httpjson"
)

const (
	maxRequest  = 32 << 20
	maxInFlight = 64 // each in-flight request may buffer a body

	statusClientGone = "client_gone"
)

// NewMux serves the one endpoint LiteLLM needs; models is the measured allowlist with each model's output limit, checked
// before any provider lookup.
func NewMux(up upstream.Provider, models map[string]int, log *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()
	slots := make(chan struct{}, maxInFlight)
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			log.Error("egress: at capacity, refusing a request", "slots", maxInFlight)
			writeError(w, http.StatusServiceUnavailable, "egress at capacity")
			return
		}
		handle(w, r, up, models, log)
	})
	return mux
}

func handle(w http.ResponseWriter, r *http.Request, up upstream.Provider, models map[string]int, log *slog.Logger) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			writeError(w, http.StatusRequestEntityTooLarge, "request body over limit")
			return
		}
		writeError(w, http.StatusBadRequest, "request body unreadable")
		return
	}
	fields, err := decodeRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "request must be a JSON object naming a model")
		return
	}
	model, stream := fields.model(), fields.stream()
	maxOutput, ok := models[model]
	if !ok {
		writeError(w, http.StatusNotFound, "model not in the measured catalog")
		return
	}
	if body, err = fields.prepare(maxOutput); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	line := &callLine{model: model, stream: stream, start: time.Now(), status: strconv.Itoa(http.StatusOK)}
	defer line.emit(log) // deferred: a failed reply below leaves by panicking
	reply, err := up.Invoke(r.Context(), model, r.URL.Path, stream, body, &line.call)
	if err != nil {
		line.status = refusalStatus(err)
		status, msg := classify(err)
		log.Warn("egress: request refused", "model", model, "status", status, "err", err)
		writeError(w, status, msg)
		return
	}
	writeReply(w, reply, len(body), log, line)
}

func writeReply(w http.ResponseWriter, reply *upstream.Reply, promptBytes int, log *slog.Logger, line *callLine) {
	defer func() { _ = reply.Body.Close() }()
	w.Header().Set("Content-Type", reply.ContentType)
	if line.stream {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
	}
	w.WriteHeader(http.StatusOK)
	if line.stream {
		relayWithUsage(flushWriter{w}, reply.Body, line.model, promptBytes, log, line)
		return
	}
	if _, err := io.Copy(w, reply.Body); err != nil {
		// Headers are out: abort the connection so a truncated reply never reads as a complete answer.
		line.status = statusClientGone
		log.Warn("egress: reply failed", "model", line.model, "err", err)
		panic(http.ErrAbortHandler)
	}
}

// callLine is the one log entry of an upstream call: routing, timing and counts, nothing that could tie it to a buyer.
type callLine struct {
	model  string
	stream bool
	start  time.Time
	status string // the upstream's code, or what ended the call
	call   upstream.Call
}

func (l *callLine) emit(log *slog.Logger) {
	attrs := []any{"model", l.model, "chute", l.call.Chute, "instance", l.call.Instance, "stream", l.stream, "status", l.status,
		"attest_wait_ms", l.call.AttestWait.Milliseconds()}
	if !l.call.Sent.IsZero() && !l.call.FirstByte.IsZero() {
		attrs = append(attrs, "first_byte_ms", l.call.FirstByte.Sub(l.call.Sent).Milliseconds())
	}
	attrs = append(attrs, "total_ms", time.Since(l.start).Milliseconds())
	if l.call.CompletionTokens != nil {
		attrs = append(attrs, "completion_tokens", *l.call.CompletionTokens)
	}
	log.Info("egress: upstream call", attrs...)
}

// refusalStatus names why a call produced no reply, for the log only; the client's answer is classify's.
func refusalStatus(err error) string {
	var refusal *upstream.Error
	switch {
	case errors.Is(err, context.Canceled):
		return statusClientGone
	case errors.Is(err, upstream.ErrUnknownModel):
		return "unknown_model"
	case errors.Is(err, upstream.ErrNotConfidential):
		return "not_confidential"
	case errors.Is(err, upstream.ErrNoAttestedInstance):
		return "no_attested_instance"
	case errors.As(err, &refusal):
		return strconv.Itoa(refusal.Status)
	default:
		return "upstream_error"
	}
}

// classify maps provider errors to a status and a client-safe message; details stay in the log.
func classify(err error) (int, string) {
	var refusal *upstream.Error
	switch {
	case errors.Is(err, upstream.ErrUnknownModel), errors.Is(err, upstream.ErrNotConfidential):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, upstream.ErrNoAttestedInstance):
		return http.StatusServiceUnavailable, "no attested upstream instance for this model: " + err.Error()
	case errors.As(err, &refusal):
		if refusal.Status == http.StatusTooManyRequests || refusal.Status == http.StatusBadRequest {
			return refusal.Status, fmt.Sprintf("upstream refused the request (HTTP %d)", refusal.Status)
		}
		return http.StatusBadGateway, fmt.Sprintf("upstream returned HTTP %d", refusal.Status)
	default:
		return http.StatusBadGateway, "upstream request failed"
	}
}

type errorBody struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	var body errorBody
	body.Error.Message, body.Error.Type = msg, "egress_error"
	httpjson.Write(w, status, body)
}

type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}
