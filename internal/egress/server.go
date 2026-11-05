package egress

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/sealedin/gateway/internal/egress/upstream"
	"github.com/sealedin/gateway/internal/httpjson"
)

const (
	maxRequest  = 32 << 20
	maxInFlight = 64 // each in-flight request may buffer a body
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
	reply, err := up.Invoke(r.Context(), model, r.URL.Path, stream, body)
	if err != nil {
		status, msg := classify(err)
		log.Warn("egress: request refused", "model", model, "status", status, "err", err)
		writeError(w, status, msg)
		return
	}
	defer func() { _ = reply.Body.Close() }()
	w.Header().Set("Content-Type", reply.ContentType)
	if stream {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
	}
	w.WriteHeader(http.StatusOK)
	if stream {
		relayWithUsage(flushWriter{w}, reply.Body, model, len(body), log)
		return
	}
	if _, err = io.Copy(w, reply.Body); err != nil {
		// Headers are out: abort the connection so a truncated reply never reads as a complete answer.
		log.Warn("egress: reply failed", "model", model, "err", err)
		panic(http.ErrAbortHandler)
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
