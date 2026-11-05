package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"
)

const (
	doneLine = "data: [DONE]"
	jsonNull = "null"
	// bytesPerToken estimates tokens only for a stream that ended with no usage chunk: a rule of thumb.
	bytesPerToken = 4
	// litellmDefaultOutput is DEFAULT_MAX_OUTPUT_TOKENS_FALLBACK in the pinned LiteLLM: its estimate for a request naming no limit.
	litellmDefaultOutput = 16384
)

var (
	errOutputLimit = errors.New("max_tokens must be a positive integer")
	errChoices     = errors.New("only one choice per request: n must be 1")
	errOptions     = errors.New("stream_options must be a JSON object")
)

// requestFields is a body by its exact keys, as the upstream reads them: a struct decode folds case and sees another request.
type requestFields map[string]json.RawMessage

func decodeRequest(body []byte) (requestFields, error) {
	var fields requestFields
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	if fields.model() == "" {
		return nil, errors.New("no model")
	}
	return fields, nil
}

func (f requestFields) model() string {
	var model string
	if json.Unmarshal(f["model"], &model) != nil {
		return ""
	}
	return model
}

func (f requestFields) stream() bool {
	return string(f["stream"]) == "true"
}

// prepare fixes what a metered request must carry upstream and encodes it.
func (f requestFields) prepare(maxOutput int) ([]byte, error) {
	if raw, ok := f["n"]; ok && string(raw) != jsonNull && string(raw) != "1" {
		return nil, errChoices
	}
	if err := f.clampOutput(maxOutput); err != nil {
		return nil, err
	}
	if f.stream() {
		if err := f.forceUsage(); err != nil {
			return nil, err
		}
	}
	return json.Marshal(f)
}

// clampOutput holds a request to LiteLLM's estimate, the lowest figure named or the model's limit, so asking for more buys nothing.
// LiteLLM estimates on one of these and passes them all on; max_tokens always carries the result, as the one an upstream honours.
func (f requestFields) clampOutput(limit int) error {
	allowed := 0
	var named []string
	for _, field := range []string{"max_completion_tokens", "max_tokens", "max_output_tokens"} {
		raw, ok := f[field]
		if !ok || string(raw) == jsonNull {
			continue
		}
		var requested int
		if json.Unmarshal(raw, &requested) != nil || requested < 1 {
			return errOutputLimit
		}
		named = append(named, field)
		if allowed == 0 || requested < allowed {
			allowed = requested
		}
	}
	if allowed == 0 {
		allowed = litellmDefaultOutput
	}
	allowed = min(allowed, limit)
	for _, field := range append(named, "max_tokens") {
		f[field] = json.RawMessage(strconv.Itoa(allowed))
	}
	return nil
}

// forceUsage asks for one usage chunk at the end and nothing else: a mid-stream usage would pass for the final one in a cut stream.
func (f requestFields) forceUsage() error {
	if raw, ok := f["stream_options"]; ok && string(raw) != jsonNull {
		var options map[string]json.RawMessage
		if json.Unmarshal(raw, &options) != nil {
			return errOptions
		}
	}
	f["stream_options"] = json.RawMessage(`{"include_usage":true}`)
	return nil
}

// relayWithUsage passes SSE through and guarantees it ends with a usage chunk, all that meters with LiteLLM's counter off. A cut
// stream ends like a length limit, with estimated usage; one failing after its usage ends cleanly, as LiteLLM books nothing aborted.
func relayWithUsage(w io.Writer, body io.Reader, model string, promptBytes int, log *slog.Logger, call *callLine) {
	meter := &streamMeter{}
	defer func() { call.call.CompletionTokens = meter.completionTokens }()
	reader := bufio.NewReader(body)
	atBoundary := true
	var failure error
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && call.call.FirstByte.IsZero() {
			call.call.FirstByte = time.Now()
		}
		trimmed := bytes.TrimSpace(line)
		if string(trimmed) == doneLine {
			break
		}
		if err != nil { // a partial line would corrupt the chunk after it
			failure = err
			break
		}
		meter.observe(line)
		atBoundary = len(trimmed) == 0
		if _, writeErr := w.Write(line); writeErr != nil {
			call.status = statusClientGone
			log.Warn("egress: gateway gone mid-stream", "model", model, "err", writeErr)
			return
		}
	}
	if errors.Is(failure, context.Canceled) {
		call.status = statusClientGone
		log.Warn("egress: gateway gone mid-stream", "model", model, "err", failure)
		return
	}
	var tail bytes.Buffer
	if !atBoundary { // the cut fell between a data line and its blank line, and the next event must not join it
		tail.WriteByte('\n')
	}
	if !meter.usageSeen {
		call.status = "stream_cut"
		if failure == nil {
			call.status = "no_usage"
		}
		log.Error("egress: stream ended with no usage, billing an estimate", "model", model, "err", failure)
		tail.Write(meter.finalChunk(model, promptBytes))
	} else if failure != nil && !errors.Is(failure, io.EOF) {
		call.status = "stream_cut_after_usage"
		log.Warn("egress: stream failed after its usage", "model", model, "err", failure)
	}
	fmt.Fprintf(&tail, "%s\n\n", doneLine)
	if _, err := w.Write(tail.Bytes()); err != nil {
		call.status = statusClientGone
		log.Warn("egress: gateway gone mid-stream", "model", model, "err", err)
	}
}

// streamMeter reads only lengths and the presence of usage, never keeping any content.
type streamMeter struct {
	usageSeen        bool
	chunks           int
	bytes            int
	completionTokens *int
}

func (m *streamMeter) observe(line []byte) {
	payload, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:"))
	if !ok {
		return
	}
	var event struct {
		Usage   json.RawMessage `json:"usage"`
		Choices []struct {
			Delta struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
				Reasoning        string `json:"reasoning"`
				ToolCalls        []struct {
					Function struct {
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return
	}
	if len(event.Usage) > 0 && string(event.Usage) != jsonNull {
		m.usageSeen = true
		var usage struct {
			CompletionTokens *int `json:"completion_tokens"`
		}
		if json.Unmarshal(event.Usage, &usage) == nil && usage.CompletionTokens != nil {
			m.completionTokens = usage.CompletionTokens
		}
	}
	for _, choice := range event.Choices {
		delta := choice.Delta
		m.chunks++
		m.bytes += len(delta.Content) + len(delta.ReasoningContent) + len(delta.Reasoning)
		for _, call := range delta.ToolCalls {
			m.bytes += len(call.Function.Arguments)
		}
	}
}

// finalChunk closes a cut stream the way a length limit would, so a client sees it was truncated, with estimated usage. The
// prompt's estimate counts the request's JSON, a little over the prompt itself; the output is at least one token per chunk.
func (m *streamMeter) finalChunk(model string, promptBytes int) []byte {
	prompt := promptBytes / bytesPerToken
	completion := max(m.chunks, m.bytes/bytesPerToken)
	chunk, err := json.Marshal(map[string]any{
		"id":      "egress-cut",
		"object":  "chat.completion.chunk",
		"created": 0,
		"model":   model,
		"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "length"}},
		"usage":   map[string]int{"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion},
	})
	if err != nil { // plain maps of strings and ints always encode
		panic(err)
	}
	return append(append([]byte("data: "), chunk...), "\n\n"...)
}
