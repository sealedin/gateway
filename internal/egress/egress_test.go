package egress_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/egress"
	"github.com/sealedin/gateway/internal/egress/upstream"
)

func measuredPolicy(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "egress", "policy.yaml"))
	require.NoError(t, err)
	return raw
}

func TestLoadMeasuredPolicy(t *testing.T) {
	p, err := egress.LoadPolicy(strings.NewReader(string(measuredPolicy(t))))
	require.NoError(t, err)
	require.Equal(t, "chutes", p.Provider)
	require.Equal(t, "https://api.chutes.ai", p.Hosts.API)
	require.Equal(t, "https://llm.chutes.ai", p.Hosts.Catalog)
	require.Equal(t, 15*time.Minute, p.ReattestInterval)
	require.Len(t, p.Upstream.TDX.MRTD, 1)
	require.Len(t, p.Upstream.TDX.Images, 4)
	require.ElementsMatch(t, []string{"HOPPER", "BLACKWELL"}, p.Upstream.GPU.Archs)
}

func TestLoadPolicyRejects(t *testing.T) {
	base := string(measuredPolicy(t))
	tests := []struct {
		name    string
		mutate  func(s string) string
		wantErr string
	}{
		{"unknown key", func(s string) string { return s + "\nextra: 1\n" }, "extra"},
		{"misspelled gpu key", func(s string) string { return strings.Replace(s, "modes:", "mode:", 1) }, "mode"},
		{"http host", func(s string) string { return strings.Replace(s, "https://api.chutes.ai", "http://api.chutes.ai", 1) }, "https"},
		{"host with path", func(s string) string {
			return strings.Replace(s, "https://llm.chutes.ai", "https://llm.chutes.ai/v1", 1)
		}, "https"},
		{"other provider", func(s string) string { return strings.Replace(s, "provider: chutes", "provider: other", 1) }, "provider"},
		{"zero interval", func(s string) string { return strings.Replace(s, "reattest_interval: 15m", "reattest_interval: 0s", 1) }, "interval"},
		{"no mrtd", func(s string) string {
			return regexp.MustCompile(`(?m)^  mrtd:\n    - \w+\n`).ReplaceAllString(s, "  mrtd: []\n")
		}, "mrtd"},
		{"not yaml", func(string) string { return "{" }, "policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := egress.LoadPolicy(strings.NewReader(tt.mutate(base)))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

const finalUsage = `data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`

// allowAll admits every model name the tests use, with their output limit.
var allowAll = map[string]int{"org/m-TEE": 1000, "m": 1000} //nolint:gochecknoglobals // test table

type stubUpstream struct {
	reply *upstream.Reply
	err   error
	seen  struct {
		model, path string
		stream      bool
		body        string
	}
}

func (s *stubUpstream) Invoke(_ context.Context, model, path string, stream bool, body []byte) (*upstream.Reply, error) {
	s.seen.model, s.seen.path, s.seen.stream, s.seen.body = model, path, stream, string(body)
	return s.reply, s.err
}

func TestMuxRoutesOnlyChatCompletions(t *testing.T) {
	up := &stubUpstream{reply: &upstream.Reply{ContentType: "application/json", Body: io.NopCloser(strings.NewReader(`{"ok":1}`))}}
	mux := egress.NewMux(up, allowAll, slog.New(slog.DiscardHandler))
	tests := []struct {
		method, path, body string
		want               int
	}{
		{http.MethodPost, "/v1/chat/completions", `{"model":"org/m-TEE","messages":[]}`, http.StatusOK},
		{http.MethodGet, "/v1/chat/completions", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/completions", `{"model":"x"}`, http.StatusNotFound},
		{http.MethodPost, "/v1/embeddings", `{"model":"x"}`, http.StatusNotFound},
		{http.MethodGet, "/v1/models", "", http.StatusNotFound},
		{http.MethodPost, "/v1/chat/completions", `not json`, http.StatusBadRequest},
		{http.MethodPost, "/v1/chat/completions", `{"messages":[]}`, http.StatusBadRequest},
		{http.MethodPost, "/v1/chat/completions", `{"model":"org/not-measured"}`, http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path+" "+tt.body, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body)))
			require.Equal(t, tt.want, rec.Code, rec.Body.String())
		})
	}
	require.Equal(t, "org/m-TEE", up.seen.model)
	require.Equal(t, "/v1/chat/completions", up.seen.path)
	require.False(t, up.seen.stream)
	require.JSONEq(t, `{"model":"org/m-TEE","messages":[],"max_tokens":1000}`, up.seen.body, "a non-streaming body gets no stream_options")
}

// A stream must end with a usage chunk (the gateway meters on it), so the egress asks for one whatever the client sent.
func TestMuxForcesStreamUsage(t *testing.T) {
	tests := []struct {
		name, body, want string
		status           int
	}{
		{"absent", `{"model":"m","stream":true}`,
			`{"model":"m","stream":true,"max_tokens":1000,"stream_options":{"include_usage":true}}`, http.StatusOK},
		{"disabled by the client", `{"model":"m","stream":true,"stream_options":{"include_usage":false,"other":1}}`,
			`{"model":"m","stream":true,"max_tokens":1000,"stream_options":{"include_usage":true}}`, http.StatusOK},
		{"null", `{"model":"m","stream":true,"stream_options":null}`,
			`{"model":"m","stream":true,"max_tokens":1000,"stream_options":{"include_usage":true}}`, http.StatusOK},
		{"not an object", `{"model":"m","stream":true,"stream_options":[]}`, "", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &stubUpstream{reply: &upstream.Reply{ContentType: "text/event-stream", Body: io.NopCloser(strings.NewReader("data: [DONE]\n\n"))}}
			rec := httptest.NewRecorder()
			egress.NewMux(up, allowAll, slog.New(slog.DiscardHandler)).ServeHTTP(rec,
				httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tt.body)))
			require.Equal(t, tt.status, rec.Code, rec.Body.String())
			if tt.want != "" {
				require.JSONEq(t, tt.want, up.seen.body)
			}
		})
	}
}

func TestMuxMapsUpstreamErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"unknown model", upstream.ErrUnknownModel, http.StatusNotFound},
		{"not confidential", upstream.ErrNotConfidential, http.StatusNotFound},
		{"no attested instance", upstream.ErrNoAttestedInstance, http.StatusServiceUnavailable},
		{"upstream 429", &upstream.Error{Status: http.StatusTooManyRequests, Detail: "busy"}, http.StatusTooManyRequests},
		{"upstream 400", &upstream.Error{Status: http.StatusBadRequest, Detail: "bad"}, http.StatusBadRequest},
		{"upstream 500", &upstream.Error{Status: http.StatusInternalServerError, Detail: "secret"}, http.StatusBadGateway},
		{"other", errors.New("boom"), http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := egress.NewMux(&stubUpstream{err: tt.err}, allowAll, slog.New(slog.DiscardHandler))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m"}`)))
			require.Equal(t, tt.want, rec.Code)
			require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			require.Contains(t, rec.Body.String(), `"error"`)
			require.NotContains(t, rec.Body.String(), "secret", "upstream detail stays in the log")
			require.NotContains(t, rec.Body.String(), "busy")
		})
	}
}

func TestMuxStreamsAndFlushes(t *testing.T) {
	pr, pw := io.Pipe()
	up := &stubUpstream{reply: &upstream.Reply{ContentType: "text/event-stream", Body: pr}}
	srv := httptest.NewServer(egress.NewMux(up, allowAll, slog.New(slog.DiscardHandler)))
	defer srv.Close()
	go func() {
		_, _ = io.WriteString(pw, "data: {\"a\":1}\n\n")
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(pw, finalUsage+"\n\ndata: [DONE]\n\n")
		_ = pw.Close()
	}()
	resp, err := srv.Client().Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m","stream":true}`))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	require.True(t, up.seen.stream)
	first := make([]byte, len("data: {\"a\":1}\n\n"))
	_, err = io.ReadFull(resp.Body, first)
	require.NoError(t, err)
	require.Equal(t, "data: {\"a\":1}\n\n", string(first), "first chunk arrives before the stream ends")
	rest, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, finalUsage+"\n\ndata: [DONE]\n\n", string(rest), "a stream with its own usage passes through untouched")
}

// runStream serves one stream through the mux and returns what the gateway would read.
func runStream(t *testing.T, upstreamBody io.Reader) string {
	t.Helper()
	up := &stubUpstream{reply: &upstream.Reply{ContentType: "text/event-stream", Body: io.NopCloser(upstreamBody)}}
	rec := httptest.NewRecorder()
	body := `{"model":"m","stream":true,"messages":[{"role":"user","content":"` + strings.Repeat("p", 4000) + `"}]}`
	egress.NewMux(up, allowAll, slog.New(slog.DiscardHandler)).ServeHTTP(rec,
		httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}

// usageOf returns the usage of the last data chunk, which is what LiteLLM books.
func usageOf(t *testing.T, stream string) (int, int, string) {
	t.Helper()
	require.True(t, strings.HasSuffix(stream, "data: [DONE]\n\n"), stream)
	events := strings.Split(strings.TrimSuffix(stream, "\n\ndata: [DONE]\n\n"), "\n\n")
	var last struct {
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(events[len(events)-1], "data: ")), &last), stream)
	require.Len(t, last.Choices, 1)
	return last.Usage.Prompt, last.Usage.Completion, last.Choices[0].FinishReason
}

// A stream that ends with no usage still bills: LiteLLM counts no tokens itself, so without this it would book nothing.
func TestMuxBillsAStreamEndingWithoutUsage(t *testing.T) {
	chunk := `data: {"choices":[{"delta":{"content":"` + strings.Repeat("c", 800) + `"}}]}` + "\n\n"
	tests := []struct {
		name string
		body func() io.Reader
	}{
		{"failed mid-stream", func() io.Reader {
			return io.MultiReader(strings.NewReader(chunk), iotest.ErrReader(errors.New("chunk authentication failed")))
		}},
		{"ended without done", func() io.Reader { return strings.NewReader(chunk) }},
		{"done but no usage", func() io.Reader { return strings.NewReader(chunk + "data: [DONE]\n\n") }},
		{"cut inside a line", func() io.Reader { return strings.NewReader(chunk + `data: {"choices":[{"del`) }},
		{"cut before the blank line", func() io.Reader { return strings.NewReader(strings.TrimSuffix(chunk, "\n")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := runStream(t, tt.body())
			require.Contains(t, stream, strings.TrimSuffix(chunk, "\n\n"), "what was delivered stays delivered")
			require.Contains(t, stream, "\n\ndata: {\"choices\":[{\"delta\":{},", "the closing chunk is its own event")
			require.NotContains(t, stream, `{"del`+"\n", "a partial line never reaches the gateway")
			prompt, completion, finish := usageOf(t, stream)
			require.GreaterOrEqual(t, prompt, 1000, "the prompt is estimated from the request")
			require.Equal(t, 200, completion, "the output is estimated from what was delivered")
			require.Equal(t, "length", finish, "a client can tell the reply was cut")
		})
	}
}

func TestMuxEstimatesReasoningAndToolCalls(t *testing.T) {
	stream := runStream(t, strings.NewReader(`data: {"choices":[{"delta":{"reasoning_content":"`+strings.Repeat("r", 400)+`"}}]}`+"\n\n"+
		`data: {"choices":[{"delta":{"tool_calls":[{"function":{"arguments":"`+strings.Repeat("a", 400)+`"}}]}}]}`+"\n\n"))
	_, completion, _ := usageOf(t, stream)
	require.Equal(t, 200, completion)
}

// Failing after its usage ends cleanly and adds nothing: the usage is what gets booked.
func TestMuxKeepsTheUpstreamUsage(t *testing.T) {
	want := "data: {\"a\":1}\n\n" + finalUsage + "\n\n"
	stream := runStream(t, io.MultiReader(strings.NewReader(want), iotest.ErrReader(errors.New("reset"))))
	require.Equal(t, want+"data: [DONE]\n\n", stream)
}

// LiteLLM's estimate is min(requested, the model's limit), so whatever is forwarded must be no more than that.
func TestMuxClampsOutputToTheReservation(t *testing.T) {
	tests := []struct {
		name, fields, want string
		limit              int
	}{
		{"larger than the limit", `"max_tokens":1000000000`, `"max_tokens":1000`, 1000},
		{"larger, newer field", `"max_completion_tokens":1000000000`, `"max_completion_tokens":1000,"max_tokens":1000`, 1000},
		{"reserved on a field an upstream may ignore", `"max_output_tokens":7`, `"max_output_tokens":7,"max_tokens":7`, 1000},
		{"below the limit", `"max_tokens":5`, `"max_tokens":5`, 1000},
		{"named twice", `"max_tokens":1000000,"max_completion_tokens":5`, `"max_tokens":5,"max_completion_tokens":5`, 1000},
		{"unnamed, limit below the default", ``, `"max_tokens":1000`, 1000},
		{"unnamed, limit above the default", ``, `"max_tokens":16384`, 65535},
		{"null", `"max_tokens":null`, `"max_tokens":16384`, 65535},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &stubUpstream{reply: &upstream.Reply{Body: io.NopCloser(strings.NewReader("{}"))}}
			rec := httptest.NewRecorder()
			body := `{"model":"m"`
			if tt.fields != "" {
				body += "," + tt.fields
			}
			egress.NewMux(up, map[string]int{"m": tt.limit}, slog.New(slog.DiscardHandler)).ServeHTTP(rec,
				httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body+"}")))
			require.Equal(t, http.StatusOK, rec.Code)
			require.JSONEq(t, `{"model":"m",`+tt.want+`}`, up.seen.body)
		})
	}
}

// Only the exact key counts, as for the upstream: a case-folding decode would see another model or stream setting.
func TestMuxReadsExactKeys(t *testing.T) {
	reply := &upstream.Reply{ContentType: "text/event-stream", Body: io.NopCloser(strings.NewReader(finalUsage + "\n\n"))}
	up := &stubUpstream{reply: reply}
	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"model":"m","Model":"other","stream":true,"Stream":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	egress.NewMux(up, allowAll, slog.New(slog.DiscardHandler)).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.True(t, up.seen.stream)
	require.Contains(t, rec.Body.String(), "data: [DONE]")
}

func TestMuxRefusesABadOutputLimit(t *testing.T) {
	for _, field := range []string{
		`"n":2`, `"n":"2"`, `"max_tokens":0`, `"max_tokens":-1`, `"max_tokens":"9"`, `"max_tokens":1.5`, `"max_completion_tokens":0`,
	} {
		t.Run(field, func(t *testing.T) {
			rec := httptest.NewRecorder()
			egress.NewMux(&stubUpstream{}, allowAll, slog.New(slog.DiscardHandler)).ServeHTTP(rec,
				httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m",`+field+`}`)))
			require.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

type upstreamFunc func()

func (f upstreamFunc) Invoke(context.Context, string, string, bool, []byte) (*upstream.Reply, error) {
	f()
	return nil, errors.New("released")
}

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Saturation is what the operator watches for: every refusal logs at error level.
func TestMuxLogsSaturationAtErrorLevel(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 128)
	up := upstreamFunc(func() { entered <- struct{}{}; <-release })
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	srv := httptest.NewServer(egress.NewMux(up, allowAll, logger))
	defer srv.Close()
	defer close(release)
	post := func() (*http.Response, error) {
		return srv.Client().Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m"}`))
	}
	for range 64 {
		go func() {
			if resp, err := post(); err == nil {
				_ = resp.Body.Close()
			}
		}()
		<-entered
	}
	resp, err := post()
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Contains(t, logs.String(), "level=ERROR")
	require.Contains(t, logs.String(), "at capacity")
}
