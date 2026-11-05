package egress_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	call  upstream.Call
	seen  struct {
		model, path string
		stream      bool
		body        string
	}
}

func (s *stubUpstream) Invoke(_ context.Context, model, path string, stream bool, body []byte,
	call *upstream.Call) (*upstream.Reply, error) {
	*call = s.call
	call.Sent = time.Now()
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

func (f upstreamFunc) Invoke(context.Context, string, string, bool, []byte, *upstream.Call) (*upstream.Reply, error) {
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

// callLine serves one request and returns the log, which must hold exactly one call line.
func callLine(t *testing.T, up upstream.Provider, body string) string {
	t.Helper()
	var logs syncBuffer
	rec := httptest.NewRecorder()
	egress.NewMux(up, allowAll, slog.New(slog.NewTextHandler(&logs, nil))).ServeHTTP(rec,
		httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)))
	return oneCallLine(t, logs.String())
}

func oneCallLine(t *testing.T, logs string) string {
	t.Helper()
	var lines []string
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, `msg="egress: upstream call"`) {
			lines = append(lines, line)
		}
	}
	require.Len(t, lines, 1, logs)
	return lines[0]
}

const streamBody, plainBody = `{"model":"m","stream":true}`, `{"model":"m"}`

// errReader yields text and then fails, as a decrypted stream does when the upstream cuts it.
func errReader(text string, err error) io.Reader {
	return io.MultiReader(strings.NewReader(text), iotest.ErrReader(err))
}

func TestCallLineStatus(t *testing.T) {
	chunk := "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"
	usage := `data: {"choices":[],"usage":{"completion_tokens":7}}` + "\n\n"
	cut := errors.New("chutes: stream ended without [DONE]")
	streaming := func(r io.Reader) *upstream.Reply {
		return &upstream.Reply{ContentType: "text/event-stream", Body: io.NopCloser(r)}
	}
	tests := []struct {
		name, body string
		up         *stubUpstream
		want       []string
		absent     []string
	}{
		{"complete stream", streamBody, &stubUpstream{reply: streaming(strings.NewReader(chunk + usage + "data: [DONE]\n\n"))},
			[]string{"status=200", "stream=true", "completion_tokens=7", "first_byte_ms="}, nil},
		{"cut before usage", streamBody, &stubUpstream{reply: streaming(errReader(chunk, cut))},
			[]string{"status=stream_cut ", "first_byte_ms="}, []string{"completion_tokens"}},
		{"cut before the first chunk", streamBody, &stubUpstream{reply: streaming(errReader("", cut))},
			[]string{"status=stream_cut "}, []string{"first_byte_ms", "completion_tokens"}},
		{"cut after usage", streamBody, &stubUpstream{reply: streaming(errReader(chunk+usage, cut))},
			[]string{"status=stream_cut_after_usage", "completion_tokens=7"}, nil},
		{"ended cleanly with no usage", streamBody, &stubUpstream{reply: streaming(strings.NewReader(chunk + "data: [DONE]\n\n"))},
			[]string{"status=no_usage"}, []string{"completion_tokens"}},
		{"gateway gone while reading", streamBody, &stubUpstream{reply: streaming(errReader(chunk, context.Canceled))},
			[]string{"status=client_gone"}, nil},
		{"complete reply", plainBody, &stubUpstream{
			reply: &upstream.Reply{ContentType: "application/json", Body: io.NopCloser(strings.NewReader(`{}`))},
			call:  upstream.Call{Chute: "c", Instance: "i", AttestWait: 2 * time.Second},
		}, []string{"status=200", "stream=false", "chute=c", "instance=i", "attest_wait_ms=2000", "total_ms=", "model=m"}, nil},
		{"upstream refusal", plainBody, &stubUpstream{err: &upstream.Error{Status: http.StatusTooManyRequests}},
			[]string{"status=429"}, nil},
		{"no attested instance", plainBody, &stubUpstream{err: upstream.ErrNoAttestedInstance},
			[]string{"status=no_attested_instance"}, nil},
		{"unknown upstream model", plainBody, &stubUpstream{err: upstream.ErrUnknownModel}, []string{"status=unknown_model"}, nil},
		{"not confidential", plainBody, &stubUpstream{err: upstream.ErrNotConfidential}, []string{"status=not_confidential"}, nil},
		{"gateway gone before the reply", plainBody, &stubUpstream{err: fmt.Errorf("chutes: invoke: %w", context.Canceled)},
			[]string{"status=client_gone"}, nil},
		{"other failure", plainBody, &stubUpstream{err: errors.New("boom")}, []string{"status=upstream_error"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := callLine(t, tt.up, tt.body)
			for _, want := range tt.want {
				require.Contains(t, line, want)
			}
			for _, absent := range tt.absent {
				require.NotContains(t, line, absent)
			}
		})
	}
}

// A request refused before any upstream call is no upstream call.
func TestNoCallLineWithoutAnUpstreamCall(t *testing.T) {
	var logs syncBuffer
	rec := httptest.NewRecorder()
	egress.NewMux(&stubUpstream{}, allowAll, slog.New(slog.NewTextHandler(&logs, nil))).ServeHTTP(rec,
		httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"org/not-measured"}`)))
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.NotContains(t, logs.String(), "upstream call")
}

type failingWriter struct{ header http.Header }

func (f failingWriter) Header() http.Header { return f.header }

func (failingWriter) WriteHeader(int) {}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A write failure aborts the connection by panicking; the line must get out on the way.
func TestCallLineSurvivesAnAbortedReply(t *testing.T) {
	var logs syncBuffer
	up := &stubUpstream{reply: &upstream.Reply{ContentType: "application/json", Body: io.NopCloser(strings.NewReader(`{}`))}}
	mux := egress.NewMux(up, allowAll, slog.New(slog.NewTextHandler(&logs, nil)))
	require.PanicsWithValue(t, http.ErrAbortHandler, func() {
		mux.ServeHTTP(failingWriter{http.Header{}},
			httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(plainBody)))
	})
	require.Contains(t, oneCallLine(t, logs.String()), "status=client_gone")
}

// A hang-up seen through the mux; the real provider's own path is pinned in the chutes tests.
func TestCallLineWhenTheClientHangsUpMidStream(t *testing.T) {
	var logs syncBuffer
	pr, pw := io.Pipe()
	up := hangUpUpstream{pr: pr, pw: pw}
	srv := httptest.NewServer(egress.NewMux(up, allowAll, slog.New(slog.NewTextHandler(&logs, nil))))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(streamBody))
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, err = io.ReadFull(resp.Body, make([]byte, 6))
	require.NoError(t, err)
	cancel()
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "upstream call") }, 5*time.Second, 10*time.Millisecond)
	require.Contains(t, oneCallLine(t, logs.String()), "status=client_gone")
}

type hangUpUpstream struct {
	pr *io.PipeReader
	pw *io.PipeWriter
}

func (h hangUpUpstream) Invoke(ctx context.Context, _, _ string, _ bool, _ []byte, _ *upstream.Call) (*upstream.Reply, error) {
	context.AfterFunc(ctx, func() { _ = h.pw.CloseWithError(ctx.Err()) })
	go func() { _, _ = io.WriteString(h.pw, "data: {}\n\n") }()
	return &upstream.Reply{ContentType: "text/event-stream", Body: h.pr}, nil
}
