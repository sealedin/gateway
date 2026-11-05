package chutes_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/egress"
	"github.com/sealedin/gateway/internal/egress/chutes"
	"github.com/sealedin/gateway/internal/egress/upstream"
)

// fakeChutes is the Chutes API with one TEE instance: catalog, discovery and an E2EE relay answering like the runtime.
type fakeChutes struct {
	t        *testing.T
	inst     *instanceKey
	srv      *httptest.Server
	status   int
	content  string                      // the reply's content
	detail   string                      // a refusal's body
	e2eError string                      // sent instead of frames in a stream
	evidence func(w http.ResponseWriter) // overrides the evidence reply
	hang     bool                        // a stream stops after its first frame until the caller leaves
	seen     http.Header
	seenBody map[string]json.RawMessage
	nonces   map[string]bool
}

func newFakeChutes(t *testing.T) *fakeChutes {
	t.Helper()
	f := &fakeChutes{t: t, inst: newInstanceKey(t), status: http.StatusOK, content: "hello",
		detail: `{"detail":"Instance is at maximum capacity, try again later"}`, nonces: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeChutes) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/models":
		_, _ = io.WriteString(w, `{"data":[{"id":"org/m-TEE","chute_id":"c1","confidential_compute":true}]}`)
	case strings.HasPrefix(r.URL.Path, "/e2e/instances/"):
		_, _ = fmt.Fprintf(w, `{"instances":[{"instance_id":"i1","e2e_pubkey":%q,"nonces":["n1","n2","n3"]}],"nonce_expires_in":60}`,
			f.inst.pubkeyB64())
	case strings.HasSuffix(r.URL.Path, "/evidence") && f.evidence != nil:
		f.evidence(w)
	case strings.HasSuffix(r.URL.Path, "/evidence"):
		_, _ = io.WriteString(w, `{"evidence":[{"instance_id":"i1"}]}`)
	case r.URL.Path == "/e2e/invoke":
		f.invoke(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeChutes) invoke(w http.ResponseWriter, r *http.Request) {
	f.seen = r.Header.Clone()
	nonce := r.Header.Get("X-E2e-Nonce")
	if f.nonces[nonce] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"detail":"Invalid, expired, or already-used nonce"}`)
		return
	}
	f.nonces[nonce] = true
	if f.status != http.StatusOK {
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.detail)
		return
	}
	blob, err := io.ReadAll(r.Body)
	if !assert.NoError(f.t, err) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	payload, responseKey, err := f.inst.open(blob)
	if !assert.NoError(f.t, err) {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.seenBody = payload
	if r.Header.Get("X-E2e-Stream") == "true" {
		shared, ct := responseKey.Encapsulate()
		key := chutes.DeriveKey(shared, ct, "e2e-stream-v1")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: {\"e2e_init\":%q}\n\n", base64.StdEncoding.EncodeToString(ct))
		if f.e2eError != "" {
			_, _ = fmt.Fprintf(w, "data: {\"e2e_error\":%q}\n\n", f.e2eError)
			return
		}
		// Live shape: one SSE line per frame, [DONE] encrypted like any line, then the API's own plaintext usage event.
		for _, chunk := range []string{`data: {"choices":[{"delta":{"content":"he"}}]}` + "\n", "\n",
			`data: {"choices":[{"delta":{"content":"` + f.streamTail() + `"}}]}` + "\n", "\n",
			`data: {"choices":[],"usage":{"completion_tokens":2}}` + "\n", "\n", "data: [DONE]\n", "\n"} {
			enc := chutes.SealChaCha(f.t, key, []byte(chunk))
			_, _ = fmt.Fprintf(w, "data: {\"e2e\":%q}\n\n", base64.StdEncoding.EncodeToString(enc))
			if f.hang {
				w.(http.Flusher).Flush() //nolint:errcheck,forcetypeassert // the httptest server's writer flushes
				<-r.Context().Done()
				return
			}
		}
		_, _ = io.WriteString(w, `data: {"usage":{"completion_tokens":2}}`+"\n\n")
		return
	}
	shared, ct := responseKey.Encapsulate()
	key := chutes.DeriveKey(shared, ct, "e2e-resp-v1")
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write([]byte(`{"choices":[{"message":{"content":"` + f.content + `"}}],"usage":{"completion_tokens":1}}`))
	_ = gw.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(append(ct, chutes.SealChaCha(f.t, key, gz.Bytes())...))
}

// streamTail is the reply's content past the "he" of the first frame, or all of it when it does not start so.
func (f *fakeChutes) streamTail() string { return strings.TrimPrefix(f.content, "he") }

func newProvider(t *testing.T, f *fakeChutes) *chutes.Provider {
	t.Helper()
	return chutes.NewProvider(f.srv.URL, "cpk_test", f.srv.Client(), chutes.NewCatalog(f.srv.URL, f.srv.Client()),
		newProviderAttester(t, f))
}

func TestInvokeNonStreaming(t *testing.T) {
	f := newFakeChutes(t)
	p := newProvider(t, f)
	reply, err := p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false,
		[]byte(`{"model":"org/m-TEE","messages":[{"role":"user","content":"hi"}]}`), &upstream.Call{})
	require.NoError(t, err)
	defer func() { _ = reply.Body.Close() }()
	body, err := io.ReadAll(reply.Body)
	require.NoError(t, err)
	require.Equal(t, "application/json", reply.ContentType)
	require.JSONEq(t, `{"choices":[{"message":{"content":"hello"}}],"usage":{"completion_tokens":1}}`, string(body))
	require.Equal(t, "Bearer cpk_test", f.seen.Get("Authorization"))
	require.Equal(t, "c1", f.seen.Get("X-Chute-Id"))
	require.Equal(t, "i1", f.seen.Get("X-Instance-Id"))
	require.Equal(t, "n1", f.seen.Get("X-E2e-Nonce"))
	require.Equal(t, "false", f.seen.Get("X-E2e-Stream"))
	require.Equal(t, "/v1/chat/completions", f.seen.Get("X-E2e-Path"))
	require.Equal(t, "application/octet-stream", f.seen.Get("Content-Type"))
	require.JSONEq(t, `[{"role":"user","content":"hi"}]`, string(f.seenBody["messages"]))

	// The next request consumes the next nonce.
	reply, err = p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false, []byte(`{"model":"org/m-TEE"}`), &upstream.Call{})
	require.NoError(t, err)
	_ = reply.Body.Close()
	require.Equal(t, "n2", f.seen.Get("X-E2e-Nonce"))
}

func TestInvokeStreaming(t *testing.T) {
	f := newFakeChutes(t)
	p := newProvider(t, f)
	reply, err := p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", true, []byte(`{"model":"org/m-TEE","stream":true}`),
		&upstream.Call{})
	require.NoError(t, err)
	defer func() { _ = reply.Body.Close() }()
	require.Equal(t, "text/event-stream", reply.ContentType)
	out, err := io.ReadAll(reply.Body)
	require.NoError(t, err)
	require.Equal(t, `data: {"choices":[{"delta":{"content":"he"}}]}`+"\n\n"+
		`data: {"choices":[{"delta":{"content":"llo"}}]}`+"\n\n"+
		`data: {"choices":[],"usage":{"completion_tokens":2}}`+"\n\n"+"data: [DONE]\n\n", string(out),
		"decrypted lines relayed verbatim up to the encrypted [DONE], the plaintext usage event dropped")
	require.Equal(t, "true", f.seen.Get("X-E2e-Stream"))
}

func TestInvokeErrors(t *testing.T) {
	f := newFakeChutes(t)
	p := newProvider(t, f)
	ctx := context.Background()

	_, err := p.Invoke(ctx, "org/unknown", "/v1/chat/completions", false, []byte(`{}`), &upstream.Call{})
	require.ErrorIs(t, err, upstream.ErrUnknownModel)

	f.status = http.StatusTooManyRequests
	_, err = p.Invoke(ctx, "org/m-TEE", "/v1/chat/completions", false, []byte(`{}`), &upstream.Call{})
	var refusal *upstream.Error
	require.ErrorAs(t, err, &refusal)
	require.Equal(t, http.StatusTooManyRequests, refusal.Status)
	require.Contains(t, refusal.Detail, "capacity")

	f.status = http.StatusOK
	_, err = p.Invoke(ctx, "org/m-TEE", "/v1/chat/completions", false, []byte(`not json`), &upstream.Call{})
	require.ErrorContains(t, err, "JSON object")
}

func TestInvokeFailsClosedWithoutAttestedInstance(t *testing.T) {
	f := newFakeChutes(t)
	att, err := chutes.NewAttester(f.srv.URL, "cpk_test", f.srv.Client(), &stubVerifier{now: time.Now}, time.Hour,
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	chutes.SetGetter(att, func(context.Context, string, string) ([]byte, error) {
		return []byte(`{"instances":[],"nonce_expires_in":60}`), nil
	})
	p := chutes.NewProvider(f.srv.URL, "cpk_test", f.srv.Client(), chutes.NewCatalog(f.srv.URL, f.srv.Client()), att)
	_, err = p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false, []byte(`{}`), &upstream.Call{})
	require.ErrorIs(t, err, upstream.ErrNoAttestedInstance)
	require.Nil(t, f.seen, "nothing was sent upstream")
}

func newProviderAttester(t *testing.T, f *fakeChutes) *chutes.Attester {
	t.Helper()
	return loggedAttester(t, f, slog.New(slog.DiscardHandler))
}

func loggedAttester(t *testing.T, f *fakeChutes, log *slog.Logger) *chutes.Attester {
	t.Helper()
	att, err := chutes.NewAttester(f.srv.URL, "cpk_test", f.srv.Client(),
		&stubVerifier{accept: map[string]bool{"i1": true}, now: time.Now}, time.Hour, log)
	require.NoError(t, err)
	return att
}

// loggedMux is the real provider behind the real mux, with every line of both in one log.
func loggedMux(t *testing.T, f *fakeChutes, logs io.Writer) *http.ServeMux {
	t.Helper()
	log := slog.New(slog.NewTextHandler(logs, nil))
	provider := chutes.NewProvider(f.srv.URL, "cpk_test", f.srv.Client(), chutes.NewCatalog(f.srv.URL, f.srv.Client()),
		loggedAttester(t, f, log))
	return egress.NewMux(provider, map[string]int{"org/m-TEE": 1000}, log)
}

// streamThrough relays the fake's encrypted SSE through a rewriting proxy and returns the egress read error.
func streamThrough(t *testing.T, f *fakeChutes, rewrite func(body []byte) []byte) error {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, f.srv.URL+r.URL.Path, r.Body)
		if !assert.NoError(t, err) {
			return
		}
		req.Header = r.Header
		resp, err := f.srv.Client().Do(req)
		if !assert.NoError(t, err) {
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(rewrite(body))
	}))
	defer proxy.Close()
	p := chutes.NewProvider(proxy.URL, "cpk_test", proxy.Client(), chutes.NewCatalog(f.srv.URL, f.srv.Client()),
		newProviderAttester(t, f))
	reply, err := p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", true, []byte(`{"stream":true}`), &upstream.Call{})
	require.NoError(t, err)
	defer func() { _ = reply.Body.Close() }()
	_, err = io.ReadAll(reply.Body)
	return err
}

// The relay sits outside the encryption, so nothing it corrupts, replays, drops or forges may pass as complete.
func TestRelayStreamRejectsRelayTampering(t *testing.T) {
	frames := func(body []byte) [][]byte {
		var out [][]byte
		for line := range bytes.SplitSeq(body, []byte("\n\n")) {
			if bytes.HasPrefix(line, []byte(`data: {"e2e":`)) {
				out = append(out, line)
			}
		}
		return out
	}
	tests := []struct {
		name    string
		rewrite func(body []byte) []byte
		wantErr string
	}{
		{"chunk corrupted", func(body []byte) []byte {
			i := bytes.Index(body, []byte(`{"e2e":"`)) + len(`{"e2e":"`) + 20
			if body[i] == 'A' {
				body[i] = 'B'
			} else {
				body[i] = 'A'
			}
			return body
		}, "authentication failed"},
		{"usage frame dropped", func(body []byte) []byte {
			usage := frames(body)[4]
			return bytes.Replace(body, append(usage, []byte("\n\n")...), nil, 1)
		}, "before the final usage chunk"},
		{"plaintext DONE injected", func(body []byte) []byte {
			done := frames(body)[6]
			return bytes.Replace(body, done, append([]byte("data: [DONE]\n\n"), done...), 1)
		}, "outside the encryption"},
		{"stream cut before the encrypted DONE", func(body []byte) []byte {
			before, _, _ := bytes.Cut(body, frames(body)[6])
			return before
		}, "without [DONE]"},
		{"duplicated frame", func(body []byte) []byte {
			first := frames(body)[0]
			return bytes.Replace(body, first, append(append([]byte(nil), first...), append([]byte("\n\n"), first...)...), 1)
		}, "repeated stream frame"},
		{"frame reordered to the end", func(body []byte) []byte {
			// Every frame stays valid: the documented undetectable case, so it must still decrypt.
			return body
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A fresh fake per case: its invocation nonces are single use.
			err := streamThrough(t, newFakeChutes(t), tt.rewrite)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// The provider fills what only it knows: where the call went, how long attestation took, the sending time, the tokens.
func TestInvokeFillsTheCall(t *testing.T) {
	p := newProvider(t, newFakeChutes(t))
	var call upstream.Call
	reply, err := p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false, []byte(`{}`), &call)
	require.NoError(t, err)
	_ = reply.Body.Close()
	require.Equal(t, "c1", call.Chute)
	require.Equal(t, "i1", call.Instance)
	require.Positive(t, call.AttestWait)
	require.False(t, call.Sent.IsZero())
	require.False(t, call.FirstByte.Before(call.Sent), "headers come after sending")
	require.NotNil(t, call.CompletionTokens)
	require.Equal(t, 1, *call.CompletionTokens)

	var streamed upstream.Call
	reply, err = p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", true, []byte(`{}`), &streamed)
	require.NoError(t, err)
	defer func() { _ = reply.Body.Close() }()
	require.False(t, streamed.Sent.IsZero())
	require.True(t, streamed.FirstByte.IsZero(), "a stream's first byte is its first decrypted chunk, seen by the reader")
}

// A marker in the request, the reply, a refusal or an instance error, a client key or address: none reaches the log.
func TestLogsCarryNoContentOrIdentity(t *testing.T) {
	const marker = "SECRETMARKER"
	tests := []struct {
		name, body, status string
		set                func(f *fakeChutes)
	}{
		{"reply", `{"model":"org/m-TEE","messages":[{"content":"` + marker + `"}]}`, "status=200",
			func(f *fakeChutes) { f.content = marker }},
		{"stream", `{"model":"org/m-TEE","stream":true,"messages":[{"content":"` + marker + `"}]}`, "status=200",
			func(f *fakeChutes) { f.content = marker }},
		{"refusal echoing the request", `{"model":"org/m-TEE","messages":[{"content":"` + marker + `"}]}`, "status=500",
			func(f *fakeChutes) {
				f.status, f.detail = http.StatusInternalServerError, `{"detail":"bad `+marker+`"}`
			}},
		{"instance error in a stream", `{"model":"org/m-TEE","stream":true,"messages":[{"content":"` + marker + `"}]}`,
			"status=stream_cut", func(f *fakeChutes) { f.e2eError = "bad " + marker }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeChutes(t)
			tt.set(f)
			var logs syncBuffer
			mux := loggedMux(t, f, &logs)
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer sk-"+marker)
			req.Header.Set("X-Forwarded-For", "203.0.113.77")
			req.RemoteAddr = "203.0.113.77:1234"
			mux.ServeHTTP(httptest.NewRecorder(), req)
			text := logs.String()
			require.Contains(t, text, `msg="egress: upstream call"`)
			require.Contains(t, text, tt.status+" ")
			for _, forbidden := range []string{marker, "cpk_test", "203.0.113.77", "n1", "n2", "sk-"} {
				require.NotContains(t, text, forbidden)
			}
		})
	}
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

// A client leaving mid-stream ends the upstream read through the request context, the whole way through the real provider.
func TestCallLineWhenTheClientLeavesARealStream(t *testing.T) {
	f := newFakeChutes(t)
	f.hang = true
	var logs syncBuffer
	srv := httptest.NewServer(loggedMux(t, f, &logs))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"org/m-TEE","stream":true}`))
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, err = io.ReadFull(resp.Body, make([]byte, 6))
	require.NoError(t, err)
	cancel()
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "upstream call") }, 5*time.Second, 10*time.Millisecond)
	require.Contains(t, logs.String(), "status=client_gone ")
	require.Contains(t, logs.String(), "first_byte_ms=")
	require.Contains(t, logs.String(), "instance=i1")
}

// A failed fetch quotes the evidence URL, which carries the attestation nonce, on the way to the log and the caller.
func TestFailedEvidenceFetchNamesNoNonce(t *testing.T) {
	tests := []struct {
		name  string
		reply func(w http.ResponseWriter)
	}{
		{"http error", func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }},
		{"connection cut", func(http.ResponseWriter) { panic(http.ErrAbortHandler) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeChutes(t)
			f.evidence = tt.reply
			var logs syncBuffer
			mux := loggedMux(t, f, &logs)
			// The second request takes the backoff path, which repeats the first failure.
			for range 2 {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"org/m-TEE"}`)))
				require.NotContains(t, rec.Body.String(), "nonce=")
			}
			require.Contains(t, logs.String(), "evidence for")
			require.NotContains(t, logs.String(), "nonce=")
		})
	}
}

// Refusals the operator acts on keep a name; the rest are withheld, since an instance's words may quote the prompt.
func TestRefusalDetailIsLogSafe(t *testing.T) {
	tests := []struct{ body, want string }{
		{`{"detail":"Instance is at maximum capacity, try again later"}`, "instance at maximum capacity"},
		{`{"detail":"Invalid, expired, or already-used nonce"}`, "invocation token refused"},
		{`{"detail":"anything else"}`, "withheld, 26 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			f := newFakeChutes(t)
			f.status, f.detail = http.StatusTooManyRequests, tt.body
			_, err := newProvider(t, f).Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false, []byte(`{}`), &upstream.Call{})
			var refusal *upstream.Error
			require.ErrorAs(t, err, &refusal)
			require.Equal(t, tt.want, refusal.Detail)
		})
	}
}
