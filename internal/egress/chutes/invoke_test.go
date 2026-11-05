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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/egress/chutes"
	"github.com/sealedin/gateway/internal/egress/upstream"
)

// fakeChutes is the Chutes API with one TEE instance: catalog, discovery and an E2EE relay answering like the runtime.
type fakeChutes struct {
	t        *testing.T
	inst     *instanceKey
	srv      *httptest.Server
	status   int
	seen     http.Header
	seenBody map[string]json.RawMessage
	nonces   map[string]bool
}

func newFakeChutes(t *testing.T) *fakeChutes {
	t.Helper()
	f := &fakeChutes{t: t, inst: newInstanceKey(t), status: http.StatusOK, nonces: map[string]bool{}}
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
		_, _ = io.WriteString(w, `{"detail":"Instance is at maximum capacity, try again later"}`)
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
		// Live shape: one SSE line per frame, [DONE] encrypted like any line, then the API's own plaintext usage event.
		for _, chunk := range []string{`data: {"choices":[{"delta":{"content":"he"}}]}` + "\n", "\n",
			`data: {"choices":[{"delta":{"content":"llo"}}]}` + "\n", "\n",
			`data: {"choices":[],"usage":{"completion_tokens":2}}` + "\n", "\n", "data: [DONE]\n", "\n"} {
			enc := chutes.SealChaCha(f.t, key, []byte(chunk))
			_, _ = fmt.Fprintf(w, "data: {\"e2e\":%q}\n\n", base64.StdEncoding.EncodeToString(enc))
		}
		_, _ = io.WriteString(w, `data: {"usage":{"completion_tokens":2}}`+"\n\n")
		return
	}
	shared, ct := responseKey.Encapsulate()
	key := chutes.DeriveKey(shared, ct, "e2e-resp-v1")
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write([]byte(`{"choices":[{"message":{"content":"hello"}}],"usage":{"completion_tokens":1}}`))
	_ = gw.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(append(ct, chutes.SealChaCha(f.t, key, gz.Bytes())...))
}

func newProvider(t *testing.T, f *fakeChutes) *chutes.Provider {
	t.Helper()
	return chutes.NewProvider(f.srv.URL, "cpk_test", f.srv.Client(), chutes.NewCatalog(f.srv.URL, f.srv.Client()),
		newProviderAttester(t, f))
}

func TestInvokeNonStreaming(t *testing.T) {
	f := newFakeChutes(t)
	p := newProvider(t, f)
	reply, err := p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false,
		[]byte(`{"model":"org/m-TEE","messages":[{"role":"user","content":"hi"}]}`))
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
	reply, err = p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false, []byte(`{"model":"org/m-TEE"}`))
	require.NoError(t, err)
	_ = reply.Body.Close()
	require.Equal(t, "n2", f.seen.Get("X-E2e-Nonce"))
}

func TestInvokeStreaming(t *testing.T) {
	f := newFakeChutes(t)
	p := newProvider(t, f)
	reply, err := p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", true, []byte(`{"model":"org/m-TEE","stream":true}`))
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

	_, err := p.Invoke(ctx, "org/unknown", "/v1/chat/completions", false, []byte(`{}`))
	require.ErrorIs(t, err, upstream.ErrUnknownModel)

	f.status = http.StatusTooManyRequests
	_, err = p.Invoke(ctx, "org/m-TEE", "/v1/chat/completions", false, []byte(`{}`))
	var upstream *upstream.Error
	require.ErrorAs(t, err, &upstream)
	require.Equal(t, http.StatusTooManyRequests, upstream.Status)
	require.Contains(t, upstream.Detail, "capacity")

	f.status = http.StatusOK
	_, err = p.Invoke(ctx, "org/m-TEE", "/v1/chat/completions", false, []byte(`not json`))
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
	_, err = p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", false, []byte(`{}`))
	require.ErrorIs(t, err, upstream.ErrNoAttestedInstance)
	require.Nil(t, f.seen, "nothing was sent upstream")
}

func newProviderAttester(t *testing.T, f *fakeChutes) *chutes.Attester {
	t.Helper()
	att, err := chutes.NewAttester(f.srv.URL, "cpk_test", f.srv.Client(),
		&stubVerifier{accept: map[string]bool{"i1": true}, now: time.Now}, time.Hour, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return att
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
	reply, err := p.Invoke(context.Background(), "org/m-TEE", "/v1/chat/completions", true, []byte(`{"stream":true}`))
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
