package drain_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/drain"
	"github.com/sealedin/gateway/internal/limits"
)

// newProxy serves the proxy over a real listener: stalls and hang-ups need real sockets.
func newProxy(t *testing.T, upstream http.Handler, limit, stall time.Duration, logs io.Writer) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	if logs == nil {
		logs = io.Discard
	}
	limits := drain.Limits{Deliver: limit, Upstream: limit, Stall: stall, Parallel: limits.ParallelRequests}
	handler := drain.New(target, limits, slog.New(slog.NewTextHandler(logs, nil)))
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)
	return front
}

func post(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, strings.NewReader(`{"prompt":"secret-prompt"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer sk-client-key")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}

// Random keys pass the per-key limit, and LiteLLM reads a body before it checks the key, so all bodies together are bounded.
func TestBodyBudgetHoldsAcrossCredentials(t *testing.T) {
	t.Parallel()
	var seen atomic.Int64
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if strings.Contains(r.Header.Get("Authorization"), "holder") {
			<-release
		}
	})
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	letGo := sync.OnceFunc(func() { close(release) })
	t.Cleanup(letGo) // before the servers close, which wait for their handlers, so a failure below ends rather than hangs
	send := func(key string) *http.Response {
		// No declared length, so each reserves the most a body may be.
		body := io.NopCloser(strings.NewReader("{}"))
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/messages", body)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer sk-"+key)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		return resp
	}
	holders := int64(drain.MaxInFlightBodyBytes / drain.MaxBodyBytes)
	var running sync.WaitGroup
	for i := range holders {
		running.Go(func() {
			resp := send("holder-" + strconv.FormatInt(i, 10))
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.NoError(t, resp.Body.Close())
		})
	}
	require.Eventually(t, func() bool { return seen.Load() == holders }, 10*time.Second, 5*time.Millisecond)

	refused := send("one-too-many")
	require.NoError(t, refused.Body.Close())
	require.Equal(t, http.StatusTooManyRequests, refused.StatusCode)
	require.NotEmpty(t, refused.Header.Get("Retry-After"))
	require.Equal(t, holders, seen.Load(), "a refused body never reaches the upstream")

	letGo()
	running.Wait()
	after := send("after")
	require.NoError(t, after.Body.Close())
	require.Equal(t, http.StatusOK, after.StatusCode, "the budget returns when requests end")
}

// A stream reaches the client as it is produced, not when it ends.
func TestStreamsChunkByChunk(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, err := w.Write([]byte("data: first\n\n"))
		assert.NoError(t, err)
		assert.NoError(t, http.NewResponseController(w).Flush())
		<-release
		_, err = w.Write([]byte("data: last\n\n"))
		assert.NoError(t, err)
	})
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	resp := post(t, srv, "/v1/chat/completions")
	defer func() { require.NoError(t, resp.Body.Close()) }()
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "data: first\n", line, "read while the upstream is still holding the rest")
	close(release)
	rest, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Contains(t, string(rest), "data: last")
}

// What the client sent and the status LiteLLM answered pass through unchanged.
func TestPassesTheRequestAndStatusThrough(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer sk-client-key", r.Header.Get("Authorization"))
		assert.Equal(t, "beta=true", r.URL.RawQuery)
		assert.Empty(t, r.Header.Get("X-Forwarded-For"), "the gateway needs no client address")
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.JSONEq(t, `{"prompt":"secret-prompt"}`, string(body))
		w.WriteHeader(http.StatusTooManyRequests)
	})
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	resp := post(t, srv, "/v1/messages?beta=true")
	defer func() { require.NoError(t, resp.Body.Close()) }()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

// The point of the proxy: a client hanging up does not cut the upstream, so LiteLLM reaches the end of the stream and bills.
func TestAClientHangingUpLeavesTheUpstreamRunningToItsEnd(t *testing.T) {
	t.Parallel()
	finished := make(chan struct{})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 50 {
			if _, err := w.Write([]byte("data: chunk\n\n")); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
		close(finished)
	})
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	_, err = io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nX-Api-Key: sk-raw\r\nContent-Length: 2\r\n\r\n{}")
	require.NoError(t, err)
	_, err = bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream was cut when the client left")
	}
}

// A client that hangs up before any byte came back: the request has already been paid for upstream, so it runs on.
func TestAClientHangingUpBeforeTheFirstByteLeavesTheUpstreamRunning(t *testing.T) {
	t.Parallel()
	started, finished := make(chan struct{}), make(chan struct{})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
		_, err := w.Write([]byte("done"))
		assert.NoError(t, err)
		close(finished)
	})
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	_, err = io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nX-Api-Key: sk-raw\r\nContent-Length: 2\r\n\r\n{}")
	require.NoError(t, err)
	<-started
	require.NoError(t, conn.Close())
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream was cut when the client left")
	}
}

// A client that stops reading must not slow the upstream through backpressure, or the spend lands too late or never.
func TestAStalledClientDoesNotHoldTheUpstreamBack(t *testing.T) {
	t.Parallel()
	finished := make(chan struct{})
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 64 { // far more than the socket buffers on the way hold
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		close(finished)
	})
	srv := newProxy(t, upstream, time.Minute, 50*time.Millisecond, nil)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()
	_, err = io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nX-Api-Key: sk-raw\r\nContent-Length: 2\r\n\r\n{}")
	require.NoError(t, err)
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("a client that stopped reading held the upstream back")
	}
}

// The drain is bounded: a request past the upstream limit is cut, whoever is or is not reading.
func TestTheUpstreamLimitStillCuts(t *testing.T) {
	t.Parallel()
	cut := make(chan struct{})
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, http.NewResponseController(w).Flush())
		select {
		case <-r.Context().Done():
			close(cut)
		case <-time.After(30 * time.Second):
		}
	})
	srv := newProxy(t, upstream, 50*time.Millisecond, time.Minute, nil)
	resp := post(t, srv, "/v1/chat/completions")
	defer func() { require.NoError(t, resp.Body.Close()) }()
	select {
	case <-cut:
	case <-time.After(10 * time.Second):
		t.Fatal("the limit did not cut the upstream")
	}
}

func TestAnUnreachableUpstreamIsA502(t *testing.T) {
	t.Parallel()
	target, err := url.Parse("http://127.0.0.1:1")
	require.NoError(t, err)
	limits := drain.Limits{Deliver: time.Second, Upstream: time.Second, Stall: time.Second, Parallel: 1}
	srv := httptest.NewServer(drain.New(target, limits, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	resp := post(t, srv, "/v1/chat/completions")
	defer func() { require.NoError(t, resp.Body.Close()) }()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// A key's limit holds for as long as its requests run, which LiteLLM's own 60-second counter does not, and it is per key.
func TestParallelLimitHoldsPerCredentialUntilTheRequestEnds(t *testing.T) {
	t.Parallel()
	release, entered := make(chan struct{}), make(chan struct{}, 1)
	once := sync.OnceFunc(func() { close(release) })
	t.Cleanup(once)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer sk-held" {
			entered <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusOK)
	})
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	limits := drain.Limits{Deliver: time.Minute, Upstream: time.Minute, Stall: time.Minute, Parallel: 1}
	srv := httptest.NewServer(drain.New(target, limits, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	call := func(key string) int {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/messages", strings.NewReader("{}"))
		if reqErr != nil {
			return 0
		}
		req.Header.Set("X-Api-Key", key)
		resp, doErr := srv.Client().Do(req)
		if doErr != nil {
			return 0
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	first := make(chan int, 1)
	go func() { first <- call("sk-held") }()
	<-entered
	require.Equal(t, http.StatusTooManyRequests, call("sk-held"))
	require.Equal(t, http.StatusOK, call("sk-other"))
	once()
	require.Equal(t, http.StatusOK, <-first)
	got := make(chan int, 1)
	go func() { got <- call("sk-held") }()
	<-entered
	require.Equal(t, http.StatusOK, <-got, "the slot came back")
}

// One credential, in one accepted form, and one normalized header on: a junk second header or another form could otherwise
// dodge the limit, since LiteLLM authenticates from only the first it finds.
// LiteLLM takes its call id, which the budget guard counts under, and other controls from these headers: no client may set them.
func TestLiteLLMControlHeadersStopHere(t *testing.T) {
	t.Parallel()
	got := make(chan http.Header, 1)
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got <- r.Header.Clone() })
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/messages", strings.NewReader("{}"))
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", "sk-a")
	req.Header.Set("X-Litellm-Call-Id", "chosen")
	req.Header.Set("X-Litellm-Timeout", "1")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	seen := <-got
	require.Empty(t, seen.Get("X-Litellm-Call-Id"))
	require.Empty(t, seen.Get("X-Litellm-Timeout"))
	require.Equal(t, "2023-06-01", seen.Get("Anthropic-Version"), "other headers go on")
}

func TestCredentialForms(t *testing.T) {
	t.Parallel()
	var seen sync.Map
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen.Store(r.Header.Get("X-Case"), r.Header.Clone()) })
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"bearer", map[string]string{"Authorization": "Bearer sk-a"}, http.StatusOK},
		{"x-api-key", map[string]string{"X-Api-Key": "sk-a"}, http.StatusOK},
		{"both, the bearer wins, as Claude Code can send", map[string]string{"Authorization": "Bearer sk-a", "X-Api-Key": "sk-junk"},
			http.StatusOK},
		{"a space in the token, which LiteLLM's bearer parsing would fold", map[string]string{"Authorization": "Bearer sk-Bearer a"},
			http.StatusUnauthorized},
		{"none", nil, http.StatusUnauthorized},
		{"lowercase bearer", map[string]string{"Authorization": "bearer sk-a"}, http.StatusUnauthorized},
		{"basic", map[string]string{"Authorization": "Basic sk-a"}, http.StatusUnauthorized},
		{"doubled bearer", map[string]string{"Authorization": "Bearer " + "Bearer sk-a"}, http.StatusUnauthorized},
		{"not a key", map[string]string{"X-Api-Key": "abc"}, http.StatusUnauthorized},
		{"a form this does not accept", map[string]string{"X-Litellm-Api-Key": "sk-a"}, http.StatusUnauthorized},
		{"another form alongside", map[string]string{"Authorization": "Bearer sk-a", "X-Litellm-Api-Key": "sk-b", "Api-Key": "sk-c",
			"X-Goog-Api-Key": "sk-d", "Ocp-Apim-Subscription-Key": "sk-e"}, http.StatusOK},
	}
	for _, tc := range tests {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/messages", strings.NewReader("{}"))
		require.NoError(t, err)
		req.Header.Set("X-Case", tc.name)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, tc.want, resp.StatusCode, tc.name)
		got, reached := seen.Load(tc.name)
		require.Equal(t, tc.want == http.StatusOK, reached, tc.name)
		if reached {
			headers, ok := got.(http.Header)
			require.True(t, ok)
			require.Equal(t, "Bearer sk-a", headers.Get("Authorization"), tc.name)
			for _, stripped := range []string{"X-Api-Key", "X-Litellm-Api-Key", "Api-Key", "X-Goog-Api-Key", "Ocp-Apim-Subscription-Key"} {
				require.Empty(t, headers.Get(stripped), "%s: %s", tc.name, stripped)
			}
		}
	}
}

// The bypass the limit must not have: the same bearer with a different junk header each time would be a new bucket.
func TestParallelLimitCountsTheKeyWhateverItsForm(t *testing.T) {
	t.Parallel()
	release, entered := make(chan struct{}), make(chan struct{}, 1)
	once := sync.OnceFunc(func() { close(release) })
	t.Cleanup(once)
	upstream := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		entered <- struct{}{}
		<-release
	})
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	srv := httptest.NewServer(drain.New(target, drain.Limits{Deliver: time.Minute, Upstream: time.Minute, Stall: time.Minute, Parallel: 1},
		slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	first, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/messages", strings.NewReader("{}"))
	require.NoError(t, err)
	first.Header.Set("Authorization", "Bearer sk-same")
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, doErr := srv.Client().Do(first); doErr == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered
	second, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/messages", strings.NewReader("{}"))
	require.NoError(t, err)
	second.Header.Set("X-Api-Key", "sk-same")
	resp, err := srv.Client().Do(second)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "the same key by another header")
	once()
	<-done
}

// The critical case: a reader slow enough never to trip the stall limit must not hold LiteLLM back past the egress's limit,
// where the cut would leave it nothing to book. Past the delivery limit the reply is only read.
func TestASlowReaderCannotOutlastTheDeliveryLimit(t *testing.T) {
	t.Parallel()
	finished := make(chan struct{})
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 64 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		close(finished)
	})
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	target, err := url.Parse(backend.URL)
	require.NoError(t, err)
	limits := drain.Limits{Deliver: 100 * time.Millisecond, Upstream: 20 * time.Second, Stall: time.Hour, Parallel: 1}
	srv := httptest.NewServer(drain.New(target, limits, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()
	_, err = io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nX-Api-Key: sk-raw\r\nContent-Length: 2\r\n\r\n{}")
	require.NoError(t, err)
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("a reader that never trips the stall limit held the upstream past the delivery limit")
	}
}

// A body past the limit stops here, declared or not, before LiteLLM reads it into memory.
func TestBodyLimit(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
	})
	srv := newProxy(t, upstream, time.Minute, time.Minute, nil)
	big := bytes.Repeat([]byte("x"), drain.MaxBodyBytes+1)
	for _, tc := range []struct {
		name string
		body io.Reader
	}{{"declared", bytes.NewReader(big)}, {"chunked", io.MultiReader(bytes.NewReader(big))}} {
		name, body := tc.name, tc.body
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/messages", body)
		require.NoError(t, err)
		req.Header.Set("X-Api-Key", "sk-a")
		resp, err := srv.Client().Do(req)
		require.NoError(t, err, name)
		require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode, name)
		require.NoError(t, resp.Body.Close())
		if name == "declared" {
			require.Zero(t, calls.Load(), "a declared oversize never reaches the upstream")
		}
	}
}

// Quiet longer than the stall limit before the end of a stream still gives the client a clean finish.
func TestQuietBeforeTheEndDoesNotBreakTheBody(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("data"))
		assert.NoError(t, err)
		assert.NoError(t, http.NewResponseController(w).Flush())
		time.Sleep(300 * time.Millisecond)
	})
	srv := newProxy(t, upstream, time.Minute, 100*time.Millisecond, nil)
	resp := post(t, srv, "/v1/chat/completions")
	defer func() { require.NoError(t, resp.Body.Close()) }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "no unexpected EOF")
	require.Equal(t, "data", string(body))
}

// Only the inference routes pass: the admin API must stay out of reach even if the edge's table were wrong.
func TestServesOnlyTheInferenceRoutes(t *testing.T) {
	t.Parallel()
	srv := newProxy(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), time.Minute, time.Minute, nil)
	for _, path := range drain.Routes() {
		resp := post(t, srv, path)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.NoError(t, resp.Body.Close())
	}
	for _, path := range []string{"/", "/key/generate", "/key/info", "/spend/logs", "/config/update", "/v1/messages/x"} {
		resp := post(t, srv, path)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, path)
		require.NoError(t, resp.Body.Close())
	}
}

// Nothing of a request or its reply reaches a log line, on any path.
func TestLogsNoContent(t *testing.T) {
	t.Parallel()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte("secret-completion"))
		assert.NoError(t, err)
	})
	var logs safeBuffer
	srv := newProxy(t, upstream, time.Minute, time.Minute, &logs)
	resp := post(t, srv, "/v1/chat/completions")
	_, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	target, err := url.Parse("http://127.0.0.1:1")
	require.NoError(t, err)
	limits := drain.Limits{Deliver: time.Second, Upstream: time.Second, Stall: time.Second, Parallel: 1}
	down := httptest.NewServer(drain.New(target, limits, slog.New(slog.NewTextHandler(&logs, nil))))
	t.Cleanup(down.Close)
	resp = post(t, down, "/v1/chat/completions")
	require.NoError(t, resp.Body.Close())

	// A hang-up is where the proxy itself logs.
	hangUp := newProxy(t, upstream, time.Minute, time.Minute, &logs)
	conn, err := net.Dial("tcp", hangUp.Listener.Addr().String())
	require.NoError(t, err)
	_, err = io.WriteString(conn, "POST /v1/chat/completions?marker=secret-query HTTP/1.1\r\nHost: x\r\n"+
		"X-Api-Key: sk-client-key\r\nContent-Length: 2\r\n\r\n{}")
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	for _, secret := range []string{"secret-prompt", "secret-completion", "sk-client-key", "secret-query"} {
		require.NotContains(t, logs.String(), secret)
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
