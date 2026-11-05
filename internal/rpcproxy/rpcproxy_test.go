package rpcproxy_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/rpcproxy"
	"github.com/sealedin/gateway/internal/solanarpc"
)

const apiKey = "provider-secret"

// upstream records what reached it and answers a fixed reply.
type upstream struct {
	srv    *httptest.Server
	bodies []string
	query  []string
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		u.bodies = append(u.bodies, string(body))
		u.query = append(u.query, r.URL.RawQuery)
		_, err = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"ok"}`))
		assert.NoError(t, err)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func newProxy(t *testing.T) (*httptest.Server, *upstream, *upstream) {
	t.Helper()
	primary, confirmation := newUpstream(t), newUpstream(t)
	policy := rpcproxy.Policy{
		Primary:      rpcproxy.Host{URL: primary.srv.URL + "/", APIKeyParam: "api-key"},
		Confirmation: rpcproxy.Host{URL: confirmation.srv.URL + "/"},
	}
	handler, err := rpcproxy.NewMux(policy, apiKey, primary.srv.Client(), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)
	return proxy, primary, confirmation
}

func post(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func call(method string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":[]}`
}

// The allowlist is exactly what settlement calls, per route.
func TestAllowlist(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path, method string
		want         int
	}{
		{solanarpc.PrimaryRoute, solanarpc.MethodLatestBlockhash, http.StatusOK},
		{solanarpc.PrimaryRoute, solanarpc.MethodSimulate, http.StatusOK},
		{solanarpc.PrimaryRoute, solanarpc.MethodSend, http.StatusOK},
		{solanarpc.PrimaryRoute, solanarpc.MethodSignatureStatuses, http.StatusOK},
		{solanarpc.PrimaryRoute, solanarpc.MethodTransaction, http.StatusOK},
		{solanarpc.ConfirmationRoute, solanarpc.MethodSignatureStatuses, http.StatusOK},
		{solanarpc.ConfirmationRoute, solanarpc.MethodSend, http.StatusForbidden},
		{solanarpc.ConfirmationRoute, solanarpc.MethodTransaction, http.StatusForbidden},
		{solanarpc.PrimaryRoute, "getBalance", http.StatusForbidden},
		{solanarpc.PrimaryRoute, "getProgramAccounts", http.StatusForbidden},
		{solanarpc.PrimaryRoute, "requestAirdrop", http.StatusForbidden},
		{solanarpc.PrimaryRoute, "", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.path+" "+tc.method, func(t *testing.T) {
			t.Parallel()
			proxy, _, _ := newProxy(t)
			status, _ := post(t, proxy.URL+tc.path, call(tc.method))
			require.Equal(t, tc.want, status)
		})
	}
}

func TestRefusesWhatItCannotReadStrictly(t *testing.T) {
	t.Parallel()
	proxy, primary, _ := newProxy(t)
	for name, body := range map[string]string{
		"batch":         `[` + call(solanarpc.MethodSend) + `]`,
		"not json":      `nope`,
		"unknown field": `{"method":"sendTransaction","extra":1}`,
		"trailing data": call(solanarpc.MethodSend) + call("getBalance"),
		"too large":     `{"method":"sendTransaction","params":["` + strings.Repeat("A", 1<<20) + `"]}`,
	} {
		status, _ := post(t, proxy.URL+solanarpc.PrimaryRoute, body)
		require.Equal(t, http.StatusBadRequest, status, name)
	}
	require.Empty(t, primary.bodies, "nothing unreadable reaches a provider")
}

// The forwarded body is rebuilt from what the allowlist read, so a duplicate key cannot smuggle another method upstream.
func TestForwardsOnlyTheParsedCall(t *testing.T) {
	t.Parallel()
	proxy, primary, _ := newProxy(t)
	status, _ := post(t, proxy.URL+solanarpc.PrimaryRoute, `{"method":"requestAirdrop","method":"sendTransaction","id":7,"params":["x"]}`)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, primary.bodies, 1)
	var forwarded map[string]any
	require.NoError(t, json.Unmarshal([]byte(primary.bodies[0]), &forwarded))
	require.Equal(t, "sendTransaction", forwarded["method"])
	require.NotContains(t, primary.bodies[0], "requestAirdrop")
}

func TestAPIKeyGoesOnlyToThePrimary(t *testing.T) {
	t.Parallel()
	proxy, primary, confirmation := newProxy(t)
	_, reply := post(t, proxy.URL+solanarpc.PrimaryRoute, call(solanarpc.MethodSignatureStatuses))
	require.JSONEq(t, `{"jsonrpc":"2.0","id":1,"result":"ok"}`, reply)
	post(t, proxy.URL+solanarpc.ConfirmationRoute, call(solanarpc.MethodSignatureStatuses))
	require.Equal(t, []string{"api-key=" + apiKey}, primary.query)
	require.Equal(t, []string{""}, confirmation.query)
}

// http.Client errors quote the URL, which carries the key: neither the reply nor the log may repeat it.
func TestUpstreamFailureNeverLeaksTheKey(t *testing.T) {
	t.Parallel()
	var logs strings.Builder
	policy := rpcproxy.Policy{Primary: rpcproxy.Host{URL: "http://127.0.0.1:1/", APIKeyParam: "api-key"},
		Confirmation: rpcproxy.Host{URL: "http://127.0.0.1:1/"}}
	handler, err := rpcproxy.NewMux(policy, apiKey, http.DefaultClient, slog.New(slog.NewTextHandler(&logs, nil)))
	require.NoError(t, err)
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)
	status, reply := post(t, proxy.URL+solanarpc.PrimaryRoute, call(solanarpc.MethodSend))
	require.Equal(t, http.StatusBadGateway, status)
	require.NotContains(t, reply, apiKey)
	require.NotContains(t, logs.String(), apiKey)
	require.Contains(t, logs.String(), "upstream failed")
}

func TestNewMuxNeedsTheKeyThePolicyNames(t *testing.T) {
	t.Parallel()
	policy := rpcproxy.Policy{Primary: rpcproxy.Host{URL: "https://a.test/", APIKeyParam: "api-key"},
		Confirmation: rpcproxy.Host{URL: "https://b.test/"}}
	_, err := rpcproxy.NewMux(policy, "", http.DefaultClient, slog.New(slog.DiscardHandler))
	require.Error(t, err)
}

func TestLoadPolicyRefuses(t *testing.T) {
	t.Parallel()
	for name, text := range map[string]string{
		"not https":     "primary: {url: 'http://a.test/'}\nconfirmation: {url: 'https://b.test/'}\n",
		"query in url":  "primary: {url: 'https://a.test/?api-key=x'}\nconfirmation: {url: 'https://b.test/'}\n",
		"userinfo":      "primary: {url: 'https://k@a.test/'}\nconfirmation: {url: 'https://b.test/'}\n",
		"same host":     "primary: {url: 'https://a.test/'}\nconfirmation: {url: 'https://a.test/x'}\n",
		"no primary":    "confirmation: {url: 'https://b.test/'}\n",
		"unknown field": "primary: {url: 'https://a.test/', extra: 1}\nconfirmation: {url: 'https://b.test/'}\n",
		"key on second": "primary: {url: 'https://a.test/'}\nconfirmation: {url: 'https://b.test/', api_key_param: k}\n",
	} {
		_, err := rpcproxy.LoadPolicy(strings.NewReader(text))
		require.Error(t, err, name)
	}
}

// The file baked into the image parses and names the chosen provider; a placeholder host stays refused.
func TestMeasuredPolicy(t *testing.T) {
	t.Parallel()
	f, err := os.Open(filepath.Join("..", "..", "rpcproxy", "policy.yaml"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	policy, err := rpcproxy.LoadPolicy(f)
	require.NoError(t, err)
	require.Equal(t, "https://solana-rpc.publicnode.com/", policy.Confirmation.URL)
	require.Equal(t, "https://mainnet.helius-rpc.com/", policy.Primary.URL)
	require.Equal(t, "api-key", policy.Primary.APIKeyParam)
	require.False(t, policy.Placeholder())
	policy.Primary.URL = "https://solana-rpc-placeholder.invalid/"
	require.True(t, policy.Placeholder())
}
