package keys_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/keys"
	"github.com/sealedin/gateway/internal/testsupport"
)

const (
	masterKey   = "sk-master"
	operatorKey = "op-secret"
)

func newService(t *testing.T, fake *testsupport.FakeGateway) (*httptest.Server, *testsupport.FakeGateway) {
	t.Helper()
	if fake == nil {
		fake = &testsupport.FakeGateway{MasterKey: masterKey}
	}
	svc := &keys.Service{Gateway: fake.Client(t), Operator: operatorKey, Models: gateway.CatalogModels()}
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, fake
}

func call(t *testing.T, srv *httptest.Server, method, path, bearer, body string) (int, map[string]any, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded map[string]any
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &decoded), "body: %s", raw)
	}
	return resp.StatusCode, decoded, string(raw)
}

func TestIssueScopesToMeasuredCatalog(t *testing.T) {
	t.Parallel()
	srv, fake := newService(t, nil)
	status, body, _ := call(t, srv, http.MethodPost, "/v1/keys", operatorKey, `{"alias":"alice","max_budget_usd":20,"rpm_limit":30}`)
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, "alice", body["alias"])
	require.NotEmpty(t, body["key"])
	require.InEpsilon(t, 20.0, body["max_budget_usd"], 1e-12)
	require.InEpsilon(t, 30.0, body["rpm_limit"], 1e-12)
	want := gateway.CatalogModels()
	got, ok := body["models"].([]any)
	require.True(t, ok)
	require.Len(t, got, len(want))
	for i, m := range want {
		require.Equal(t, m, got[i])
	}
	calls := fake.Generated()
	require.Len(t, calls, 1)
	require.Equal(t, want, calls[0].Models, "the gateway must receive exactly the measured catalog")
	require.Equal(t, 30, calls[0].RPMLimit)
	require.Nil(t, calls[0].BudgetDuration, "prepaid credits never reset")
}

func TestIssueDefaultsRPM(t *testing.T) {
	t.Parallel()
	srv, fake := newService(t, nil)
	status, _, _ := call(t, srv, http.MethodPost, "/v1/keys", operatorKey, `{"alias":"bob","max_budget_usd":5}`)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 60, fake.Generated()[0].RPMLimit)
}

func TestIssueRejectsBadRequests(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{"malformed json", `{`},
		{"empty alias", `{"alias":"","max_budget_usd":1}`},
		{"uppercase alias", `{"alias":"Alice","max_budget_usd":1}`},
		{"alias too long", `{"alias":"` + strings.Repeat("a", 65) + `","max_budget_usd":1}`},
		{"alias with slash", `{"alias":"a/b","max_budget_usd":1}`},
		{"missing budget", `{"alias":"alice"}`},
		{"zero budget", `{"alias":"alice","max_budget_usd":0}`},
		{"negative budget", `{"alias":"alice","max_budget_usd":-1}`},
		{"zero rpm", `{"alias":"alice","max_budget_usd":1,"rpm_limit":0}`},
		{"budget over the ceiling", fmt.Sprintf(`{"alias":"alice","max_budget_usd":%d}`, keys.MaxBudgetUSD+1)},
		{"rpm over the ceiling", fmt.Sprintf(`{"alias":"alice","max_budget_usd":1,"rpm_limit":%d}`, keys.MaxRPMLimit+1)},
		{"fractional rpm", `{"alias":"alice","max_budget_usd":1,"rpm_limit":1.5}`},
		{"models not caller-chosen", `{"alias":"alice","max_budget_usd":1,"models":["*"]}`},
		{"metadata refused", `{"alias":"alice","max_budget_usd":1,"metadata":{"x":1}}`},
		{"trailing data", `{"alias":"alice","max_budget_usd":1}{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, fake := newService(t, nil)
			status, body, _ := call(t, srv, http.MethodPost, "/v1/keys", operatorKey, tc.body)
			require.Equal(t, http.StatusBadRequest, status, body)
			require.Contains(t, body, "error")
			require.Empty(t, fake.Generated(), "nothing reaches the gateway")
		})
	}
}

func TestIssueAcceptsTheCeilings(t *testing.T) {
	t.Parallel()
	srv, _ := newService(t, nil)
	body := fmt.Sprintf(`{"alias":"alice","max_budget_usd":%d,"rpm_limit":%d}`, keys.MaxBudgetUSD, keys.MaxRPMLimit)
	status, reply, _ := call(t, srv, http.MethodPost, "/v1/keys", operatorKey, body)
	require.Equal(t, http.StatusOK, status, reply)
}

func TestOversizedBodyIs413(t *testing.T) {
	t.Parallel()
	srv, fake := newService(t, nil)
	body := `{"alias":"` + strings.Repeat("a", 5000) + `","max_budget_usd":1}`
	status, _, _ := call(t, srv, http.MethodPost, "/v1/keys", operatorKey, body)
	require.Equal(t, http.StatusRequestEntityTooLarge, status)
	require.Empty(t, fake.Generated())
}

func TestBearerAuthFailsClosed(t *testing.T) {
	t.Parallel()
	srv, fake := newService(t, nil)
	t.Cleanup(func() { require.Empty(t, fake.Generated(), "no rejected bearer may reach the gateway") })
	cases := []struct {
		name   string
		bearer string
	}{
		{"no header", ""},
		{"wrong token", "op-secre"},
		{"longer token", operatorKey + "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, route := range []struct{ method, path string }{{http.MethodPost, "/v1/keys"}, {http.MethodGet, "/v1/keys/alice"}} {
				status, _, raw := call(t, srv, route.method, route.path, tc.bearer, `{"alias":"alice","max_budget_usd":1}`)
				require.Equal(t, http.StatusUnauthorized, status)
				require.Empty(t, raw, "no detail on a failed bearer")
			}
		})
	}
}

// An unset operator key must not let an empty bearer through: two empty strings compare equal.
func TestEmptyOperatorKeyRefusesAll(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey}
	svc := &keys.Service{Gateway: fake.Client(t), Operator: "", Models: gateway.CatalogModels()}
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for _, bearer := range []string{"", "x"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/keys", strings.NewReader(`{}`))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestLookupReportsSpend(t *testing.T) {
	t.Parallel()
	srv, _ := newService(t, &testsupport.FakeGateway{MasterKey: masterKey, SpendUSD: 0.25})
	status, _, _ := call(t, srv, http.MethodPost, "/v1/keys", operatorKey, `{"alias":"alice","max_budget_usd":20}`)
	require.Equal(t, http.StatusOK, status)

	status, body, _ := call(t, srv, http.MethodGet, "/v1/keys/alice", operatorKey, "")
	require.Equal(t, http.StatusOK, status, body)
	require.Equal(t, map[string]any{"alias": "alice", "spend_usd": 0.25, "max_budget_usd": 20.0}, body)

	status, body, _ = call(t, srv, http.MethodGet, "/v1/keys/nobody", operatorKey, "")
	require.Equal(t, http.StatusNotFound, status, body)
	status, _, _ = call(t, srv, http.MethodGet, "/v1/keys/Not-Valid", operatorKey, "")
	require.Equal(t, http.StatusBadRequest, status)
}

// A gateway failure is a 502 without its detail; the wrong master key is the operator's problem, not the client's.
func TestGatewayFailureIsBadGateway(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: "sk-other"}
	gw := fake.Client(t)
	gw.MasterKey = masterKey
	svc := &keys.Service{Gateway: gw, Operator: operatorKey, Models: gateway.CatalogModels()}
	mux := http.NewServeMux()
	svc.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	status, body, _ := call(t, srv, http.MethodPost, "/v1/keys", operatorKey, `{"alias":"alice","max_budget_usd":1}`)
	require.Equal(t, http.StatusBadGateway, status)
	require.Equal(t, map[string]any{"error": "gateway unavailable"}, body)
}
