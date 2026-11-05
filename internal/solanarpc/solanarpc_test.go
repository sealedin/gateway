package solanarpc_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/solanarpc"
)

// stub answers every call with reply and records the method and params it saw.
func stub(t *testing.T, reply string) (*solanarpc.Client, *struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}) {
	t.Helper()
	seen := &struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.NoError(t, json.Unmarshal(body, seen))
		_, err = w.Write([]byte(reply))
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)
	return &solanarpc.Client{URL: srv.URL, HTTP: srv.Client()}, seen
}

func TestLatestBlockhash(t *testing.T) {
	t.Parallel()
	c, seen := stub(t, `{"result":{"value":{"blockhash":"abc","lastValidBlockHeight":77}}}`)
	hash, height, err := c.LatestBlockhash(t.Context())
	require.NoError(t, err)
	require.Equal(t, "abc", hash)
	require.Equal(t, uint64(77), height)
	require.Equal(t, "getLatestBlockhash", seen.Method)
}

func TestSimulate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, reply string
		wantErr     string
	}{
		{"passes", `{"result":{"value":{"err":null,"unitsConsumed":10}}}`, ""},
		{"fails", `{"result":{"value":{"err":"BlockhashNotFound"}}}`, `"BlockhashNotFound"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, seen := stub(t, tc.reply)
			failure, err := c.Simulate(t.Context(), []byte{1, 2})
			require.NoError(t, err)
			require.Equal(t, tc.wantErr, failure)
			require.JSONEq(t, `["AQI=",{"encoding":"base64","sigVerify":false,"commitment":"confirmed"}]`, string(seen.Params),
				"a partially signed transaction cannot be simulated with signature checks")
		})
	}
}

func TestSend(t *testing.T) {
	t.Parallel()
	c, seen := stub(t, `{"result":"sig1"}`)
	id, err := c.Send(t.Context(), []byte{1, 2})
	require.NoError(t, err)
	require.Equal(t, "sig1", id)
	require.JSONEq(t, `["AQI=",{"encoding":"base64","skipPreflight":true}]`, string(seen.Params), "the sponsor already simulated")
}

func TestSignatureStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, reply string
		want        *solanarpc.Status
	}{
		{"unknown", `{"result":{"value":[null]}}`, nil},
		{"confirmed", `{"result":{"value":[{"confirmationStatus":"confirmed","err":null}]}}`, &solanarpc.Status{Confirmed: true}},
		{"finalized", `{"result":{"value":[{"confirmationStatus":"finalized","err":null}]}}`, &solanarpc.Status{Confirmed: true}},
		{"processed", `{"result":{"value":[{"confirmationStatus":"processed","err":null}]}}`, &solanarpc.Status{}},
		{"failed", `{"result":{"value":[{"confirmationStatus":"confirmed","err":{"InstructionError":[2,{"Custom":1}]}}]}}`,
			&solanarpc.Status{Confirmed: true, Failure: `{"InstructionError":[2,{"Custom":1}]}`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, seen := stub(t, tc.reply)
			got, err := c.SignatureStatus(t.Context(), "sig1")
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.JSONEq(t, `[["sig1"],{"searchTransactionHistory":true}]`, string(seen.Params))
		})
	}
}

func TestTransaction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, reply string
		want        *solanarpc.ConfirmedTransaction
		wantErr     bool
	}{
		{"unknown", `{"result":null}`, nil, false},
		{"landed", `{"result":{"transaction":["AQI=","base64"],"meta":{"err":null}}}`,
			&solanarpc.ConfirmedTransaction{Raw: []byte{1, 2}}, false},
		{"with a block time", `{"result":{"transaction":["AQI=","base64"],"blockTime":1800000000,"meta":{"err":null}}}`,
			&solanarpc.ConfirmedTransaction{Raw: []byte{1, 2}, BlockTime: time.Unix(1800000000, 0)}, false},
		{"failed", `{"result":{"transaction":["AQI=","base64"],"meta":{"err":"Boom"}}}`,
			&solanarpc.ConfirmedTransaction{Raw: []byte{1, 2}, Failure: `"Boom"`}, false},
		{"no meta", `{"result":{"transaction":["AQI=","base64"]}}`, nil, true},
		{"wrong encoding", `{"result":{"transaction":["AQI=","base58"],"meta":{"err":null}}}`, nil, true},
		{"bad base64", `{"result":{"transaction":["!!","base64"],"meta":{"err":null}}}`, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, seen := stub(t, tc.reply)
			got, err := c.Transaction(t.Context(), "sig1")
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.JSONEq(t, `["sig1",{"encoding":"base64","commitment":"confirmed","maxSupportedTransactionVersion":0}]`, string(seen.Params))
		})
	}
}

func TestSimulateRefusesAnEmptyReply(t *testing.T) {
	t.Parallel()
	for _, reply := range []string{`{"result":{}}`, `{"result":{"value":null}}`, `{"result":null}`} {
		c, _ := stub(t, reply)
		_, err := c.Simulate(t.Context(), []byte{1})
		require.Error(t, err, reply)
	}
}

// An error object is the node's definite answer, distinct from a transport failure that leaves the outcome unknown.
func TestErrorsAreDistinct(t *testing.T) {
	t.Parallel()
	c, _ := stub(t, `{"error":{"code":-32005,"message":"unhealthy"}}`)
	_, err := c.Send(t.Context(), []byte{1})
	rpcErr, ok := errors.AsType[*solanarpc.Error](err)
	require.True(t, ok, "err: %v", err)
	require.Equal(t, -32005, rpcErr.Code)

	down := &solanarpc.Client{URL: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	_, err = down.Send(t.Context(), []byte{1})
	require.Error(t, err)
	_, ok = errors.AsType[*solanarpc.Error](err)
	require.False(t, ok)
}

func TestOnlySomeErrorObjectsAreDefinite(t *testing.T) {
	t.Parallel()
	require.True(t, (&solanarpc.Error{Code: -32005}).Definite())
	require.False(t, (&solanarpc.Error{Code: -32000}).Definite(), "an unknown code may follow a forward")
}

func TestRejectsNonOKStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(srv.Close)
	c := &solanarpc.Client{URL: srv.URL, HTTP: srv.Client()}
	_, _, err := c.LatestBlockhash(t.Context())
	require.ErrorContains(t, err, "status 403")
}

func TestTimeoutOrder(t *testing.T) {
	t.Parallel()
	require.Less(t, solanarpc.ProxyUpstreamTimeout, solanarpc.CallTimeout)
	require.Less(t, solanarpc.CallTimeout, solanarpc.ClientTimeout)
}
