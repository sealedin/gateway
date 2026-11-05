package enclave_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/enclave"
)

func serve(t *testing.T, id *enclave.Identity, edge enclave.CertSource) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(enclave.NewMux(id, edge))
	t.Cleanup(srv.Close)
	return srv
}

func unattestedServer(t *testing.T) *httptest.Server {
	t.Helper()
	id, err := enclave.NewIdentity()
	require.NoError(t, err)
	return serve(t, id, nil)
}

// attestedServer serves an identity whose fake fetch echoes the report data back as the quote.
func attestedServer(t *testing.T) (*httptest.Server, *enclave.Identity) {
	t.Helper()
	id, err := enclave.NewTestIdentityWithEventLog(fakeFetch, []byte(sampleEventLog))
	require.NoError(t, err)
	return serve(t, id, nil), id
}

type body map[string]json.RawMessage

func (b body) str(t *testing.T, key string) string {
	t.Helper()
	var s string
	require.NoError(t, json.Unmarshal(b[key], &s), "field %q missing or not a string", key)
	return s
}

func (b body) num(t *testing.T, key string) float64 {
	t.Helper()
	var n float64
	require.NoError(t, json.Unmarshal(b[key], &n), "field %q missing or not a number", key)
	return n
}

func getJSON(t *testing.T, url string) (int, body) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var decoded body
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	return resp.StatusCode, decoded
}

func TestQuoteEndpointRejects(t *testing.T) {
	t.Parallel()
	unattested := unattestedServer(t)
	attested, _ := attestedServer(t)
	tests := []struct {
		name    string
		srv     *httptest.Server
		method  string
		path    string
		want    int
		wantErr string
	}{
		{"unattested", unattested, http.MethodGet, "/v1/quote", http.StatusNotFound, "not running in a TEE"},
		{"unattested with block id", unattested, http.MethodGet, "/v1/quote?block_id=" + strings.Repeat("ab", 32),
			http.StatusNotFound, "not running in a TEE"},
		{"not hex", unattested, http.MethodGet, "/v1/quote?block_id=zz", http.StatusBadRequest, "block_id"},
		{"bare prefix", unattested, http.MethodGet, "/v1/quote?block_id=0x", http.StatusBadRequest, "block_id"},
		{"too long", unattested, http.MethodGet, "/v1/quote?block_id=" + strings.Repeat("ab", 33), http.StatusBadRequest, "block_id"},
		// url.Query would drop the malformed pair and serve the stale startup quote under a 200.
		{"malformed query", attested, http.MethodGet, "/v1/quote?block_id=ab;x=1", http.StatusBadRequest, "block_id"},
		{"wrong method", unattested, http.MethodPost, "/v1/quote", http.StatusMethodNotAllowed, ""},
		{"unknown path", unattested, http.MethodGet, "/v1/nope", http.StatusNotFound, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(t.Context(), tc.method, tc.srv.URL+tc.path, http.NoBody)
			require.NoError(t, err)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, tc.want, resp.StatusCode)
			if tc.wantErr == "" {
				return
			}
			var decoded body
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
			require.Contains(t, decoded.str(t, "error"), tc.wantErr)
		})
	}
}

// The fake fetch echoes report data, so the served quote proves what was bound; the event log rides along unparsed
// with every attested quote.
func TestQuoteEndpointServesQuote(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		query       string
		wantBlockID string
	}{
		{"fresh quote binds the block id", "?block_id=0xff", strings.Repeat("0", 62) + "ff"},
		{"startup quote without block id", "", strings.Repeat("0", 64)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, id := attestedServer(t)
			status, got := getJSON(t, srv.URL+"/v1/quote"+tc.query)
			require.Equal(t, http.StatusOK, status)
			require.Equal(t, tc.wantBlockID, got.str(t, "block_id"))
			require.Equal(t, id.PublicKeyHex(), got.str(t, "pubkey"))
			require.InDelta(t, 2, got.num(t, "report_data_version"), 0)
			quote, err := base64.StdEncoding.DecodeString(got.str(t, "quote"))
			require.NoError(t, err)
			require.Equal(t, tc.wantBlockID+id.PublicKeyHex(), hex.EncodeToString(quote))
			require.JSONEq(t, sampleEventLog, string(got["event_log"]))
			require.JSONEq(t, sampleEventLog, string(id.EventLog()))
		})
	}
}

func TestParseBlockID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		raw     string
		want    [enclave.BlockIDSize]byte
		fresh   bool
		wantErr bool
	}{
		{name: "empty means startup quote", raw: "", fresh: false},
		{name: "full 32 bytes", raw: "0102030405060708091011121314151617181920212223242526272829303132",
			want: [enclave.BlockIDSize]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
				0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32,
			}, fresh: true},
		{name: "short value right-aligned", raw: "2a", want: [enclave.BlockIDSize]byte{31: 0x2a}, fresh: true},
		{name: "odd length left-padded", raw: "abc", want: [enclave.BlockIDSize]byte{30: 0x0a, 31: 0xbc}, fresh: true},
		{name: "0x prefix", raw: "0x2a", want: [enclave.BlockIDSize]byte{31: 0x2a}, fresh: true},
		{name: "decimal-looking number", raw: "42", want: [enclave.BlockIDSize]byte{31: 0x42}, fresh: true},
		{name: "not hex", raw: "zz", wantErr: true},
		{name: "bare 0x", raw: "0x", wantErr: true},
		{name: "over 32 bytes", raw: "00" + "0102030405060708091011121314151617181920212223242526272829303132",
			wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			blockID, fresh, err := enclave.ParseBlockID(tc.raw)
			if tc.wantErr {
				require.ErrorIs(t, err, enclave.ErrBadBlockID)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.fresh, fresh)
			require.Equal(t, tc.want, blockID)
		})
	}
}
