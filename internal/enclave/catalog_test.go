package enclave_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/enclave"
	"github.com/sealedin/gateway/internal/gateway"
)

const catalogTag = "sealedin-catalog-v1"

// demoContent carries an ampersand in list_source: jq prints it raw, so the preimage must not HTML-escape.
func demoContent() gateway.Catalog {
	return gateway.Catalog{
		ListAsOf:      "2026-11-03",
		ListSource:    "https://example.test/list?a=1&b=<2>",
		MarkupPercent: 5,
		PayTo:         "TreasuryAddress",
		Networks:      []string{"solana:test"},
		Asset:         "MintAddress",
		Models: []gateway.CatalogModel{
			{ID: "chutes/org/a-TEE", InputUSDPerMTok: "1.3125", OutputUSDPerMTok: "4.1475", Provider: gateway.Provider,
				Tier: gateway.Tier, UpstreamID: "org/a-TEE"},
			{ID: "chutes/org/b-TEE", InputUSDPerMTok: "0.04095", OutputUSDPerMTok: "1.3125", Provider: gateway.Provider,
				Tier: gateway.Tier, UpstreamID: "org/b-TEE"},
		},
	}
}

func demoCatalog() enclave.Catalog {
	return enclave.Catalog{Catalog: demoContent(), IssuedAt: 1800000000, Pubkey: strings.Repeat("ab", 32), FeePayer: "FeePayerAddress"}
}

// jqCanonical runs the documented recipe, jq -cjS 'del(.signature)', on a reply; skipped where jq is not installed.
func jqCanonical(t *testing.T, reply []byte) []byte {
	t.Helper()
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not installed; the documented recipe cannot be exercised")
	}
	cmd := exec.CommandContext(t.Context(), jq, "-cjS", "del(.signature)")
	cmd.Stdin = bytes.NewReader(reply)
	out, err := cmd.Output()
	require.NoError(t, err)
	return out
}

// The preimage is the tag, a NUL and the body exactly as the documented jq recipe prints it.
func TestCatalogMessageMatchesJq(t *testing.T) {
	t.Parallel()
	catalog := demoCatalog()
	msg, err := catalog.Message()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(msg), catalogTag+"\x00"))
	body := msg[len(catalogTag)+1:]
	require.True(t, strings.HasPrefix(string(body), `{"asset":"MintAddress","fee_payer":"FeePayerAddress",`+
		`"issued_at":1800000000,"list_as_of":"2026-11-03","list_source":"https://example.test/list?a=1&b=<2>",`))
	require.Contains(t, string(body), `"networks":["solana:test"],"pay_to":"TreasuryAddress","pubkey":`)
	require.Contains(t, string(body), `"models":[{"id":"chutes/org/a-TEE","input_usd_per_mtok":"1.3125",`)

	reply, err := json.Marshal(enclave.SignedCatalog{Catalog: catalog, Signature: "00"})
	require.NoError(t, err)
	require.Equal(t, string(jqCanonical(t, reply)), string(body))
}

func TestSignCatalog(t *testing.T) {
	t.Parallel()
	id, err := enclave.NewIdentity()
	require.NoError(t, err)
	catalog := demoCatalog()
	msg, err := catalog.Message()
	require.NoError(t, err)
	sig, err := id.SignCatalog(catalog)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(id.PublicKey(), msg, sig))
	for i := range msg {
		tampered := append([]byte(nil), msg...)
		tampered[i] ^= 1
		require.False(t, ed25519.Verify(id.PublicKey(), tampered, sig), "byte %d changed and the signature still verified", i)
	}
}

// The served catalog carries the content, the enclave key and a signature a client rebuilds from the reply alone.
func TestCatalogEndpoint(t *testing.T) {
	t.Parallel()
	id, err := enclave.NewIdentity()
	require.NoError(t, err)
	content := demoContent()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/catalog", enclave.CatalogHandler(id, content, func() string { return "FeePayerAddress" }))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/v1/catalog", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var raw json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&raw))

	var got enclave.SignedCatalog
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, id.PublicKeyHex(), got.Pubkey)
	require.InDelta(t, time.Now().Unix(), got.IssuedAt, 5)
	require.Equal(t, content, got.Catalog.Catalog)
	require.Equal(t, "FeePayerAddress", got.FeePayer, "the sponsor's key is signed next to the treasury")

	sig, err := hex.DecodeString(got.Signature)
	require.NoError(t, err)
	msg := append([]byte(catalogTag+"\x00"), jqCanonical(t, raw)...)
	require.True(t, ed25519.Verify(id.PublicKey(), msg, sig), "the reply minus its signature, canonicalized, is the preimage")
}
