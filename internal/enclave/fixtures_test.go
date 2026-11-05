package enclave_test

// Structural pins over the golden testdata bundle; DCAP stays a live check. The bundle is a v1 capture (pubkey in
// [0:32]) and its pins say so.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TDX v4 quote offsets (TD10 body at 48), shared with scripts/verify-gateway.sh.
const (
	mrTDOffset       = 184
	rtmr3Offset      = 520
	reportDataOffset = 568
	reportDataLen    = 64
	measurementLen   = 48
)

type quoteFixture struct {
	Quote   string `json:"quote"`
	Pubkey  string `json:"pubkey"`
	BlockID string `json:"block_id"` // v2 bundles only
}

type verdictFixture struct {
	Result struct {
		OK     bool `json:"ok"`
		Status struct {
			QuoteVerified bool `json:"quote_verified"`
			DebugDisabled bool `json:"debug_disabled"`
		} `json:"status"`
		Quote struct {
			Version    int    `json:"version"`
			MRTD       string `json:"mr_td"`
			RTMR3      string `json:"rtmr3"`
			ReportData string `json:"report_data"`
			TCBStatus  string `json:"tcb_status"`
			FMSPC      string `json:"fmspc"`
		} `json:"quote"`
	} `json:"result"`
}

type metaFixture struct {
	Pubkey       string `json:"pubkey"`
	MRTD         string `json:"mr_td"`
	RTMR3        string `json:"rtmr3"`
	BlockID      string `json:"block_id"`
	FMSPC        string `json:"fmspc"`
	TCBStatus    string `json:"tcb_status"`
	QuoteVersion int    `json:"quote_version"`
	QuoteSHA256  string `json:"quote_sha256"`
}

// attestationBundle is the golden v1 capture under testdata.
const attestationBundle = "attestation"

func readFixtureBytes(t *testing.T, bundle, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", bundle, name))
	require.NoError(t, err)
	return raw
}

func readFixture(t *testing.T, bundle, name string, v any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(readFixtureBytes(t, bundle, name), v))
}

func readQuoteFixture(t *testing.T, bundle string) (quoteFixture, []byte) {
	t.Helper()
	var q quoteFixture
	readFixture(t, bundle, "quote.json", &q)
	quote, err := base64.StdEncoding.DecodeString(q.Quote)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(quote), reportDataOffset+reportDataLen)
	return q, quote
}

// The golden bundle is a v1 capture (pubkey in [0:32], zeros in [32:64]); a v2 refresh updates these pins too.
func TestFixtureV1ReportDataBindsPubkey(t *testing.T) {
	t.Parallel()
	q, quote := readQuoteFixture(t, attestationBundle)

	require.Equal(t, q.Pubkey, hex.EncodeToString(quote[reportDataOffset:reportDataOffset+ed25519.PublicKeySize]))
	zeros := make([]byte, reportDataLen-ed25519.PublicKeySize)
	require.Equal(t, zeros, quote[reportDataOffset+ed25519.PublicKeySize:reportDataOffset+reportDataLen])
}

// quote.hex is the form the verify script hands to the DCAP verifier; pin it to the canonical base64.
func TestFixtureQuoteHexMatchesJSON(t *testing.T) {
	t.Parallel()
	_, quote := readQuoteFixture(t, attestationBundle)
	hexQuote := strings.TrimSpace(string(readFixtureBytes(t, attestationBundle, "quote.hex")))
	require.Equal(t, hex.EncodeToString(quote), hexQuote)
}

// Pin verdict.json and meta.json to the quote bytes so a partial re-capture cannot ship an incoherent bundle.
func TestFixtureBundleIsOneCaptureRun(t *testing.T) {
	t.Parallel()
	q, quote := readQuoteFixture(t, attestationBundle)
	var v verdictFixture
	var m metaFixture
	readFixture(t, attestationBundle, "verdict.json", &v)
	readFixture(t, attestationBundle, "meta.json", &m)

	mrTD := hex.EncodeToString(quote[mrTDOffset : mrTDOffset+measurementLen])
	rtmr3 := hex.EncodeToString(quote[rtmr3Offset : rtmr3Offset+measurementLen])

	require.Equal(t, q.Pubkey+strings.Repeat("00", reportDataLen-ed25519.PublicKeySize), v.Result.Quote.ReportData,
		"golden bundle is a v1 capture; a refresh from a v2 identity flips the report_data halves")
	require.Equal(t, mrTD, v.Result.Quote.MRTD)
	require.Equal(t, rtmr3, v.Result.Quote.RTMR3)

	require.Equal(t, q.Pubkey, m.Pubkey)
	require.Equal(t, mrTD, m.MRTD)
	require.Equal(t, rtmr3, m.RTMR3)
}
