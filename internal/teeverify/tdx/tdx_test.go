package tdx_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/teeverify/tdx"
	"github.com/sealedin/gateway/internal/teeverify/tdx/tdxtest"
)

// fixtureDir holds the Chutes evidence captured on 2026-10-27 (see meta.json there).
func fixtureDir() string { return filepath.Join("..", "testdata", "chutes") }

// captureTime pins collateral currency checks inside the fixture's validity window.
func captureTime() time.Time { return time.Date(2026, time.October, 27, 13, 20, 0, 0, time.UTC) }

type sample struct {
	ReportData0_32 string `json:"report_data_0_32"`
	Nonce          string `json:"nonce"`
}

type meta struct {
	Samples    map[string]sample `json:"samples"`
	Collateral map[string]string `json:"collateral"`
}

func loadMeta(t *testing.T) meta {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir(), "meta.json"))
	require.NoError(t, err)
	var m meta
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func loadQuote(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir(), name+".json"))
	require.NoError(t, err)
	var f struct {
		Evidence struct {
			Quote string `json:"quote"`
		} `json:"evidence"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	quote, err := base64.StdEncoding.DecodeString(f.Evidence.Quote)
	require.NoError(t, err)
	return quote
}

func fixtureVerifier(t *testing.T) tdx.Verifier {
	t.Helper()
	files := map[string]string{}
	for url, name := range loadMeta(t).Collateral {
		files[url] = filepath.Join(fixtureDir(), "collateral", name)
	}
	return tdx.Verifier{Getter: tdxtest.CollateralFiles(files), Now: captureTime}
}

func TestVerifyFixtureQuotes(t *testing.T) {
	m := loadMeta(t)
	for _, name := range []string{"blackwell", "hopper"} {
		t.Run(name, func(t *testing.T) {
			report, err := fixtureVerifier(t).Verify(context.Background(), loadQuote(t, name))
			require.NoError(t, err)
			require.Equal(t, m.Samples[name].ReportData0_32, hex.EncodeToString(report.ReportData[:32]))
			require.False(t, report.Debug())
			require.NotEqual(t, [48]byte{}, report.MRTD)
			for i := range report.RTMR {
				require.NotEqual(t, [48]byte{}, report.RTMR[i], "rtmr%d", i)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	quote := loadQuote(t, "blackwell")
	tamper := func(offset int) []byte {
		q := append([]byte(nil), quote...)
		q[offset] ^= 0x01
		return q
	}
	expired := fixtureVerifier(t)
	expired.Now = func() time.Time { return captureTime().AddDate(2, 0, 0) }
	tests := []struct {
		name     string
		quote    []byte
		verifier tdx.Verifier
		wantErr  string
	}{
		{"flipped report_data bit", tamper(48 + 520), fixtureVerifier(t), "signature"},
		{"flipped signature bit", tamper(48 + 584 + 4), fixtureVerifier(t), "signature"},
		{"truncated quote", quote[:600], fixtureVerifier(t), "quote"},
		{"collateral expired", quote, expired, "collateral"},
		{"collateral unavailable", quote, tdx.Verifier{Getter: tdxtest.CollateralFiles(nil), Now: captureTime}, "collateral"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.verifier.Verify(context.Background(), tt.quote)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestVerifierRequiresGetter(t *testing.T) {
	_, err := tdx.Verifier{}.Verify(context.Background(), loadQuote(t, "blackwell"))
	require.ErrorIs(t, err, tdx.ErrNoCollateralSource)
}

func TestParseReportsDebugBit(t *testing.T) {
	quote := loadQuote(t, "blackwell")
	report, err := tdx.Parse(quote)
	require.NoError(t, err)
	require.False(t, report.Debug())

	quote[48+120] |= 0x01 // TD_ATTRIBUTES bit 0: DEBUG
	report, err = tdx.Parse(quote)
	require.NoError(t, err)
	require.True(t, report.Debug())
	_, err = fixtureVerifier(t).Verify(context.Background(), quote)
	require.Error(t, err, "a debug TD must not verify, whatever else the quote says")
}

func TestPolicyCheck(t *testing.T) {
	report, err := tdx.Parse(loadQuote(t, "blackwell"))
	require.NoError(t, err)
	hexOf := func(b [48]byte) string { return hex.EncodeToString(b[:]) }
	other := hexOf([48]byte{1})
	good := tdx.Policy{
		MRTD:  []string{other, hexOf(report.MRTD)},
		RTMR0: []string{hexOf(report.RTMR[0]), other},
		Images: []tdx.Image{
			{RTMR1: other, RTMR2: other, RTMR3: other},
			{RTMR1: hexOf(report.RTMR[1]), RTMR2: hexOf(report.RTMR[2]), RTMR3: hexOf(report.RTMR[3])},
		},
		TDAttributes:  hex.EncodeToString(report.TDAttributes[:]),
		XFAM:          hex.EncodeToString(report.XFAM[:]),
		MRConfigID:    hex.EncodeToString(report.MRConfigID[:]),
		MROwner:       hex.EncodeToString(report.MROwner[:]),
		MROwnerConfig: hex.EncodeToString(report.MROwnerConfig[:]),
	}
	tests := []struct {
		name    string
		mutate  func(p *tdx.Policy)
		wantErr string
	}{
		{"pinned", func(*tdx.Policy) {}, ""},
		{"mrtd unpinned", func(p *tdx.Policy) { p.MRTD = []string{other} }, "mrtd"},
		{"rtmr0 unpinned", func(p *tdx.Policy) { p.RTMR0 = []string{other} }, "rtmr0"},
		{"image rtmr3 differs", func(p *tdx.Policy) { p.Images[1].RTMR3 = other }, "rtmr1-3"},
		{"td attributes differ", func(p *tdx.Policy) { p.TDAttributes = "0000000000000000" }, "td_attributes"},
		{"xfam differs", func(p *tdx.Policy) { p.XFAM = "0000000000000000" }, "xfam"},
		{"mrowner differs", func(p *tdx.Policy) { p.MROwner = other }, "mrowner"},
		{"empty policy", func(p *tdx.Policy) { *p = tdx.Policy{} }, "mrtd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tdx.Policy{MRTD: append([]string(nil), good.MRTD...), RTMR0: append([]string(nil), good.RTMR0...),
				Images: append([]tdx.Image(nil), good.Images...), TDAttributes: good.TDAttributes, XFAM: good.XFAM,
				MRConfigID: good.MRConfigID, MROwner: good.MROwner, MROwnerConfig: good.MROwnerConfig}
			tt.mutate(&p)
			checkErr := p.Check(report)
			if tt.wantErr == "" {
				require.NoError(t, checkErr)
				return
			}
			require.ErrorIs(t, checkErr, tdx.ErrUnpinnedMeasurement)
			require.ErrorContains(t, checkErr, tt.wantErr)
		})
	}
}

func TestPolicyValidateRejectsMalformedHex(t *testing.T) {
	tests := []struct {
		name   string
		policy tdx.Policy
	}{
		{"short mrtd", tdx.Policy{MRTD: []string{"abcd"}, RTMR0: []string{hex.EncodeToString(make([]byte, 48))},
			Images: []tdx.Image{{RTMR1: hex.EncodeToString(make([]byte, 48)), RTMR2: hex.EncodeToString(make([]byte, 48)),
				RTMR3: hex.EncodeToString(make([]byte, 48))}}}},
		{"no images", tdx.Policy{MRTD: []string{hex.EncodeToString(make([]byte, 48))},
			RTMR0: []string{hex.EncodeToString(make([]byte, 48))}}},
		{"non-hex rtmr2", tdx.Policy{MRTD: []string{hex.EncodeToString(make([]byte, 48))},
			RTMR0:  []string{hex.EncodeToString(make([]byte, 48))},
			Images: []tdx.Image{{RTMR1: hex.EncodeToString(make([]byte, 48)), RTMR2: "zz", RTMR3: hex.EncodeToString(make([]byte, 48))}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Error(t, tt.policy.Validate())
		})
	}
}

func TestHTTPGetter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Tcb-Info-Issuer-Chain", "chain")
			_, _ = w.Write([]byte("body"))
		case "/huge":
			_, _ = w.Write([]byte(strings.Repeat("x", 4<<20+1)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	g := tdx.HTTPGetter(srv.Client())
	headers, body, err := g.Get(srv.URL + "/ok")
	require.NoError(t, err)
	require.Equal(t, "body", string(body))
	require.Equal(t, []string{"chain"}, headers["Tcb-Info-Issuer-Chain"])
	_, _, err = g.Get(srv.URL + "/missing")
	require.ErrorContains(t, err, "HTTP 404")
	_, _, err = g.Get(srv.URL + "/huge")
	require.ErrorContains(t, err, "exceeds")
}
