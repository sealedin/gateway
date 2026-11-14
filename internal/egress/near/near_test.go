package near_test

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/egress/near"
	"github.com/sealedin/gateway/internal/egress/upstream"
	"github.com/sealedin/gateway/internal/teeverify/tdx"
)

const (
	recordedAppID   = "f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae"
	recordedCompose = "2643bc7ae47ecf4cf84509a647d2c2cc3bcacad95a87b8a73d543e6c48ad3b22"
	otherHash       = "00000000000000000000000000000000000000000000000000000000000000aa"
	signer          = "b98a789cdc4817275f5155593ba73ef2a957e779"
	dstackEvent     = 0x08000001
)

// keyProvider is the key-provider event of the recorded guest: hex of {"name":"kms","id":"<the KMS root key>"}.
func keyProvider() string {
	return hex.EncodeToString([]byte(`{"name":"kms","id":"3059301306072a8648ce3d020106082a8648ce3d03010703420004394aaed2` +
		`c745e6a457cb835f7f47423f57ff3ead71b92abff6bdc14d905b319f2e13961b42c50740dae4498d9c51dd7a2e227660c9e5c504083cda06b6c11682"}`))
}

func recordedPolicy() near.Policy {
	return near.Policy{
		API: "https://cloud-api.near.ai",
		Guests: []near.Guest{{
			MRTD:  "7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
			RTMR0: "d090162bff4b1d1dc74dc59dc548838efc4b811b173da8536efa8e2a9c045da70ee092301293ad90afebee448bcd0211",
			RTMR1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
			RTMR2: "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
		}},
		TDAttributes: "0000001000000000",
		XFAM:         "e702060000000000",
		AppIDs:       []string{recordedAppID},
		KeyProviders: []string{keyProvider()},
	}
}

// parseOnly stands in for DCAP: the recorded quote's collateral is not recorded, and tdx tests cover that step.
type parseOnly struct{}

func (parseOnly) Verify(_ context.Context, raw []byte) (*tdx.Report, error) { return tdx.Parse(raw) }

type recorded struct {
	Nonce    string          `json:"nonce"`
	PeerSPKI string          `json:"peer_spki_sha256"`
	Report   json.RawMessage `json:"report"`
}

func loadRecorded(t *testing.T) (recorded, [near.NonceSize]byte, [sha256.Size]byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/gateway-report.json")
	require.NoError(t, err)
	var rec recorded
	require.NoError(t, json.Unmarshal(raw, &rec))
	var nonce [near.NonceSize]byte
	var spki [sha256.Size]byte
	_, err = hex.Decode(nonce[:], []byte(rec.Nonce))
	require.NoError(t, err)
	_, err = hex.Decode(spki[:], []byte(rec.PeerSPKI))
	require.NoError(t, err)
	return rec, nonce, spki
}

func TestVerifyAcceptsTheRecordedGatewayReport(t *testing.T) {
	rec, nonce, spki := loadRecorded(t)
	verifier := &near.Verifier{TDX: parseOnly{}, Policy: recordedPolicy()}

	verified, err := verifier.Verify(t.Context(), rec.Report, nonce, spki)

	require.NoError(t, err)
	assert.Equal(t, &near.Verified{AppID: recordedAppID, ComposeHash: recordedCompose}, verified)
}

func TestVerifyRefusals(t *testing.T) {
	rec, nonce, spki := loadRecorded(t)
	flipped := func(in [32]byte) [32]byte { in[0] ^= 1; return in }
	cases := map[string]struct {
		policy func(*near.Policy)
		report func(string) string
		nonce  [near.NonceSize]byte
		spki   [sha256.Size]byte
		check  string
	}{
		"another nonce":          {nonce: flipped(nonce), spki: spki, check: "nonce"},
		"another connection key": {nonce: nonce, spki: flipped(spki), check: "tls_key_binding"},
		"a guest that is not pinned": {nonce: nonce, spki: spki, check: "guest",
			policy: func(p *near.Policy) { p.Guests[0].RTMR2 = p.Guests[0].RTMR1 }},
		"an event payload rewritten under its digest": {nonce: nonce, spki: spki, check: "event_log",
			report: func(r string) string { return strings.ReplaceAll(r, recordedAppID, strings.Repeat("ab", 20)) }},
		"another app": {nonce: nonce, spki: spki, check: "app_id",
			policy: func(p *near.Policy) { p.AppIDs = []string{strings.Repeat("ab", 20)} }},
		"another key provider": {nonce: nonce, spki: spki, check: "key_provider",
			policy: func(p *near.Policy) { p.KeyProviders = []string{"00"} }},
		"a build outside the allowlist": {nonce: nonce, spki: spki, check: "compose_hash",
			policy: func(p *near.Policy) { p.ComposeHashes = []string{otherHash} }},
		"a quote that is not one": {nonce: nonce, spki: spki, check: "dcap",
			report: func(r string) string { return strings.Replace(r, `"intel_quote": "04`, `"intel_quote": "05`, 1) }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			policy, report := recordedPolicy(), string(rec.Report)
			if tc.policy != nil {
				tc.policy(&policy)
			}
			if tc.report != nil {
				report = tc.report(report)
				require.NotEqual(t, string(rec.Report), report, "the tampering must change the report")
			}
			verifier := &near.Verifier{TDX: parseOnly{}, Policy: policy}

			_, err := verifier.Verify(t.Context(), []byte(report), tc.nonce, tc.spki)

			failure, isCheck := errors.AsType[*near.CheckError](err)
			require.True(t, isCheck, "got %v", err)
			assert.Equal(t, tc.check, failure.Check)
		})
	}
}

func TestVerifyAcceptsAnAllowlistedBuild(t *testing.T) {
	rec, nonce, spki := loadRecorded(t)
	policy := recordedPolicy()
	policy.ComposeHashes = []string{otherHash, recordedCompose}

	_, err := (&near.Verifier{TDX: parseOnly{}, Policy: policy}).Verify(t.Context(), rec.Report, nonce, spki)

	require.NoError(t, err)
}

func TestPolicyValidate(t *testing.T) {
	require.NoError(t, recordedPolicy().Validate())
	for name, breakIt := range map[string]func(*near.Policy){
		"plain http origin": func(p *near.Policy) { p.API = "http://cloud-api.near.ai" },
		"origin with path":  func(p *near.Policy) { p.API += "/v1" },
		"no guest":          func(p *near.Policy) { p.Guests = nil },
		"no app id":         func(p *near.Policy) { p.AppIDs = nil },
		"no key provider":   func(p *near.Policy) { p.KeyProviders = nil },
		"short measurement": func(p *near.Policy) { p.Guests[0].MRTD = "7fe6" },
		"short compose":     func(p *near.Policy) { p.ComposeHashes = []string{"26"} },
	} {
		t.Run(name, func(t *testing.T) {
			policy := recordedPolicy()
			breakIt(&policy)
			require.Error(t, policy.Validate())
		})
	}
}

// fakeGateway plays the provider: it answers the report request with evidence bound to the key it presents (or, as a
// man in the middle would have to, to another key) and counts what reached it.
type fakeGateway struct {
	server      *httptest.Server
	boundToPeer atomic.Bool
	reports     atomic.Int32
	chats       atomic.Int32
	keyOnReport atomic.Bool
	chat        http.HandlerFunc
}

// The fake quote is REPORT_DATA alone; fakeDCAP expands it into the report a genuine quote of this guest would carry.
type fakeDCAP struct{ log string }

func (f fakeDCAP) Verify(_ context.Context, raw []byte) (*tdx.Report, error) {
	policy := recordedPolicy()
	report := &tdx.Report{}
	for dst, src := range map[*[tdx.MeasurementSize]byte]string{&report.MRTD: policy.Guests[0].MRTD,
		&report.RTMR[0]: policy.Guests[0].RTMR0, &report.RTMR[1]: policy.Guests[0].RTMR1, &report.RTMR[2]: policy.Guests[0].RTMR2} {
		if _, err := hex.Decode(dst[:], []byte(src)); err != nil {
			return nil, err
		}
	}
	_, _ = hex.Decode(report.TDAttributes[:], []byte(policy.TDAttributes))
	_, _ = hex.Decode(report.XFAM[:], []byte(policy.XFAM))
	report.MRConfigID[0] = 1
	_, _ = hex.Decode(report.MRConfigID[1:], []byte(recordedCompose))
	copy(report.ReportData[:], raw)
	report.RTMR[3] = fold(f.log)
	return report, nil
}

func eventLog() string {
	type entry struct {
		IMR     int    `json:"imr"`
		Type    uint32 `json:"event_type"`
		Event   string `json:"event"`
		Payload string `json:"event_payload"`
	}
	raw, _ := json.Marshal([]entry{ //nolint:errchkjson // plain strings and integers
		{IMR: 0, Type: 1, Event: "", Payload: "00"},
		{IMR: 3, Type: dstackEvent, Event: "app-id", Payload: recordedAppID},
		{IMR: 3, Type: dstackEvent, Event: "compose-hash", Payload: recordedCompose},
		{IMR: 3, Type: dstackEvent, Event: "key-provider", Payload: keyProvider()},
		{IMR: 3, Type: dstackEvent, Event: "system-ready", Payload: ""},
	})
	return string(raw)
}

// fold is the test's own replay of the RTMR3 events of a log.
func fold(log string) [tdx.MeasurementSize]byte {
	var entries []struct {
		IMR     int    `json:"imr"`
		Type    uint32 `json:"event_type"`
		Event   string `json:"event"`
		Payload string `json:"event_payload"`
	}
	_ = json.Unmarshal([]byte(log), &entries)
	var register [tdx.MeasurementSize]byte
	for _, e := range entries {
		if e.IMR != 3 {
			continue
		}
		payload, _ := hex.DecodeString(e.Payload)
		typeLE := binary.LittleEndian.AppendUint32(nil, e.Type)
		digest := sha512.Sum384([]byte(string(typeLE) + ":" + e.Event + ":" + string(payload)))
		register = sha512.Sum384(append(register[:], digest[:]...))
	}
	return register
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{}
	g.boundToPeer.Store(true)
	g.chat = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[],"usage":{"completion_tokens":7}}`)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/attestation/report", func(w http.ResponseWriter, r *http.Request) {
		g.reports.Add(1)
		if r.Header.Get("Authorization") != "" {
			g.keyOnReport.Store(true)
		}
		spki := sha256.Sum256(g.server.Certificate().RawSubjectPublicKeyInfo)
		if !g.boundToPeer.Load() {
			spki[0] ^= 1
		}
		address, _ := hex.DecodeString(signer)
		bound := sha256.Sum256(append(address, spki[:]...))
		_ = json.NewEncoder(w).Encode(map[string]any{"gateway_attestation": map[string]string{
			"signing_address": "0x" + signer, "event_log": eventLog(),
			"intel_quote": hex.EncodeToString(bound[:]) + r.URL.Query().Get("nonce")}})
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		g.chats.Add(1)
		g.chat(w, r)
	})
	g.server = httptest.NewTLSServer(mux)
	t.Cleanup(g.server.Close)
	return g
}

func (g *fakeGateway) provider(t *testing.T, now func() time.Time) *near.Provider {
	t.Helper()
	policy := recordedPolicy()
	policy.API = g.server.URL
	roots := x509.NewCertPool()
	roots.AddCert(g.server.Certificate())
	provider, err := near.NewProvider(near.Options{APIKey: "test-key", Timeout: 10 * time.Second, Lifetime: 15 * time.Minute,
		Verifier: &near.Verifier{TDX: fakeDCAP{log: eventLog()}, Policy: policy}, Roots: roots,
		Log: slog.New(slog.DiscardHandler), Now: now})
	require.NoError(t, err)
	return provider
}

func invoke(t *testing.T, p *near.Provider, stream bool) (string, *upstream.Call, error) {
	t.Helper()
	call := &upstream.Call{}
	reply, err := p.Invoke(t.Context(), "Qwen/Qwen3.8-27B", "/v1/chat/completions", stream, []byte(`{"model":"m"}`), call)
	if err != nil {
		return "", call, err
	}
	defer func() { _ = reply.Body.Close() }()
	body, readErr := io.ReadAll(reply.Body)
	require.NoError(t, readErr)
	return string(body), call, nil
}

func TestInvokeAttestsTheConnectionItSendsOn(t *testing.T) {
	gateway := newFakeGateway(t)
	var sawKey, sawNoAliasing atomic.Bool
	gateway.chat = func(w http.ResponseWriter, r *http.Request) {
		sawKey.Store(r.Header.Get("Authorization") == "Bearer test-key")
		sawNoAliasing.Store(r.Header.Get("X-No-Aliasing") == "true")
		_, _ = io.WriteString(w, `{"choices":[],"usage":{"completion_tokens":7}}`)
	}
	provider := gateway.provider(t, nil)

	body, call, err := invoke(t, provider, false)
	require.NoError(t, err)
	_, _, err = invoke(t, provider, false)
	require.NoError(t, err)

	assert.JSONEq(t, `{"choices":[],"usage":{"completion_tokens":7}}`, body)
	require.NotNil(t, call.CompletionTokens)
	assert.Equal(t, 7, *call.CompletionTokens)
	assert.True(t, sawKey.Load(), "the API key goes with the request")
	assert.True(t, sawNoAliasing.Load())
	assert.False(t, gateway.keyOnReport.Load(), "no credential crosses a connection before it is verified")
	assert.Equal(t, int32(1), gateway.reports.Load(), "the second call reuses the attested connection")
}

func TestInvokeSendsNothingOverAConnectionBoundToAnotherKey(t *testing.T) {
	gateway := newFakeGateway(t)
	gateway.boundToPeer.Store(false)

	_, _, err := invoke(t, gateway.provider(t, nil), false)

	require.ErrorIs(t, err, upstream.ErrNoAttestedInstance)
	assert.Equal(t, int32(0), gateway.chats.Load())
}

func TestInvokeAttestsAgainOnceTheLifetimeIsOver(t *testing.T) {
	gateway := newFakeGateway(t)
	var clock atomic.Int64
	start := time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)
	provider := gateway.provider(t, func() time.Time { return start.Add(time.Duration(clock.Load())) })

	_, _, err := invoke(t, provider, false)
	require.NoError(t, err)
	clock.Store(int64(16 * time.Minute))
	_, _, err = invoke(t, provider, false)
	require.NoError(t, err)

	assert.Equal(t, int32(2), gateway.reports.Load())
}

func TestInvokeRelaysAStreamAndWithholdsARefusal(t *testing.T) {
	gateway := newFakeGateway(t)
	provider := gateway.provider(t, nil)
	gateway.chat = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"x\":1}\n\ndata: [DONE]\n\n")
	}

	body, _, err := invoke(t, provider, true)

	require.NoError(t, err)
	assert.Equal(t, "data: {\"x\":1}\n\ndata: [DONE]\n\n", body)

	gateway.chat = func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "your prompt was: secret", http.StatusTooManyRequests)
	}

	_, _, err = invoke(t, provider, false)

	refusal, isRefusal := errors.AsType[*upstream.Error](err)
	require.True(t, isRefusal, "got %v", err)
	assert.Equal(t, http.StatusTooManyRequests, refusal.Status)
	assert.NotContains(t, refusal.Detail, "secret")
}
