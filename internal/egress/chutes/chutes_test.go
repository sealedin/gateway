package chutes_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/sealedin/gateway/internal/egress/chutes"
	"github.com/sealedin/gateway/internal/egress/upstream"
	"github.com/sealedin/gateway/internal/teeverify/nvidia"
	"github.com/sealedin/gateway/internal/teeverify/tdx"
	"github.com/sealedin/gateway/internal/teeverify/tdx/tdxtest"
)

func fixtureDir() string { return filepath.Join("..", "..", "teeverify", "testdata", "chutes") }

func captureTime() time.Time { return time.Date(2026, time.October, 27, 13, 20, 0, 0, time.UTC) }

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{fixtureDir()}, parts...)...))
	require.NoError(t, err)
	return raw
}

type fixture struct {
	Nonce     string          `json:"nonce"`
	ChuteID   string          `json:"chute_id"`
	E2EPubkey string          `json:"e2e_pubkey"`
	Evidence  chutes.Evidence `json:"evidence"`
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	var f fixture
	require.NoError(t, json.Unmarshal(readFixture(t, name+".json"), &f))
	return f
}

type meta struct {
	Samples map[string]struct {
		ReportData string `json:"report_data_0_32"`
		IssuedAt   int64  `json:"nras_iat"`
	} `json:"samples"`
	Collateral map[string]string `json:"collateral"`
}

func loadMeta(t *testing.T) meta {
	t.Helper()
	var m meta
	require.NoError(t, json.Unmarshal(readFixture(t, "meta.json"), &m))
	return m
}

// sampleNonce is the GPU nonce of a recorded sample: its quote's REPORT_DATA[0:32].
func sampleNonce(t *testing.T, name string) [32]byte {
	t.Helper()
	var nonce [32]byte
	n, err := hex.DecodeString(loadMeta(t).Samples[name].ReportData)
	require.NoError(t, err)
	copy(nonce[:], n)
	return nonce
}

func measuredPolicy(t *testing.T) chutes.Policy {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "egress", "policy.yaml"))
	require.NoError(t, err)
	var p chutes.Policy
	require.NoError(t, yaml.Unmarshal(raw, &p))
	return p
}

// nrasStub answers every attestation with the recorded verdict for name.
func nrasStub(t *testing.T, name string, status *atomic.Int32) *nvidia.NRAS {
	t.Helper()
	verdict := readFixture(t, "nras", name+".json")
	jwks := readFixture(t, "jwks.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			_, _ = w.Write(jwks)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write(verdict)
	}))
	t.Cleanup(srv.Close)
	n := nvidia.NewNRAS(srv.URL+"/attest", srv.URL+"/jwks", srv.Client())
	issuedAt := loadMeta(t).Samples[name].IssuedAt
	n.Now = func() time.Time { return time.Unix(issuedAt, 0).Add(time.Minute) }
	return n
}

func fixtureVerifier(t *testing.T, name string, status *atomic.Int32) *chutes.Verifier {
	t.Helper()
	files := map[string]string{}
	for u, f := range loadMeta(t).Collateral {
		files[u] = filepath.Join(fixtureDir(), "collateral", f)
	}
	return &chutes.Verifier{
		TDX:    tdx.Verifier{Getter: tdxtest.CollateralFiles(files), Now: captureTime},
		NRAS:   nrasStub(t, name, status),
		Policy: measuredPolicy(t),
		Now:    captureTime,
	}
}

// The recorded evidence lacks the E2EE keys, so reaching exactly the key-binding error proves every earlier check.
func TestVerifyFixturesPassUpToKeyBinding(t *testing.T) {
	for _, name := range []string{"blackwell", "hopper"} {
		t.Run(name, func(t *testing.T) {
			var ok atomic.Int32
			ok.Store(http.StatusOK)
			f := loadFixture(t, name)
			_, err := fixtureVerifier(t, name, &ok).Verify(context.Background(), f.Evidence, f.Nonce, "unknown-key")
			require.ErrorIs(t, err, chutes.ErrBinding)
			require.ErrorContains(t, err, "REPORT_DATA[0:32]")
		})
	}
}

func resign(t *testing.T, ev chutes.Evidence) chutes.Evidence {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "impostor"},
		NotBefore: captureTime().Add(-time.Hour), NotAfter: captureTime().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	body, err := base64.StdEncoding.DecodeString(ev.AttestedBody)
	require.NoError(t, err)
	digest := sha256.Sum256(body)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	ev.Certificate = base64.StdEncoding.EncodeToString(der)
	ev.Signature = base64.StdEncoding.EncodeToString(sig)
	return ev
}

// The GPU step runs after the E2EE key binding the fixtures cannot satisfy, so it is exercised on its own.
func TestCheckGPUsFixtures(t *testing.T) {
	for _, name := range []string{"blackwell", "hopper"} {
		t.Run(name, func(t *testing.T) {
			var ok atomic.Int32
			ok.Store(http.StatusOK)
			verdict, err := fixtureVerifier(t, name, &ok).CheckGPUs(context.Background(), loadFixture(t, name).Evidence,
				sampleNonce(t, name))
			require.NoError(t, err)
			require.True(t, verdict.Overall)
		})
	}
}

func flipB64(t *testing.T, s string, offset int) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	b[offset] ^= 0x01
	return base64.StdEncoding.EncodeToString(b)
}

func TestVerifyRejects(t *testing.T) {
	f := loadFixture(t, "blackwell")
	good := f.Evidence
	otherQuote := loadFixture(t, "hopper").Evidence.Quote
	// Mutations are prepared here, on the test goroutine, so no subtest asserts through the parent's t.
	flippedSig, editedBody, tamperedQuote := flipB64(t, good.Signature, 10), flipB64(t, good.AttestedBody, 30), flipB64(t, good.Quote, 48+520)
	impostor := resign(t, good)
	tests := []struct {
		name    string
		mutate  func(ev *chutes.Evidence)
		nonce   string
		policy  func(p *chutes.Policy)
		wantErr string
	}{
		{"nonce mismatch", func(*chutes.Evidence) {}, strings.Repeat("00", 32), nil, "attested_body nonce"},
		{"signature flipped", func(ev *chutes.Evidence) { ev.Signature = flippedSig }, f.Nonce, nil, "signature"},
		{"attested body edited", func(ev *chutes.Evidence) { ev.AttestedBody = editedBody }, f.Nonce, nil, "signature"},
		{"quote swapped", func(ev *chutes.Evidence) { ev.Quote = otherQuote }, f.Nonce, nil, "quote differs"},
		{"quote tampered", func(ev *chutes.Evidence) { ev.Quote = tamperedQuote }, f.Nonce, nil, "quote differs"},
		{"impostor certificate", func(ev *chutes.Evidence) { *ev = impostor }, f.Nonce, nil, "REPORT_DATA[32:64]"},
		{"unpinned measurement", func(*chutes.Evidence) {}, f.Nonce,
			func(p *chutes.Policy) { p.TDX.MRTD = []string{strings.Repeat("00", 48)} }, "mrtd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var status atomic.Int32
			status.Store(http.StatusOK)
			v := fixtureVerifier(t, "blackwell", &status)
			if tt.policy != nil {
				tt.policy(&v.Policy)
			}
			ev := good
			tt.mutate(&ev)
			_, err := v.Verify(context.Background(), ev, tt.nonce, "unknown-key")
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestCheckGPUsRejects(t *testing.T) {
	f := loadFixture(t, "blackwell")
	nonce := sampleNonce(t, "blackwell")
	tamperedGPU := flipB64(t, f.Evidence.GPUEvidence[0].Evidence, 100)
	tests := []struct {
		name    string
		mutate  func(ev *chutes.Evidence)
		policy  func(p *chutes.Policy)
		nras    int32
		wantErr string
	}{
		{"gpu evidence tampered", func(ev *chutes.Evidence) { ev.GPUEvidence[0].Evidence = tamperedGPU }, nil,
			http.StatusOK, "gpu 0"},
		{"gpu arch not allowed", func(*chutes.Evidence) {},
			func(p *chutes.Policy) { p.GPU.Archs = []string{"HOPPER"} }, http.StatusOK, "arch"},
		{"gpu mode not allowed", func(*chutes.Evidence) {},
			func(p *chutes.Policy) { p.GPU.Modes = []nvidia.Mode{nvidia.ModePPCIE} }, http.StatusOK, "mode"},
		{"no gpu evidence", func(ev *chutes.Evidence) { ev.GPUEvidence = nil }, nil, http.StatusOK, "no GPU"},
		{"nras unavailable", func(*chutes.Evidence) {}, nil, http.StatusBadGateway, "NRAS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var status atomic.Int32
			status.Store(tt.nras)
			v := fixtureVerifier(t, "blackwell", &status)
			if tt.policy != nil {
				tt.policy(&v.Policy)
			}
			ev := f.Evidence
			ev.GPUEvidence = append([]nvidia.Evidence(nil), f.Evidence.GPUEvidence...)
			tt.mutate(&ev)
			_, checkErr := v.CheckGPUs(context.Background(), ev, nonce)
			require.ErrorContains(t, checkErr, tt.wantErr)
		})
	}
}

func TestCatalogResolve(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		assert.Equal(t, "/v1/models", r.URL.Path)
		_, _ = io.WriteString(w, `{"data":[{"id":"org/model-TEE","chute_id":"c1","confidential_compute":true},`+
			`{"id":"org/model","chute_id":"c2","confidential_compute":false},{"id":"org/noid","confidential_compute":true}]}`)
	}))
	defer srv.Close()
	c := chutes.NewCatalog(srv.URL, srv.Client())
	clock := time.Now()
	chutes.SetCatalogClock(c, func() time.Time { return clock })
	ctx := context.Background()

	id, err := c.Resolve(ctx, "org/model-TEE")
	require.NoError(t, err)
	require.Equal(t, "c1", id)
	_, err = c.Resolve(ctx, "org/model")
	require.ErrorIs(t, err, upstream.ErrNotConfidential)
	_, err = c.Resolve(ctx, "org/noid")
	require.ErrorIs(t, err, upstream.ErrUnknownModel)
	_, err = c.Resolve(ctx, "org/missing")
	require.ErrorIs(t, err, upstream.ErrUnknownModel)
	require.Equal(t, int32(1), hits.Load(), "an unknown model does not refetch a fresh catalog")
	clock = clock.Add(time.Minute)
	_, err = c.Resolve(ctx, "org/missing")
	require.ErrorIs(t, err, upstream.ErrUnknownModel)
	require.Equal(t, int32(2), hits.Load(), "an unknown model refetches once the catalog is old enough")
	id, err = c.Resolve(ctx, "org/model-TEE")
	require.NoError(t, err)
	require.Equal(t, "c1", id)
	require.Equal(t, int32(2), hits.Load())
}

type stubVerifier struct {
	accept map[string]bool
	calls  atomic.Int32
	now    func() time.Time
}

func (s *stubVerifier) Verify(_ context.Context, ev chutes.Evidence, _, pubkey string) (*chutes.Verified, error) {
	s.calls.Add(1)
	if !s.accept[ev.InstanceID] {
		return nil, errors.New("stub: rejected")
	}
	return &chutes.Verified{InstanceID: ev.InstanceID, Pubkey: pubkey, VerifiedAt: s.now(), ExpiresAt: s.now().Add(time.Hour)}, nil
}

type fakeAPI struct {
	instances string
	evidence  string
	failInst  bool
	calls     []string
}

func (f *fakeAPI) get(_ context.Context, url, key string) ([]byte, error) {
	f.calls = append(f.calls, url)
	if key != "cpk_test" {
		return nil, errors.New("fake: bad key")
	}
	switch {
	case strings.Contains(url, "/e2e/instances/"):
		if f.failInst {
			return nil, errors.New("fake: instances down")
		}
		return []byte(f.instances), nil
	case strings.Contains(url, "/evidence?nonce="):
		return []byte(f.evidence), nil
	}
	return nil, fmt.Errorf("fake: unexpected %s", url)
}

func TestAttesterTake(t *testing.T) {
	api := &fakeAPI{
		instances: `{"instances":[{"instance_id":"a","e2e_pubkey":"pkA","nonces":["n1","n2"]},` +
			`{"instance_id":"b","e2e_pubkey":"pkB","nonces":["n3"]}],"nonce_expires_in":60}`,
		evidence: `{"evidence":[{"instance_id":"a","quote":"q"},{"instance_id":"b","quote":"q"},{"instance_id":"zombie"}]}`,
	}
	clock := captureTime()
	now := func() time.Time { return clock }
	verifier := &stubVerifier{accept: map[string]bool{"a": true}, now: now}
	att, err := chutes.NewAttester("https://api.test", "cpk_test", http.DefaultClient, verifier, 15*time.Minute,
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	chutes.SetGetter(att, api.get)
	chutes.SetClock(att, now)
	_, err = chutes.NewAttester("https://api.test", "cpk_test", http.DefaultClient, verifier, 0, slog.New(slog.DiscardHandler))
	require.Error(t, err, "a zero interval would never consider an instance current")
	ctx := context.Background()

	first, err := att.Take(ctx, "chute-1")
	require.NoError(t, err)
	require.Equal(t, chutes.Target{ChuteID: "chute-1", InstanceID: "a", Pubkey: "pkA", Nonce: "n1"}, first)
	require.Equal(t, int32(2), verifier.calls.Load(), "both listed instances verified once; the unlisted one never")
	require.Len(t, api.calls, 2)

	second, err := att.Take(ctx, "chute-1")
	require.NoError(t, err)
	require.Equal(t, "n2", second.Nonce, "second nonce from the pool, no API call")
	require.Len(t, api.calls, 2)

	// Pool exhausted: instances and evidence refetched, only the rejected instance is retried; a stays current.
	_, err = att.Take(ctx, "chute-1")
	require.NoError(t, err)
	require.Len(t, api.calls, 4)
	require.Equal(t, int32(3), verifier.calls.Load())

	// A rotated E2EE key on a verified instance forces re-attestation of that instance.
	api.instances = `{"instances":[{"instance_id":"a","e2e_pubkey":"pkA2","nonces":["n9"]}],"nonce_expires_in":60}`
	clock = clock.Add(time.Minute)
	rotated, err := att.Take(ctx, "chute-1")
	require.NoError(t, err)
	require.Equal(t, "pkA2", rotated.Pubkey)
	require.Equal(t, int32(4), verifier.calls.Load())

	// Past the re-attestation interval the instance is verified again even with the same key.
	clock = clock.Add(16 * time.Minute)
	_, err = att.Take(ctx, "chute-1")
	require.NoError(t, err)
	require.Equal(t, int32(5), verifier.calls.Load())

	// Fail closed: a rejected fleet yields no target, and an unreachable API is an error, never a stale target.
	verifier.accept = map[string]bool{}
	clock = clock.Add(16 * time.Minute)
	_, err = att.Take(ctx, "chute-1")
	require.ErrorIs(t, err, upstream.ErrNoAttestedInstance)
	api.failInst = true
	clock = clock.Add(time.Minute)
	_, err = att.Take(ctx, "chute-1")
	require.ErrorContains(t, err, "instances down")
	calls := len(api.calls)
	_, err = att.Take(ctx, "chute-1")
	require.ErrorContains(t, err, "last refresh failed", "a failed refresh is not retried for a moment")
	require.Len(t, api.calls, calls)
}

// signedBody re-encodes the fixture's attested_body with the signed quote under the given field names and re-signs it.
func signedBody(t *testing.T, ev chutes.Evidence, quoteFields map[string]string) chutes.Evidence {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(mustDecode(t, ev.AttestedBody), &body))
	evidence, ok := body["evidence"].(map[string]any)
	require.True(t, ok)
	delete(evidence, "tdx_quote")
	delete(evidence, "quote")
	for name, value := range quoteFields {
		evidence[name] = value
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	ev.AttestedBody = base64.StdEncoding.EncodeToString(raw)
	return resign(t, ev)
}

// The signed quote may sit under either name; a resigned body passes the signed part and stops at the impostor certificate.
func TestVerifySignedQuoteField(t *testing.T) {
	f := loadFixture(t, "blackwell")
	quote, other := f.Evidence.Quote, loadFixture(t, "hopper").Evidence.Quote
	const passed, differs = "REPORT_DATA[32:64]", "quote differs"
	tests := []struct {
		name    string
		fields  map[string]string
		wantErr string
	}{
		{"only tdx_quote", map[string]string{"tdx_quote": quote}, passed},
		{"only quote", map[string]string{"quote": quote}, passed},
		{"both equal", map[string]string{"tdx_quote": quote, "quote": quote}, passed},
		{"both differ, quote is the other", map[string]string{"tdx_quote": quote, "quote": other}, differs},
		{"both differ, tdx_quote is the other", map[string]string{"tdx_quote": other, "quote": quote}, differs},
		{"only quote, not the verified one", map[string]string{"quote": other}, differs},
		{"neither", map[string]string{}, differs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ok atomic.Int32
			ok.Store(http.StatusOK)
			_, err := fixtureVerifier(t, "blackwell", &ok).Verify(context.Background(), signedBody(t, f.Evidence, tt.fields),
				f.Nonce, "unknown-key")
			require.ErrorIs(t, err, chutes.ErrBinding)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// The signed attested_body carries the GPU evidence too; the unsigned sibling the verifier reads must be that copy.
func TestVerifyRejectsUnsignedGPUEvidence(t *testing.T) {
	f := loadFixture(t, "blackwell")
	var ok atomic.Int32
	ok.Store(http.StatusOK)
	ev := f.Evidence
	ev.GPUEvidence = append([]nvidia.Evidence(nil), f.Evidence.GPUEvidence...)
	ev.GPUEvidence[0].Arch = "HOPPER"
	_, err := fixtureVerifier(t, "blackwell", &ok).Verify(context.Background(), ev, f.Nonce, "unknown-key")
	require.ErrorIs(t, err, chutes.ErrBinding)
	require.ErrorContains(t, err, "gpu evidence differs")
}

type stubQuote struct{ report *tdx.Report }

func (s stubQuote) Verify(context.Context, []byte) (*tdx.Report, error) { return s.report, nil }

type stubGPU struct {
	calls atomic.Int32
	nonce [32]byte
}

func (s *stubGPU) Verify(_ context.Context, _ []nvidia.Evidence, nonce [32]byte) (*nvidia.Verdict, error) {
	s.calls.Add(1)
	s.nonce = nonce
	return &nvidia.Verdict{Overall: true, ExpiresAt: captureTime().Add(time.Hour)}, nil
}

// The accepting path runs the real signature check over a stubbed report that binds the nonce to a test key.
func TestVerifyAcceptsBoundInstance(t *testing.T) {
	f := loadFixture(t, "blackwell")
	report, err := tdx.Parse(mustDecode(t, f.Evidence.Quote))
	require.NoError(t, err)
	pubkey := "test-e2e-key"
	want := sha256.Sum256([]byte(f.Nonce + pubkey))
	copy(report.ReportData[:32], want[:])
	gpu := &stubGPU{}
	v := &chutes.Verifier{TDX: stubQuote{report}, GPU: gpu, Policy: measuredPolicy(t), Now: captureTime}

	verified, err := v.Verify(context.Background(), f.Evidence, f.Nonce, pubkey)
	require.NoError(t, err)
	require.Equal(t, f.Evidence.InstanceID, verified.InstanceID)
	require.Equal(t, pubkey, verified.Pubkey)
	require.Equal(t, captureTime(), verified.VerifiedAt)
	require.Equal(t, int32(1), gpu.calls.Load())
	require.Equal(t, want, gpu.nonce, "the GPU nonce is REPORT_DATA[0:32]")

	// The same report with the real (unknown) key hash is refused, as is a policy that does not pin this TD.
	_, err = v.Verify(context.Background(), f.Evidence, f.Nonce, "other-key")
	require.ErrorIs(t, err, chutes.ErrBinding)
	v.Policy.TDX.MRTD = []string{strings.Repeat("00", 48)}
	_, err = v.Verify(context.Background(), f.Evidence, f.Nonce, pubkey)
	require.ErrorIs(t, err, tdx.ErrUnpinnedMeasurement)
}

func mustDecode(t *testing.T, b64 string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	return b
}

// A real instance on the renamed field, its signature, quote and E2EE key binding as recorded; only DCAP and the GPUs are stubbed.
func TestVerifyRecordedQuoteFieldSample(t *testing.T) {
	f := loadFixture(t, "quote-field")
	report, err := tdx.Parse(mustDecode(t, f.Evidence.Quote))
	require.NoError(t, err)
	gpu := &stubGPU{}
	v := &chutes.Verifier{TDX: stubQuote{report}, GPU: gpu, Policy: measuredPolicy(t), Now: captureTime}

	verified, err := v.Verify(context.Background(), f.Evidence, f.Nonce, f.E2EPubkey)
	require.NoError(t, err)
	require.Equal(t, f.Evidence.InstanceID, verified.InstanceID)
	require.Equal(t, f.E2EPubkey, verified.Pubkey)
	require.Equal(t, int32(1), gpu.calls.Load())
}

// A failed refresh keeps serving known models within the grace period; unknown models and a cold cache still fail.
func TestCatalogServesStaleOnRefreshFailure(t *testing.T) {
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"org/m-TEE","chute_id":"c1","confidential_compute":true}]}`)
	}))
	defer srv.Close()
	c := chutes.NewCatalog(srv.URL, srv.Client())
	clock := time.Now()
	chutes.SetCatalogClock(c, func() time.Time { return clock })
	ctx := context.Background()
	down.Store(true)
	_, err := c.Resolve(ctx, "org/m-TEE")
	require.ErrorContains(t, err, "502", "cold cache fails closed")
	down.Store(false)
	_, err = c.Resolve(ctx, "org/m-TEE")
	require.NoError(t, err)
	down.Store(true)
	clock = clock.Add(10 * time.Minute)
	id, err := c.Resolve(ctx, "org/m-TEE")
	require.NoError(t, err, "known model within grace")
	require.Equal(t, "c1", id)
	_, err = c.Resolve(ctx, "org/other")
	require.ErrorContains(t, err, "502", "unknown model gets the refresh error")
	clock = clock.Add(2 * time.Hour)
	_, err = c.Resolve(ctx, "org/m-TEE")
	require.ErrorContains(t, err, "502", "past the grace period the stale catalog is no longer served")
}
