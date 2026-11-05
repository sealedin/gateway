package nvidia_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/teeverify/nvidia"
)

func fixtureDir() string { return filepath.Join("..", "testdata", "chutes") }

type sample struct {
	ReportData0_32 string `json:"report_data_0_32"`
	GPUs           int    `json:"gpus"`
	Arch           string `json:"arch"`
	NRASIssuedAt   int64  `json:"nras_iat"`
	NRASExpiresAt  int64  `json:"nras_exp"`
}

func loadSample(t *testing.T, name string) (sample, []nvidia.Evidence, [32]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir(), "meta.json"))
	require.NoError(t, err)
	var m struct {
		Samples map[string]sample `json:"samples"`
	}
	require.NoError(t, json.Unmarshal(raw, &m))
	raw, err = os.ReadFile(filepath.Join(fixtureDir(), name+".json"))
	require.NoError(t, err)
	var f struct {
		Evidence struct {
			GPUEvidence []nvidia.Evidence `json:"gpu_evidence"`
		} `json:"evidence"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	var nonce [32]byte
	n, err := hex.DecodeString(m.Samples[name].ReportData0_32)
	require.NoError(t, err)
	copy(nonce[:], n)
	return m.Samples[name], f.Evidence.GPUEvidence, nonce
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{fixtureDir()}, parts...)...))
	require.NoError(t, err)
	return raw
}

func captureTime() time.Time { return time.Date(2026, time.October, 27, 13, 20, 0, 0, time.UTC) }

func TestVerifyLocalFixtures(t *testing.T) {
	tests := []struct {
		name   string
		mode   nvidia.Mode
		chip   string
		driver string
	}{
		{"blackwell", nvidia.ModeSPT, "GB202", "595.71.05"},
		{"hopper", nvidia.ModePPCIE, "", "595.71.05"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, evidence, nonce := loadSample(t, tt.name)
			require.Len(t, evidence, s.GPUs)
			for i, ev := range evidence {
				report, err := nvidia.VerifyLocal(ev, nonce, captureTime())
				require.NoError(t, err, "gpu %d", i)
				require.Equal(t, s.Arch, report.Arch)
				require.Equal(t, tt.mode, report.Mode)
				require.Equal(t, tt.chip, report.Chip)
				require.Equal(t, tt.driver, report.DriverVersion)
			}
		})
	}
}

func selfSignedChain(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "not nvidia"},
		NotBefore: captureTime().Add(-time.Hour), NotAfter: captureTime().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return base64.StdEncoding.EncodeToString(append(block, block...))
}

func TestVerifyLocalRejects(t *testing.T) {
	_, evidence, nonce := loadSample(t, "blackwell")
	good := evidence[0]
	rawEvidence, err := base64.StdEncoding.DecodeString(good.Evidence)
	require.NoError(t, err)
	flip := func(offset int) string {
		b := append([]byte(nil), rawEvidence...)
		b[offset] ^= 0x01
		return base64.StdEncoding.EncodeToString(b)
	}
	wrongNonce := nonce
	wrongNonce[0] ^= 0x01
	tests := []struct {
		name    string
		ev      nvidia.Evidence
		nonce   [32]byte
		wantErr string
	}{
		{"nonce mismatch", good, wrongNonce, "nonce"},
		{"flipped signature", nvidia.Evidence{Arch: good.Arch, Certificate: good.Certificate,
			Evidence: flip(len(rawEvidence) - 1)}, nonce, "signature"},
		{"flipped measurement", nvidia.Evidence{Arch: good.Arch, Certificate: good.Certificate,
			Evidence: flip(37 + 8 + 10)}, nonce, "signature"},
		{"truncated evidence", nvidia.Evidence{Arch: good.Arch, Certificate: good.Certificate,
			Evidence: base64.StdEncoding.EncodeToString(rawEvidence[:100])}, nonce, "short"},
		{"trailing bytes", nvidia.Evidence{Arch: good.Arch, Certificate: good.Certificate,
			Evidence: base64.StdEncoding.EncodeToString(append(append([]byte(nil), rawEvidence...), 0))}, nonce, "signature"},
		{"foreign root", nvidia.Evidence{Arch: good.Arch, Certificate: selfSignedChain(t), Evidence: good.Evidence},
			nonce, "root"},
		{"garbage certificate", nvidia.Evidence{Arch: good.Arch, Certificate: "!!", Evidence: good.Evidence},
			nonce, "certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, verifyErr := nvidia.VerifyLocal(tt.ev, tt.nonce, captureTime())
			require.ErrorContains(t, verifyErr, tt.wantErr)
		})
	}
}

func TestParseOpaqueRejectsUnknownMode(t *testing.T) {
	// A feature flag outside SPT/MPT/PPCIE means a GPU in a mode this verifier does not know to be confidential.
	opaque := []byte{36, 0, 2, 0, 0x07, 0x00}
	_, err := nvidia.ParseOpaque(opaque)
	require.ErrorIs(t, err, nvidia.ErrUnsupportedMode)
}

func TestParseVerdictFixtures(t *testing.T) {
	jwks := readFixture(t, "jwks.json")
	for _, name := range []string{"blackwell", "hopper"} {
		t.Run(name, func(t *testing.T) {
			s, _, nonce := loadSample(t, name)
			now := time.Unix(s.NRASIssuedAt, 0).Add(time.Minute)
			verdict, err := nvidia.ParseVerdict(readFixture(t, "nras", name+".json"), jwks, nonce, s.GPUs, now)
			require.NoError(t, err)
			require.True(t, verdict.Overall)
			require.Len(t, verdict.GPUs, s.GPUs)
			for id, gpu := range verdict.GPUs {
				require.Equal(t, "success", gpu.MeasRes, id)
				require.Equal(t, "595.71.05", gpu.DriverVersion, id)
				require.NotEmpty(t, gpu.HWModel, id)
			}
			require.False(t, verdict.ExpiresAt.After(time.Unix(s.NRASExpiresAt, 0)))
			require.True(t, verdict.ExpiresAt.After(now))
		})
	}
}

func TestParseVerdictRejects(t *testing.T) {
	s, _, nonce := loadSample(t, "blackwell")
	raw := readFixture(t, "nras", "blackwell.json")
	jwks := readFixture(t, "jwks.json")
	now := time.Unix(s.NRASIssuedAt, 0).Add(time.Minute)
	wrongNonce := nonce
	wrongNonce[0] ^= 0x01

	var keyset struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(jwks, &keyset))
	foreign, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	for _, k := range keyset.Keys {
		k["x"] = base64.RawURLEncoding.EncodeToString(foreign.X.FillBytes(make([]byte, 48)))
		k["y"] = base64.RawURLEncoding.EncodeToString(foreign.Y.FillBytes(make([]byte, 48)))
	}
	swappedJWKS, err := json.Marshal(keyset)
	require.NoError(t, err)

	var verdict []json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &verdict))
	var overall []string
	require.NoError(t, json.Unmarshal(verdict[0], &overall))
	tampered := []byte(overall[1])
	// Flip a payload character well inside the claims (after the header and the first few payload bytes).
	payloadStart := 0
	for i, c := range tampered {
		if c == '.' {
			payloadStart = i + 1
			break
		}
	}
	tampered[payloadStart+10] ^= 0x01
	tamperedOverall, err := json.Marshal([]string{"JWT", string(tampered)})
	require.NoError(t, err)
	tamperedVerdict, err := json.Marshal([]json.RawMessage{tamperedOverall, verdict[1]})
	require.NoError(t, err)
	hopper := readFixture(t, "nras", "hopper.json")
	var hopperVerdict []json.RawMessage
	require.NoError(t, json.Unmarshal(hopper, &hopperVerdict))
	var hopperGPUs map[string]string
	require.NoError(t, json.Unmarshal(hopperVerdict[1], &hopperGPUs))
	delete(hopperGPUs, "GPU-3")
	hopperGPUsJSON, err := json.Marshal(hopperGPUs)
	require.NoError(t, err)
	droppedGPU, err := json.Marshal([]json.RawMessage{hopperVerdict[0], hopperGPUsJSON})
	require.NoError(t, err)
	hopperGPUs["GPU-3"] = hopperGPUs["GPU-2"]
	hopperGPUsJSON, err = json.Marshal(hopperGPUs)
	require.NoError(t, err)
	swappedGPU, err := json.Marshal([]json.RawMessage{hopperVerdict[0], hopperGPUsJSON})
	require.NoError(t, err)
	hs, _, hopperNonce := loadSample(t, "hopper")
	hopperNow := time.Unix(hs.NRASIssuedAt, 0).Add(time.Minute)

	tests := []struct {
		name    string
		raw     []byte
		jwks    []byte
		nonce   [32]byte
		gpus    int
		now     time.Time
		wantErr string
	}{
		{"nonce mismatch", raw, jwks, wrongNonce, 1, now, "nonce"},
		{"expired", raw, jwks, nonce, 1, time.Unix(s.NRASExpiresAt, 0).Add(time.Hour), "expired"},
		{"not yet valid", raw, jwks, nonce, 1, now.Add(-24 * time.Hour), "not yet valid"},
		{"wrong key", raw, swappedJWKS, nonce, 1, now, "signature"},
		{"unknown kid", raw, []byte(`{"keys":[]}`), nonce, 1, now, "kid"},
		{"tampered payload", tamperedVerdict, jwks, nonce, 1, now, "signature"},
		{"gpu count differs from submission", raw, jwks, nonce, 2, now, "submitted 2"},
		{"gpu token dropped", droppedGPU, jwks, hopperNonce, 8, hopperNow, "submitted 8"},
		{"gpu token swapped", swappedGPU, jwks, hopperNonce, 8, hopperNow, "digest"},
		{"not json", []byte("nope"), jwks, nonce, 1, now, "verdict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, parseErr := nvidia.ParseVerdict(tt.raw, tt.jwks, tt.nonce, tt.gpus, tt.now)
			require.ErrorContains(t, parseErr, tt.wantErr)
		})
	}
}

func TestCheckClaims(t *testing.T) {
	good := func() nvidia.Verdict {
		return nvidia.Verdict{Overall: true, GPUs: map[string]nvidia.GPUClaims{"GPU-0": {MeasRes: "success",
			NonceMatch: true, CertChainValidated: true, SignatureVerified: true, ArchCheck: true, SecureBoot: true,
			DebugStatus: "disabled"}}}
	}
	tests := []struct {
		name    string
		mutate  func(v *nvidia.Verdict)
		wantErr string
	}{
		{"passes", func(*nvidia.Verdict) {}, ""},
		{"overall false", func(v *nvidia.Verdict) { v.Overall = false }, "overall"},
		{"no gpus", func(v *nvidia.Verdict) { v.GPUs = nil }, "no GPU"},
		{"measurements fail", func(v *nvidia.Verdict) { g := v.GPUs["GPU-0"]; g.MeasRes = "fail"; v.GPUs["GPU-0"] = g }, "measres"},
		{"nonce not matched", func(v *nvidia.Verdict) { g := v.GPUs["GPU-0"]; g.NonceMatch = false; v.GPUs["GPU-0"] = g }, "nonce"},
		{"arch check failed", func(v *nvidia.Verdict) { g := v.GPUs["GPU-0"]; g.ArchCheck = false; v.GPUs["GPU-0"] = g }, "arch"},
		{"debug enabled", func(v *nvidia.Verdict) { g := v.GPUs["GPU-0"]; g.DebugStatus = "enabled"; v.GPUs["GPU-0"] = g }, "debug"},
		{"secure boot off", func(v *nvidia.Verdict) { g := v.GPUs["GPU-0"]; g.SecureBoot = false; v.GPUs["GPU-0"] = g }, "secure boot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := good()
			tt.mutate(&v)
			err := v.Check()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, nvidia.ErrVerdictFailed)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestNRASAttest(t *testing.T) {
	s, evidence, nonce := loadSample(t, "blackwell")
	verdict := readFixture(t, "nras", "blackwell.json")
	jwks := readFixture(t, "jwks.json")
	var posted []byte
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/attest/gpu":
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			posted = body
			w.WriteHeader(status)
			_, _ = w.Write(verdict)
		case "/.well-known/jwks.json":
			_, _ = w.Write(jwks)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	nras := nvidia.NewNRAS(srv.URL+"/v3/attest/gpu", srv.URL+"/.well-known/jwks.json", srv.Client())
	nras.Now = func() time.Time { return time.Unix(s.NRASIssuedAt, 0).Add(time.Minute) }

	got, err := nras.Attest(context.Background(), s.Arch, nonce, evidence)
	require.NoError(t, err)
	require.True(t, got.Overall)
	var eat struct {
		Arch         string            `json:"arch"`
		Nonce        string            `json:"nonce"`
		EvidenceList []nvidia.Evidence `json:"evidence_list"`
	}
	require.NoError(t, json.Unmarshal(posted, &eat))
	require.Equal(t, s.Arch, eat.Arch)
	require.Equal(t, hex.EncodeToString(nonce[:]), eat.Nonce)
	require.Equal(t, evidence, eat.EvidenceList)

	status = http.StatusServiceUnavailable
	_, err = nras.Attest(context.Background(), s.Arch, nonce, evidence)
	require.ErrorContains(t, err, "503")
}

func TestPolicyCheck(t *testing.T) {
	report := &nvidia.Report{Arch: "HOPPER", Mode: nvidia.ModePPCIE}
	tests := []struct {
		name    string
		policy  nvidia.Policy
		wantErr string
	}{
		{"allowed", nvidia.Policy{Archs: []string{"BLACKWELL", "HOPPER"}, Modes: []nvidia.Mode{nvidia.ModeSPT, nvidia.ModePPCIE}}, ""},
		{"arch not allowed", nvidia.Policy{Archs: []string{"BLACKWELL"}, Modes: []nvidia.Mode{nvidia.ModePPCIE}}, "arch"},
		{"mode not allowed", nvidia.Policy{Archs: []string{"HOPPER"}, Modes: []nvidia.Mode{nvidia.ModeSPT}}, "mode"},
		{"empty policy", nvidia.Policy{}, "arch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Check(report)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
