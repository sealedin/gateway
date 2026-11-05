package chutes

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/sealedin/gateway/internal/teeverify/nvidia"
	"github.com/sealedin/gateway/internal/teeverify/tdx"
)

const checkSignature = "signature"

// Policy is the measured upstream policy the verifier enforces.
type Policy struct {
	TDX tdx.Policy    `yaml:"tdx"`
	GPU nvidia.Policy `yaml:"gpu"`
}

// Validate rejects a policy whose allowlists could never pin anything.
func (p Policy) Validate() error {
	if err := p.TDX.Validate(); err != nil {
		return err
	}
	return p.GPU.Validate()
}

// Evidence is one instance's entry of GET /chutes/{id}/evidence.
type Evidence struct {
	InstanceID   string            `json:"instance_id"`
	Quote        string            `json:"quote"`
	GPUEvidence  []nvidia.Evidence `json:"gpu_evidence"`
	Certificate  string            `json:"certificate"`
	Signature    string            `json:"signature"`
	AttestedBody string            `json:"attested_body"`
}

// Verified is an instance whose evidence passed every check at VerifiedAt.
type Verified struct {
	InstanceID string
	Pubkey     string
	VerifiedAt time.Time
	ExpiresAt  time.Time // the NRAS verdict expiry
}

// ErrBinding is returned when the evidence is genuine but not bound to the nonce and key it was requested for.
var ErrBinding = errors.New("chutes: evidence not bound to this nonce and instance key")

// CheckError names the verification step that refused an instance; the rejection log carries the name.
type CheckError struct {
	Check string
	Err   error
}

func (e *CheckError) Error() string { return e.Err.Error() }

// Unwrap keeps errors.Is working on the underlying failure.
func (e *CheckError) Unwrap() error { return e.Err }

func failed(check string, err error) error { return &CheckError{Check: check, Err: err} }

// QuoteVerifier is the DCAP step; tdx.Verifier in production, a stub in the orchestration test.
type QuoteVerifier interface {
	Verify(ctx context.Context, raw []byte) (*tdx.Report, error)
}

// GPUVerifier is the GPU step; nil means the built-in local SPDM check plus NRAS.
type GPUVerifier interface {
	Verify(ctx context.Context, evidence []nvidia.Evidence, nonce [nonceByteLen]byte) (*nvidia.Verdict, error)
}

// Verifier runs the per-instance checks; the Chutes API is only a relay for the evidence it verifies.
type Verifier struct {
	TDX    QuoteVerifier
	NRAS   *nvidia.NRAS
	GPU    GPUVerifier
	Policy Policy
	Now    func() time.Time // nil means time.Now
}

func (v *Verifier) now() time.Time {
	if v.Now == nil {
		return time.Now()
	}
	return v.Now()
}

// Verify checks the proxy signature over attested_body (our nonce), DCAP plus policy, the TLS key and
// SHA256(nonce || pubkey) bindings in REPORT_DATA, then every GPU locally and through NRAS.
func (v *Verifier) Verify(ctx context.Context, ev Evidence, nonceHex, pubkeyB64 string) (*Verified, error) {
	cert, err := v.checkSignature(ev, nonceHex)
	if err != nil {
		return nil, err
	}
	quote, err := base64.StdEncoding.DecodeString(ev.Quote)
	if err != nil {
		return nil, failed("quote_format", fmt.Errorf("chutes: quote base64: %w", err))
	}
	report, err := v.TDX.Verify(ctx, quote)
	if err != nil {
		return nil, failed("dcap", err)
	}
	if err = v.Policy.TDX.Check(report); err != nil {
		return nil, failed("tdx_policy", err)
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(spki[:], report.ReportData[nonceByteLen:]) != 1 {
		return nil, failed("tls_key_binding", fmt.Errorf("%w: REPORT_DATA[32:64] is not the hash of the signing certificate's key", ErrBinding))
	}
	var gpuNonce [nonceByteLen]byte
	copy(gpuNonce[:], report.ReportData[:nonceByteLen])
	want := sha256.Sum256([]byte(nonceHex + pubkeyB64))
	if subtle.ConstantTimeCompare(want[:], gpuNonce[:]) != 1 {
		return nil, failed("e2e_key_binding", fmt.Errorf("%w: REPORT_DATA[0:32] is not SHA256(nonce || e2e_pubkey)", ErrBinding))
	}
	verdict, err := v.checkGPUs(ctx, ev, gpuNonce)
	if err != nil {
		return nil, failed("gpu", err)
	}
	return &Verified{InstanceID: ev.InstanceID, Pubkey: pubkeyB64, VerifiedAt: v.now(), ExpiresAt: verdict.ExpiresAt}, nil
}

// checkSignature verifies the proxy's RSA PKCS1v15 signature over attested_body, which must carry our nonce and evidence.
func (v *Verifier) checkSignature(ev Evidence, nonceHex string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(ev.Certificate)
	if err != nil {
		return nil, failed(checkSignature, fmt.Errorf("chutes: certificate base64: %w", err))
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, failed(checkSignature, fmt.Errorf("chutes: certificate: %w", err))
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, failed(checkSignature, fmt.Errorf("chutes: certificate key is %T, want RSA", cert.PublicKey))
	}
	body, err := base64.StdEncoding.DecodeString(ev.AttestedBody)
	if err != nil {
		return nil, failed(checkSignature, fmt.Errorf("chutes: attested_body base64: %w", err))
	}
	sig, err := base64.StdEncoding.DecodeString(ev.Signature)
	if err != nil {
		return nil, failed(checkSignature, fmt.Errorf("chutes: signature base64: %w", err))
	}
	digest := sha256.Sum256(body)
	if err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, failed(checkSignature, errors.New("chutes: attested_body signature does not verify under the evidence certificate"))
	}
	var attested struct {
		Nonce    string `json:"nonce"`
		Evidence struct {
			TDXQuote *string `json:"tdx_quote"`
			Quote    *string `json:"quote"` // what newer instances call tdx_quote; pointers tell absent from empty
			GPUs     string  `json:"nvtrust_evidence"`
		} `json:"evidence"`
	}
	if err = json.Unmarshal(body, &attested); err != nil {
		return nil, failed(checkSignature, fmt.Errorf("chutes: attested_body: %w", err))
	}
	if subtle.ConstantTimeCompare([]byte(attested.Nonce), []byte(nonceHex)) != 1 {
		return nil, failed("nonce", fmt.Errorf("%w: attested_body nonce differs from ours", ErrBinding))
	}
	if !signedQuoteMatches(ev.Quote, attested.Evidence.TDXQuote, attested.Evidence.Quote) {
		return nil, failed("signed_quote", fmt.Errorf("%w: quote differs from the signed attested_body", ErrBinding))
	}
	// The unsigned gpu_evidence sibling is what gets verified; it must be the copy the proxy signed.
	var signedGPUs []nvidia.Evidence
	if err = json.Unmarshal([]byte(attested.Evidence.GPUs), &signedGPUs); err != nil || !slices.Equal(signedGPUs, ev.GPUEvidence) {
		return nil, failed("signed_gpu_evidence", fmt.Errorf("%w: gpu evidence differs from the signed attested_body", ErrBinding))
	}
	return cert, nil
}

// signedQuoteMatches requires at least one signed copy of the quote and every signed copy to be the one verified.
func signedQuoteMatches(quote string, signed ...*string) bool {
	found := false
	for _, s := range signed {
		if s == nil {
			continue
		}
		if *s != quote {
			return false
		}
		found = true
	}
	return found
}

func (v *Verifier) checkGPUs(ctx context.Context, ev Evidence, nonce [nonceByteLen]byte) (*nvidia.Verdict, error) {
	if len(ev.GPUEvidence) == 0 {
		return nil, errors.New("chutes: instance reports no GPU evidence")
	}
	if v.GPU != nil {
		return v.GPU.Verify(ctx, ev.GPUEvidence, nonce)
	}
	now := v.now()
	arch := ev.GPUEvidence[0].Arch
	for i, g := range ev.GPUEvidence {
		report, err := nvidia.VerifyLocal(g, nonce, now)
		if err != nil {
			return nil, fmt.Errorf("gpu %d: %w", i, err)
		}
		if err = v.Policy.GPU.Check(report); err != nil {
			return nil, fmt.Errorf("gpu %d: %w", i, err)
		}
		if g.Arch != arch {
			return nil, fmt.Errorf("gpu %d: arch %q differs from gpu 0 %q", i, g.Arch, arch)
		}
	}
	return v.NRAS.Attest(ctx, arch, nonce, ev.GPUEvidence)
}

// NewNonce returns a fresh 32-byte hex nonce.
func NewNonce() (string, error) {
	var b [nonceByteLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("chutes: nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
