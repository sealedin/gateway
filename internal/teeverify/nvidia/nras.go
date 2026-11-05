package nvidia

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultAttestURL is NRAS v3 GPU attestation.
	DefaultAttestURL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
	// DefaultJWKSURL publishes the verdict signing keys.
	DefaultJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
	// Issuer is the iss claim every accepted verdict must carry.
	Issuer               = "https://nras.attestation.nvidia.com"
	jwksTTL              = time.Hour // an unknown kid refetches sooner
	maxBody              = 4 << 20
	clockLeeway          = 10 * time.Second
	jwsParts             = 3
	pairLen              = 2
	uncompressedPointTag = 0x04
)

// NRAS claim names (hyphenated on the wire, so read from a map rather than struct tags).
const (
	claimOverall       = "x-nvidia-overall-att-result"
	claimNonce         = "eat_nonce"
	claimSubmods       = "submods"
	claimIssuer        = "iss"
	claimMeasRes       = "measres"
	claimNonceMatch    = "x-nvidia-gpu-attestation-report-nonce-match"
	claimChainValid    = "x-nvidia-gpu-attestation-report-cert-chain-validated"
	claimSigVerified   = "x-nvidia-gpu-attestation-report-signature-verified"
	claimArchCheck     = "x-nvidia-gpu-arch-check"
	claimSecureBoot    = "secboot"
	claimDebugStatus   = "dbgstat"
	claimHWModel       = "hwmodel"
	claimDriverVersion = "x-nvidia-gpu-driver-version"
	claimExpiresAt     = "exp"
	claimNotBefore     = "nbf"
)

var (
	// ErrVerdictFailed is returned when NRAS verified the evidence but the verdict is not a pass.
	ErrVerdictFailed = errors.New("nvidia: NRAS verdict failed")
	errUnknownKid    = errors.New("JWT kid not in the keyset")
)

// Verdict is the verified content of an NRAS v3 response.
type Verdict struct {
	Overall bool
	Nonce   string
	GPUs    map[string]GPUClaims
	// ExpiresAt is the earliest expiry across the overall and per-GPU tokens.
	ExpiresAt time.Time
}

// GPUClaims are the per-GPU claims this verifier acts on.
type GPUClaims struct {
	MeasRes            string
	NonceMatch         bool
	CertChainValidated bool
	SignatureVerified  bool
	ArchCheck          bool
	SecureBoot         bool
	DebugStatus        string
	HWModel            string
	DriverVersion      string
}

type claims map[string]json.RawMessage

func (c claims) str(key string) string {
	var s string
	_ = json.Unmarshal(c[key], &s)
	return s
}

func (c claims) boolean(key string) bool {
	var b bool
	_ = json.Unmarshal(c[key], &b)
	return b
}

func (c claims) unix(key string) int64 {
	var n int64
	_ = json.Unmarshal(c[key], &n)
	return n
}

// ParseVerdict verifies an NRAS v3 body ([["JWT", overall], {"GPU-0": jwt, ...}]): every token's ES384 signature,
// issuer, window and nonce, the per-GPU tokens against the overall submods digests, and the GPU count.
func ParseVerdict(raw, jwks []byte, nonce [nonceSize]byte, gpus int, now time.Time) (*Verdict, error) {
	overallToken, perGPU, err := parseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	keys, err := parseJWKS(jwks)
	if err != nil {
		return nil, err
	}
	overall, err := verifyJWS(overallToken, keys, now)
	if err != nil {
		return nil, fmt.Errorf("nvidia: overall verdict: %w", err)
	}
	want := hex.EncodeToString(nonce[:])
	if !equal([]byte(overall.str(claimNonce)), []byte(want)) {
		return nil, fmt.Errorf("nvidia: NRAS verdict nonce %q does not match the expected nonce", overall.str(claimNonce))
	}
	digests, err := submodDigests(overall[claimSubmods])
	if err != nil {
		return nil, err
	}
	if len(perGPU) != gpus || len(digests) != gpus {
		return nil, fmt.Errorf("nvidia: NRAS verdict covers %d GPU tokens and %d submods, submitted %d", len(perGPU), len(digests), gpus)
	}
	v := &Verdict{Overall: overall.boolean(claimOverall), Nonce: want, GPUs: make(map[string]GPUClaims, len(perGPU)),
		ExpiresAt: time.Unix(overall.unix(claimExpiresAt), 0)}
	for id, token := range perGPU {
		sum := sha256.Sum256([]byte(token))
		if digests[id] != hex.EncodeToString(sum[:]) {
			return nil, fmt.Errorf("nvidia: %s token digest does not match the overall verdict's submods", id)
		}
		gpu, gpuErr := verifyJWS(token, keys, now)
		if gpuErr != nil {
			return nil, fmt.Errorf("nvidia: %s verdict: %w", id, gpuErr)
		}
		if !equal([]byte(gpu.str(claimNonce)), []byte(want)) {
			return nil, fmt.Errorf("nvidia: %s verdict nonce %q does not match the expected nonce", id, gpu.str(claimNonce))
		}
		if exp := time.Unix(gpu.unix(claimExpiresAt), 0); exp.Before(v.ExpiresAt) {
			v.ExpiresAt = exp
		}
		v.GPUs[id] = gpu.gpuClaims()
	}
	if checkErr := v.Check(); checkErr != nil {
		return nil, checkErr
	}
	return v, nil
}

func parseEnvelope(raw []byte) (string, map[string]string, error) {
	var envelope []json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope) != pairLen {
		return "", nil, fmt.Errorf("nvidia: NRAS verdict is not the expected two-element array: %w", err)
	}
	var overallEntry []string
	if err := json.Unmarshal(envelope[0], &overallEntry); err != nil || len(overallEntry) != pairLen || overallEntry[0] != "JWT" {
		return "", nil, fmt.Errorf("nvidia: NRAS verdict overall entry malformed: %w", err)
	}
	var perGPU map[string]string
	if err := json.Unmarshal(envelope[1], &perGPU); err != nil {
		return "", nil, fmt.Errorf("nvidia: NRAS verdict per-GPU entry malformed: %w", err)
	}
	return overallEntry[1], perGPU, nil
}

func (c claims) gpuClaims() GPUClaims {
	return GPUClaims{MeasRes: c.str(claimMeasRes), NonceMatch: c.boolean(claimNonceMatch),
		CertChainValidated: c.boolean(claimChainValid), SignatureVerified: c.boolean(claimSigVerified),
		ArchCheck: c.boolean(claimArchCheck), SecureBoot: c.boolean(claimSecureBoot),
		DebugStatus: c.str(claimDebugStatus), HWModel: c.str(claimHWModel), DriverVersion: c.str(claimDriverVersion)}
}

// submodDigests reads the overall token's submods: {"GPU-0": ["DIGEST", ["SHA-256", hex]], ...}.
func submodDigests(raw json.RawMessage) (map[string]string, error) {
	var submods map[string][]json.RawMessage
	if err := json.Unmarshal(raw, &submods); err != nil {
		return nil, fmt.Errorf("nvidia: overall verdict submods: %w", err)
	}
	digests := make(map[string]string, len(submods))
	for id, entry := range submods {
		var kind string
		var digest []string
		if len(entry) != pairLen || json.Unmarshal(entry[0], &kind) != nil || kind != "DIGEST" ||
			json.Unmarshal(entry[1], &digest) != nil || len(digest) != pairLen || digest[0] != "SHA-256" {
			return nil, fmt.Errorf("nvidia: overall verdict submod %s is not a SHA-256 digest", id)
		}
		digests[id] = strings.ToLower(digest[1])
	}
	return digests, nil
}

// Check fails unless the overall result and every GPU's claims are a pass.
func (v *Verdict) Check() error {
	if !v.Overall {
		return fmt.Errorf("%w: overall result false", ErrVerdictFailed)
	}
	if len(v.GPUs) == 0 {
		return fmt.Errorf("%w: no GPU verdicts", ErrVerdictFailed)
	}
	for id, g := range v.GPUs {
		switch {
		case g.MeasRes != "success":
			return fmt.Errorf("%w: %s measres %q", ErrVerdictFailed, id, g.MeasRes)
		case !g.NonceMatch:
			return fmt.Errorf("%w: %s report nonce not matched", ErrVerdictFailed, id)
		case !g.CertChainValidated || !g.SignatureVerified:
			return fmt.Errorf("%w: %s report certificate chain or signature not validated", ErrVerdictFailed, id)
		case !g.ArchCheck:
			return fmt.Errorf("%w: %s arch check failed", ErrVerdictFailed, id)
		case g.DebugStatus != "disabled":
			return fmt.Errorf("%w: %s debug status %q", ErrVerdictFailed, id, g.DebugStatus)
		case !g.SecureBoot:
			return fmt.Errorf("%w: %s secure boot off", ErrVerdictFailed, id)
		}
	}
	return nil
}

type jwk struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	KeyID   string `json:"kid"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

func parseJWKS(raw []byte) (map[string]*ecdsa.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("nvidia: JWKS: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.KeyType != "EC" || k.Curve != "P-384" {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil {
			return nil, fmt.Errorf("nvidia: JWKS key %q coordinates malformed", k.KeyID)
		}
		point := append(append([]byte{uncompressedPointTag}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
		if err != nil {
			return nil, fmt.Errorf("nvidia: JWKS key %q: %w", k.KeyID, err)
		}
		keys[k.KeyID] = pub
	}
	return keys, nil
}

// verifyJWS checks a compact ES384 JWS before decoding its claims; hand-rolled to keep go-jose out of the image.
func verifyJWS(token string, keys map[string]*ecdsa.PublicKey, now time.Time) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != jwsParts {
		return nil, errors.New("JWT is not three dot-separated parts")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err = json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("JWT header: %w", err)
	}
	if header.Alg != "ES384" {
		return nil, fmt.Errorf("JWT alg %q, want ES384", header.Alg)
	}
	key, ok := keys[header.Kid]
	if !ok {
		return nil, fmt.Errorf("%w: %q", errUnknownKid, header.Kid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != p384SigLen {
		return nil, errors.New("JWT signature is not 96 raw bytes")
	}
	digest := sha512.Sum384([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:p384CoordLen]), new(big.Int).SetBytes(sig[p384CoordLen:])) {
		return nil, errors.New("JWT signature does not verify")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWT payload: %w", err)
	}
	var c claims
	if err = json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("JWT payload: %w", err)
	}
	if iss := c.str(claimIssuer); iss != Issuer {
		return nil, fmt.Errorf("JWT issuer %q, want %q", iss, Issuer)
	}
	exp, nbf := c.unix(claimExpiresAt), c.unix(claimNotBefore)
	if exp == 0 || now.After(time.Unix(exp, 0).Add(clockLeeway)) {
		return nil, fmt.Errorf("JWT expired at %d", exp)
	}
	if now.Before(time.Unix(nbf, 0).Add(-clockLeeway)) {
		return nil, fmt.Errorf("JWT not yet valid until %d", nbf)
	}
	return c, nil
}

// NRAS is a client of NVIDIA's Remote Attestation Service with a cached keyset.
type NRAS struct {
	attestURL string
	jwksURL   string
	client    *http.Client
	Now       func() time.Time // tests pin it to a recorded verdict's window

	mu        sync.Mutex
	keyset    []byte
	fetchedAt time.Time
}

// NewNRAS returns a client for the given attestation and JWKS endpoints.
func NewNRAS(attestURL, jwksURL string, client *http.Client) *NRAS {
	return &NRAS{attestURL: attestURL, jwksURL: jwksURL, client: client, Now: time.Now}
}

// Attest posts the GPU evidence as an EAT bound to nonce and returns the verified, passing verdict.
func (n *NRAS) Attest(ctx context.Context, arch string, nonce [nonceSize]byte, evidence []Evidence) (*Verdict, error) {
	eat, err := json.Marshal(map[string]any{"arch": arch, "nonce": hex.EncodeToString(nonce[:]), "evidence_list": evidence})
	if err != nil {
		return nil, fmt.Errorf("nvidia: encode EAT: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.attestURL, bytes.NewReader(eat))
	if err != nil {
		return nil, fmt.Errorf("nvidia: NRAS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	body, err := n.do(req)
	if err != nil {
		return nil, fmt.Errorf("nvidia: NRAS attest: %w", err)
	}
	jwks, err := n.jwks(ctx, false)
	if err != nil {
		return nil, err
	}
	verdict, err := ParseVerdict(body, jwks, nonce, len(evidence), n.Now())
	if errors.Is(err, errUnknownKid) {
		// NVIDIA rotates keys: one forced refetch covers a verdict signed with a key newer than the cache.
		if jwks, err = n.jwks(ctx, true); err == nil {
			verdict, err = ParseVerdict(body, jwks, nonce, len(evidence), n.Now())
		}
	}
	return verdict, err
}

func (n *NRAS) jwks(ctx context.Context, force bool) ([]byte, error) {
	n.mu.Lock()
	cached, fetchedAt := n.keyset, n.fetchedAt
	n.mu.Unlock()
	if !force && cached != nil && n.Now().Sub(fetchedAt) < jwksTTL {
		return cached, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.jwksURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("nvidia: JWKS request: %w", err)
	}
	body, err := n.do(req)
	if err != nil {
		return nil, fmt.Errorf("nvidia: JWKS fetch: %w", err)
	}
	n.mu.Lock()
	n.keyset, n.fetchedAt = body, n.Now()
	n.mu.Unlock()
	return body, nil
}

func (n *NRAS) do(req *http.Request) ([]byte, error) {
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body, nil
}
