// Package nvidia verifies GPU attestation evidence locally (chain, SPDM signature, nonce, mode) and through NRAS.
package nvidia

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/sealedin/gateway/internal/teeverify"
)

// Evidence is one GPU's entry as Chutes and NRAS exchange it: base64 PEM chain, base64 SPDM request plus response.
type Evidence struct {
	Arch        string `json:"arch"`
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
}

// Mode is the confidential-computing deployment mode from the GPU's opaque data feature flag.
type Mode string

const (
	// ModeSPT is single-GPU passthrough.
	ModeSPT Mode = "SPT"
	// ModeMPT is multi-GPU passthrough.
	ModeMPT Mode = "MPT"
	// ModePPCIE is protected PCIe over an attested NVSwitch fabric.
	ModePPCIE Mode = "PPCIE"
)

// Report is what local verification learned about one GPU. Arch is the caller's label; NRAS authenticates it.
type Report struct {
	Arch          string
	DriverVersion string
	Chip          string
	Mode          Mode
}

var (
	// ErrUnsupportedMode is returned for a feature flag outside the known confidential modes.
	ErrUnsupportedMode = errors.New("nvidia: GPU reports a feature flag that is not a known confidential mode")
	// ErrBadEvidence is returned for evidence that does not parse as SPDM 1.1 GET_MEASUREMENTS/MEASUREMENTS.
	ErrBadEvidence = errors.New("nvidia: malformed SPDM evidence")
)

// NVIDIA Device Identity CA from NVIDIA/nvtrust (local_gpu_verifier/certs), pinned by fingerprint.
//
//go:embed device_identity_root_ca.pem
var rootCAPEM []byte

const rootCAFingerprint = "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48"

const (
	spdmVersion11       = 0x11
	spdmGetMeasurements = 0xe0
	spdmMeasurements    = 0x60
	getMeasurementsLen  = 37
	requestNonceOffset  = 4
	nonceSize           = 32
	responseHeaderLen   = 8
	recordLenOffset     = 5
	opaqueLenSize       = 2
	p384SigLen          = 96
	p384CoordLen        = 48
	minChainLen         = 2
	bitsPerByte         = 8
	maxFlagLen          = 8

	opaqueDriverVersion = 3
	opaqueChipInfo      = 35
	opaqueFeatureFlag   = 36
	opaqueHeaderLen     = 4
)

// VerifyLocal checks one GPU's evidence against nonce at time now; judging the measurements is NRAS's job.
func VerifyLocal(ev Evidence, nonce [nonceSize]byte, now time.Time) (*Report, error) {
	leaf, err := verifyChain(ev.Certificate, now)
	if err != nil {
		return nil, err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("nvidia: leaf certificate key is %T, want ECDSA P-384", leaf.PublicKey)
	}
	raw, decodeErr := base64.StdEncoding.DecodeString(ev.Evidence)
	if decodeErr != nil {
		return nil, fmt.Errorf("%w: base64: %w", ErrBadEvidence, decodeErr)
	}
	opaque, spdmErr := verifySPDM(raw, nonce, key)
	if spdmErr != nil {
		return nil, spdmErr
	}
	report, opaqueErr := ParseOpaque(opaque)
	if opaqueErr != nil {
		return nil, opaqueErr
	}
	report.Arch = ev.Arch
	return report, nil
}

func verifyChain(b64PEM string, now time.Time) (*x509.Certificate, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(b64PEM)
	if err != nil {
		return nil, fmt.Errorf("nvidia: certificate bundle base64: %w", err)
	}
	var certs []*x509.Certificate
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("nvidia: certificate bundle: %w", parseErr)
		}
		certs = append(certs, cert)
	}
	if len(certs) < minChainLen {
		return nil, fmt.Errorf("nvidia: certificate bundle has %d certificates, need a leaf and a chain", len(certs))
	}
	root, err := pinnedRoot()
	if err != nil {
		return nil, err
	}
	if last := certs[len(certs)-1]; !last.Equal(root) {
		got := sha256.Sum256(last.Raw)
		return nil, fmt.Errorf("nvidia: certificate chain does not end at the pinned NVIDIA root (got %s)",
			hex.EncodeToString(got[:]))
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1 : len(certs)-1] {
		intermediates.AddCert(c)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	// Device certificates are not TLS certificates: no EKU expectation.
	opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, verifyErr := certs[0].Verify(opts); verifyErr != nil {
		return nil, fmt.Errorf("nvidia: certificate chain: %w", verifyErr)
	}
	return certs[0], nil
}

func pinnedRoot() (*x509.Certificate, error) {
	cert, err := teeverify.PinnedCert(rootCAPEM, rootCAFingerprint)
	if err != nil {
		return nil, fmt.Errorf("nvidia: %w", err)
	}
	return cert, nil
}

func equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// verifySPDM checks the SPDM 1.1 pair, the requester nonce and the P-384 signature over
// request || response-without-signature, and returns the opaque data. Response after the 4-byte header:
// blocks (1), record length (3 LE), record, nonce (32), opaque length (2 LE), opaque, signature (96, r||s).
func verifySPDM(raw []byte, nonce [nonceSize]byte, key *ecdsa.PublicKey) ([]byte, error) {
	if len(raw) < getMeasurementsLen+responseHeaderLen {
		return nil, fmt.Errorf("%w: evidence too short (%d bytes)", ErrBadEvidence, len(raw))
	}
	if raw[0] != spdmVersion11 || raw[1] != spdmGetMeasurements {
		return nil, fmt.Errorf("%w: request is not SPDM 1.1 GET_MEASUREMENTS", ErrBadEvidence)
	}
	if !equal(raw[requestNonceOffset:requestNonceOffset+nonceSize], nonce[:]) {
		return nil, fmt.Errorf("nvidia: requester nonce %s does not match the expected nonce",
			hex.EncodeToString(raw[requestNonceOffset:requestNonceOffset+nonceSize]))
	}
	resp := raw[getMeasurementsLen:]
	if resp[0] != spdmVersion11 || resp[1] != spdmMeasurements {
		return nil, fmt.Errorf("%w: response is not SPDM 1.1 MEASUREMENTS", ErrBadEvidence)
	}
	recordLen := int(resp[recordLenOffset]) | int(resp[recordLenOffset+1])<<bitsPerByte |
		int(resp[recordLenOffset+2])<<(2*bitsPerByte) //nolint:mnd // three-byte little-endian length
	offset := responseHeaderLen + recordLen + nonceSize
	if offset+opaqueLenSize > len(resp) {
		return nil, fmt.Errorf("%w: response too short for the opaque length", ErrBadEvidence)
	}
	opaqueLen := int(binary.LittleEndian.Uint16(resp[offset:]))
	offset += opaqueLenSize
	if offset+opaqueLen+p384SigLen != len(resp) {
		return nil, fmt.Errorf("%w: response length does not end at the signature", ErrBadEvidence)
	}
	opaque := resp[offset : offset+opaqueLen]
	sig := resp[offset+opaqueLen:]
	digest := sha512.Sum384(raw[:getMeasurementsLen+offset+opaqueLen])
	r := new(big.Int).SetBytes(sig[:p384CoordLen])
	s := new(big.Int).SetBytes(sig[p384CoordLen:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, errors.New("nvidia: SPDM measurement signature does not verify under the GPU certificate")
	}
	return opaque, nil
}

// ParseOpaque decodes the type-length-value opaque data; a GPU without a known feature flag is refused.
func ParseOpaque(opaque []byte) (*Report, error) {
	report := &Report{}
	seenFlag := false
	for i := 0; i+opaqueHeaderLen <= len(opaque); {
		typ := binary.LittleEndian.Uint16(opaque[i:])
		size := int(binary.LittleEndian.Uint16(opaque[i+2:]))
		i += opaqueHeaderLen
		if i+size > len(opaque) {
			return nil, fmt.Errorf("%w: opaque field %d overruns the block", ErrBadEvidence, typ)
		}
		value := opaque[i : i+size]
		i += size
		switch typ {
		case opaqueDriverVersion:
			report.DriverVersion = cString(value)
		case opaqueChipInfo:
			report.Chip = cString(value)
		case opaqueFeatureFlag:
			seenFlag = true
			mode, ok := modeOf(value)
			if !ok {
				return nil, fmt.Errorf("%w: feature flag %s", ErrUnsupportedMode, hex.EncodeToString(value))
			}
			report.Mode = mode
		}
	}
	if !seenFlag {
		return nil, fmt.Errorf("%w: no feature flag in opaque data", ErrUnsupportedMode)
	}
	return report, nil
}

// modeOf maps the little-endian feature flag as nvtrust does: 0 SPT, 1 MPT, 2 PPCIE.
func modeOf(value []byte) (Mode, bool) {
	if len(value) > maxFlagLen {
		return "", false
	}
	var padded [maxFlagLen]byte
	copy(padded[:], value)
	switch binary.LittleEndian.Uint64(padded[:]) {
	case 0:
		return ModeSPT, true
	case 1:
		return ModeMPT, true
	case 2: //nolint:mnd // the three nvtrust flag values
		return ModePPCIE, true
	default:
		return "", false
	}
}

func cString(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\x00")
	return s
}

// Policy is the GPU allowlist.
type Policy struct {
	Archs []string `yaml:"archs"`
	Modes []Mode   `yaml:"modes"`
}

// Validate rejects an empty allowlist or an unknown mode.
func (p Policy) Validate() error {
	if len(p.Archs) == 0 || len(p.Modes) == 0 {
		return errors.New("nvidia: policy must allow at least one GPU arch and mode")
	}
	for _, m := range p.Modes {
		if m != ModeSPT && m != ModeMPT && m != ModePPCIE {
			return fmt.Errorf("nvidia: policy mode %q unknown", m)
		}
	}
	return nil
}

// Check fails unless the report's architecture and mode are both allowed.
func (p Policy) Check(r *Report) error {
	if !slices.Contains(p.Archs, r.Arch) {
		return fmt.Errorf("nvidia: GPU arch %q not in policy %v", r.Arch, p.Archs)
	}
	if !slices.Contains(p.Modes, r.Mode) {
		return fmt.Errorf("nvidia: GPU mode %q not in policy %v", r.Mode, p.Modes)
	}
	return nil
}
