// Package tdx verifies Intel TDX DCAP quotes of upstream TEEs and pins their measurements to a policy.
package tdx

import (
	"context"
	"crypto/x509"
	_ "embed" // the pinned Intel root below
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/sealedin/gateway/internal/teeverify"
)

const (
	// MeasurementSize is the byte length of MRTD and each RTMR.
	MeasurementSize = 48
	// ReportDataSize is the byte length of REPORT_DATA.
	ReportDataSize = 64
	rtmrCount      = 4
	attrSize       = 8
	debugBit       = 0x01 // TD_ATTRIBUTES bit 0: the host can read the TD's memory
	maxCollateral  = 4 << 20
)

var (
	// ErrNoCollateralSource is returned when no collateral getter is set; without one the TCB check would be skipped.
	ErrNoCollateralSource = errors.New("tdx: no collateral getter configured")
	// ErrDebugTD is returned for a quote whose TD runs with debug enabled.
	ErrDebugTD = errors.New("tdx: TD has the DEBUG attribute set")
	// ErrUnpinnedMeasurement is returned when a measurement is not on the policy allowlist.
	ErrUnpinnedMeasurement = errors.New("tdx: measurement not pinned by policy")
	// ErrBadQuote is returned for a quote that does not parse as a TDX v4 quote.
	ErrBadQuote = errors.New("tdx: malformed quote")
)

// Intel SGX Root CA, pinned by fingerprint and passed explicitly so the trust root is ours, not a library default.
//
//go:embed intel_sgx_root_ca.pem
var rootCAPEM []byte

const rootCAFingerprint = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

// Report is the TD report body of a verified (or merely parsed) quote.
type Report struct {
	MRTD         [MeasurementSize]byte
	RTMR         [rtmrCount][MeasurementSize]byte
	ReportData   [ReportDataSize]byte
	TDAttributes [attrSize]byte
	XFAM         [attrSize]byte
	// MRCONFIGID, MROWNER and MROWNERCONFIG are host-chosen at launch, so the policy pins them too.
	MRConfigID    [MeasurementSize]byte
	MROwner       [MeasurementSize]byte
	MROwnerConfig [MeasurementSize]byte
	TeeTCBSVN     []byte
}

// Debug reports whether the TD runs with the DEBUG attribute.
func (r *Report) Debug() bool { return r.TDAttributes[0]&debugBit != 0 }

// Parse decodes the quote structurally without checking any signature.
func Parse(raw []byte) (*Report, error) {
	report, _, err := parse(raw)
	return report, err
}

func parse(raw []byte) (*Report, *pb.QuoteV4, error) {
	quote, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrBadQuote, err)
	}
	v4, ok := quote.(*pb.QuoteV4)
	if !ok {
		return nil, nil, fmt.Errorf("%w: unsupported quote type %T", ErrBadQuote, quote)
	}
	body := v4.GetTdQuoteBody()
	rtmrs := body.GetRtmrs()
	if len(body.GetMrTd()) != MeasurementSize || len(rtmrs) != rtmrCount || len(body.GetReportData()) != ReportDataSize ||
		len(body.GetTdAttributes()) != attrSize || len(body.GetXfam()) != attrSize ||
		len(body.GetMrConfigId()) != MeasurementSize || len(body.GetMrOwner()) != MeasurementSize ||
		len(body.GetMrOwnerConfig()) != MeasurementSize {
		return nil, nil, fmt.Errorf("%w: unexpected TD report field sizes", ErrBadQuote)
	}
	r := &Report{TeeTCBSVN: body.GetTeeTcbSvn()}
	copy(r.MRTD[:], body.GetMrTd())
	copy(r.MRConfigID[:], body.GetMrConfigId())
	copy(r.MROwner[:], body.GetMrOwner())
	copy(r.MROwnerConfig[:], body.GetMrOwnerConfig())
	copy(r.ReportData[:], body.GetReportData())
	copy(r.TDAttributes[:], body.GetTdAttributes())
	copy(r.XFAM[:], body.GetXfam())
	for i, rtmr := range rtmrs {
		if len(rtmr) != MeasurementSize {
			return nil, nil, fmt.Errorf("%w: rtmr%d has %d bytes", ErrBadQuote, i, len(rtmr))
		}
		copy(r.RTMR[i][:], rtmr)
	}
	return r, v4, nil
}

// HTTPGetter fetches collateral with client, so its timeout bounds the Intel PCS round trips.
func HTTPGetter(client *http.Client) trust.HTTPSGetter { return httpGetter{client: client} }

type httpGetter struct{ client *http.Client }

func (g httpGetter) Get(url string) (map[string][]string, []byte, error) {
	resp, err := g.client.Get(url) //nolint:noctx // go-tdx-guest's getter interface carries no context
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCollateral+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxCollateral {
		return nil, nil, fmt.Errorf("tdx: collateral from %s exceeds %d bytes", url, maxCollateral)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("tdx: collateral from %s: HTTP %d", url, resp.StatusCode)
	}
	return resp.Header, body, nil
}

// Verifier runs the DCAP check with collateral from Getter; Now pins validity windows for recorded quotes.
type Verifier struct {
	Getter trust.HTTPSGetter
	Now    func() time.Time
}

// Verify checks the Intel chain, PCK CRL, QE identity and tcbInfo (TCB UpToDate only), then refuses a debug TD.
func (v Verifier) Verify(_ context.Context, raw []byte) (*Report, error) {
	if v.Getter == nil {
		return nil, ErrNoCollateralSource
	}
	roots, err := pinnedRoots()
	if err != nil {
		return nil, err
	}
	report, quote, err := parse(raw)
	if err != nil {
		return nil, err
	}
	opts := verify.DefaultOptions()
	opts.GetCollateral = true
	opts.CheckRevocations = true
	opts.Getter = v.Getter
	opts.TrustedRoots = roots
	if v.Now != nil {
		opts.Now = v.Now()
	}
	if verifyErr := verify.TdxQuote(quote, opts); verifyErr != nil {
		return nil, fmt.Errorf("tdx: DCAP verification failed (signature, PCK chain or collateral): %w", verifyErr)
	}
	if report.Debug() {
		return nil, ErrDebugTD
	}
	return report, nil
}

// Policy is the measurement allowlist: MRTD and RTMR0 independently, RTMR1-3 as one tuple per image build (a kernel
// from one build must not pair with a root filesystem from another), the rest exact.
type Policy struct {
	MRTD          []string `yaml:"mrtd"`
	RTMR0         []string `yaml:"rtmr0"`
	Images        []Image  `yaml:"images"`
	TDAttributes  string   `yaml:"td_attributes"`
	XFAM          string   `yaml:"xfam"`
	MRConfigID    string   `yaml:"mrconfigid"`
	MROwner       string   `yaml:"mrowner"`
	MROwnerConfig string   `yaml:"mrownerconfig"`
}

// Image is one guest image build's RTMR1-3 tuple, hex-encoded.
type Image struct {
	RTMR1 string `yaml:"rtmr1"`
	RTMR2 string `yaml:"rtmr2"`
	RTMR3 string `yaml:"rtmr3"`
}

// Validate rejects a policy that could never pin anything.
func (p Policy) Validate() error {
	if len(p.MRTD) == 0 || len(p.RTMR0) == 0 || len(p.Images) == 0 {
		return errors.New("tdx: policy must pin at least one mrtd, one rtmr0 and one image")
	}
	for _, list := range [][]string{p.MRTD, p.RTMR0} {
		for _, m := range list {
			if _, err := decodeHex(m, MeasurementSize); err != nil {
				return err
			}
		}
	}
	for _, img := range p.Images {
		for _, m := range []string{img.RTMR1, img.RTMR2, img.RTMR3} {
			if _, err := decodeHex(m, MeasurementSize); err != nil {
				return err
			}
		}
	}
	for _, a := range []string{p.TDAttributes, p.XFAM} {
		if _, err := decodeHex(a, attrSize); err != nil {
			return err
		}
	}
	for _, m := range []string{p.MRConfigID, p.MROwner, p.MROwnerConfig} {
		if _, err := decodeHex(m, MeasurementSize); err != nil {
			return err
		}
	}
	return nil
}

// Check fails unless every pinned field matches; all mismatches are reported together.
func (p Policy) Check(r *Report) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrUnpinnedMeasurement, err)
	}
	var problems []string
	if !contains(p.MRTD, r.MRTD[:]) {
		problems = append(problems, "mrtd "+hex.EncodeToString(r.MRTD[:]))
	}
	if !contains(p.RTMR0, r.RTMR[0][:]) {
		problems = append(problems, "rtmr0 "+hex.EncodeToString(r.RTMR[0][:]))
	}
	if !p.imagePinned(r) {
		problems = append(problems, fmt.Sprintf("rtmr1-3 %s/%s/%s",
			hex.EncodeToString(r.RTMR[1][:]), hex.EncodeToString(r.RTMR[2][:]), hex.EncodeToString(r.RTMR[3][:])))
	}
	if !contains([]string{p.TDAttributes}, r.TDAttributes[:]) {
		problems = append(problems, "td_attributes "+hex.EncodeToString(r.TDAttributes[:]))
	}
	if !contains([]string{p.XFAM}, r.XFAM[:]) {
		problems = append(problems, "xfam "+hex.EncodeToString(r.XFAM[:]))
	}
	for name, pinned := range map[string]struct {
		want string
		got  []byte
	}{"mrconfigid": {p.MRConfigID, r.MRConfigID[:]}, "mrowner": {p.MROwner, r.MROwner[:]},
		"mrownerconfig": {p.MROwnerConfig, r.MROwnerConfig[:]}} {
		if !contains([]string{pinned.want}, pinned.got) {
			problems = append(problems, name+" "+hex.EncodeToString(pinned.got))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %v", ErrUnpinnedMeasurement, problems)
	}
	return nil
}

func (p Policy) imagePinned(r *Report) bool {
	for _, img := range p.Images {
		if contains([]string{img.RTMR1}, r.RTMR[1][:]) && contains([]string{img.RTMR2}, r.RTMR[2][:]) &&
			contains([]string{img.RTMR3}, r.RTMR[3][:]) {
			return true
		}
	}
	return false
}

func contains(list []string, value []byte) bool {
	for _, pinned := range list {
		if decoded, err := decodeHex(pinned, len(value)); err == nil && string(decoded) == string(value) {
			return true
		}
	}
	return false
}

func decodeHex(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("tdx: policy value %q is not %d hex bytes", s, size)
	}
	return b, nil
}

func pinnedRoots() (*x509.CertPool, error) {
	cert, err := teeverify.PinnedCert(rootCAPEM, rootCAFingerprint)
	if err != nil {
		return nil, fmt.Errorf("tdx: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}
