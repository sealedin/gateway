// Package near forwards OpenAI-compatible requests to the NEAR AI Cloud gateway over TLS connections it has attested:
// each connection proves, on itself, that it ends inside a TDX guest the policy accepts. The attestation covers the
// provider's gateway (a router), not the model instance behind it.
package near

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	"github.com/sealedin/gateway/internal/teeverify/tdx"
)

const (
	appIDSize   = 20
	sha256Size  = 32
	attrHexSize = 8
)

// Policy pins what the provider's gateway guest may be. Guests and the two attribute fields pin the guest OS, which is
// what makes the RTMR3 event log trustworthy; the app id and key provider pin whose releases it runs.
type Policy struct {
	API          string  `yaml:"api"`
	Guests       []Guest `yaml:"guests"`
	TDAttributes string  `yaml:"td_attributes"`
	XFAM         string  `yaml:"xfam"`
	// AppIDs are the accepted app-id events, KeyProviders the accepted key-provider events (hex of the payload).
	AppIDs       []string `yaml:"app_ids"`
	KeyProviders []string `yaml:"key_providers"`
	// ComposeHashes, when set, accepts only these builds. Empty accepts any build the key provider released keys to
	// under the app id, so the provider's own release governance decides and no upgrade of theirs needs one of ours.
	ComposeHashes []string `yaml:"compose_hashes"`
}

// Guest is one guest OS image on one VM shape: firmware, then RTMR0-2 (hardware configuration, kernel, command line
// and initramfs), hex-encoded.
type Guest struct {
	MRTD  string `yaml:"mrtd"`
	RTMR0 string `yaml:"rtmr0"`
	RTMR1 string `yaml:"rtmr1"`
	RTMR2 string `yaml:"rtmr2"`
}

// Validate rejects a policy that could never pin anything.
func (p Policy) Validate() error {
	u, err := url.Parse(p.API)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.String() != "https://"+u.Host {
		return fmt.Errorf("near: policy api %q must be a bare https origin", p.API)
	}
	if len(p.Guests) == 0 || len(p.AppIDs) == 0 || len(p.KeyProviders) == 0 {
		return errors.New("near: policy must pin at least one guest, one app id and one key provider")
	}
	for _, g := range p.Guests {
		if err = hexOfSize(tdx.MeasurementSize, g.MRTD, g.RTMR0, g.RTMR1, g.RTMR2); err != nil {
			return err
		}
	}
	if err = hexOfSize(attrHexSize, p.TDAttributes, p.XFAM); err != nil {
		return err
	}
	if err = hexOfSize(appIDSize, p.AppIDs...); err != nil {
		return err
	}
	if err = hexOfSize(sha256Size, p.ComposeHashes...); err != nil {
		return err
	}
	for _, k := range p.KeyProviders {
		if raw, decodeErr := hex.DecodeString(k); decodeErr != nil || len(raw) == 0 {
			return fmt.Errorf("near: policy key provider %q is not hex", k)
		}
	}
	return nil
}

func hexOfSize(size int, values ...string) error {
	for _, v := range values {
		if raw, err := hex.DecodeString(v); err != nil || len(raw) != size {
			return fmt.Errorf("near: policy value %q is not %d hex bytes", v, size)
		}
	}
	return nil
}

// guestPinned reports whether the report's firmware and RTMR0-2 are one of the pinned guests, as a whole tuple.
func (p Policy) guestPinned(r *tdx.Report) bool {
	for _, g := range p.Guests {
		if g.MRTD == hex.EncodeToString(r.MRTD[:]) && g.RTMR0 == hex.EncodeToString(r.RTMR[0][:]) &&
			g.RTMR1 == hex.EncodeToString(r.RTMR[1][:]) && g.RTMR2 == hex.EncodeToString(r.RTMR[2][:]) {
			return true
		}
	}
	return false
}
