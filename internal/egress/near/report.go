package near

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sealedin/gateway/internal/teeverify/tdx"
)

const (
	// NonceSize is the client nonce the quote must carry in REPORT_DATA[32:64].
	NonceSize = 32

	runtimeRegister  = 3 // RTMR3, the register the guest OS extends with the events below
	eventAppID       = "app-id"
	eventComposeHash = "compose-hash"
	eventKeyProvider = "key-provider"
	// A dstack guest launches with MRCONFIGID = 0x01 || compose hash || zeros.
	configIDVersion = 0x01
)

// ErrBinding is returned when the quote does not carry our nonce or the key of the connection it arrived on.
var ErrBinding = errors.New("near: attestation binding mismatch")

// CheckError names the verification step that refused a report, for the log.
type CheckError struct {
	Check string
	Err   error
}

func (e *CheckError) Error() string { return "near: " + e.Check + ": " + e.Err.Error() }

// Unwrap exposes the cause.
func (e *CheckError) Unwrap() error { return e.Err }

func failed(check string, err error) error { return &CheckError{Check: check, Err: err} }

// QuoteVerifier is the DCAP step; tdx.Verifier in production.
type QuoteVerifier interface {
	Verify(ctx context.Context, raw []byte) (*tdx.Report, error)
}

// Verified is what a passing report established about the peer.
type Verified struct {
	AppID       string
	ComposeHash string
}

// Verifier checks one attestation report against the policy.
type Verifier struct {
	TDX    QuoteVerifier
	Policy Policy
}

type reportBody struct {
	Gateway struct {
		SigningAddress string `json:"signing_address"`
		IntelQuote     string `json:"intel_quote"`
		EventLog       string `json:"event_log"`
	} `json:"gateway_attestation"`
}

type event struct {
	Register int    `json:"imr"`
	Type     uint32 `json:"event_type"`
	Name     string `json:"event"`
	Payload  string `json:"event_payload"`
}

// Verify accepts raw only if its quote is Intel-signed with a current TCB, comes from a pinned guest, carries nonce and
// SHA256(signing address || peerSPKI) in REPORT_DATA, and its replayed event log names a pinned app and key provider.
// Nothing the report merely echoes is trusted: every checked value is read from the verified quote or recomputed.
func (v *Verifier) Verify(ctx context.Context, raw []byte, nonce [NonceSize]byte, peerSPKI [sha256Size]byte) (*Verified, error) {
	var body reportBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, failed("report_format", errors.New("not the expected JSON"))
	}
	quote, err := hex.DecodeString(body.Gateway.IntelQuote)
	if err != nil || len(quote) == 0 {
		return nil, failed("report_format", errors.New("quote is not hex"))
	}
	report, err := v.TDX.Verify(ctx, quote)
	if err != nil {
		return nil, failed("dcap", err)
	}
	if err = v.checkBinding(report, body.Gateway.SigningAddress, nonce, peerSPKI); err != nil {
		return nil, err
	}
	if !v.Policy.guestPinned(report) || v.Policy.TDAttributes != hex.EncodeToString(report.TDAttributes[:]) ||
		v.Policy.XFAM != hex.EncodeToString(report.XFAM[:]) {
		return nil, failed("guest", fmt.Errorf("%w: mrtd %x rtmr0 %x rtmr1 %x rtmr2 %x td_attributes %x xfam %x",
			tdx.ErrUnpinnedMeasurement, report.MRTD, report.RTMR[0], report.RTMR[1], report.RTMR[2],
			report.TDAttributes, report.XFAM))
	}
	events, err := replay(body.Gateway.EventLog, report)
	if err != nil {
		return nil, failed("event_log", err)
	}
	return v.checkWorkload(events, report)
}

func (v *Verifier) checkBinding(report *tdx.Report, signer string, nonce [NonceSize]byte, peerSPKI [sha256Size]byte) error {
	if subtle.ConstantTimeCompare(report.ReportData[sha256Size:], nonce[:]) != 1 {
		return failed("nonce", fmt.Errorf("%w: REPORT_DATA[32:64] is not our nonce", ErrBinding))
	}
	address, err := hex.DecodeString(strings.TrimPrefix(signer, "0x"))
	if err != nil || len(address) != appIDSize {
		return failed("report_format", errors.New("signing address is not 20 hex bytes"))
	}
	want := sha256.Sum256(append(address, peerSPKI[:]...))
	if subtle.ConstantTimeCompare(report.ReportData[:sha256Size], want[:]) != 1 {
		return failed("tls_key_binding",
			fmt.Errorf("%w: REPORT_DATA[0:32] is not SHA256(signing address || this connection's key)", ErrBinding))
	}
	return nil
}

func (v *Verifier) checkWorkload(events map[string]string, report *tdx.Report) (*Verified, error) {
	appID, compose, provider := events[eventAppID], events[eventComposeHash], events[eventKeyProvider]
	wantConfig := make([]byte, tdx.MeasurementSize)
	wantConfig[0] = configIDVersion
	if n, err := hex.Decode(wantConfig[1:], []byte(compose)); err != nil || n != sha256Size ||
		subtle.ConstantTimeCompare(wantConfig, report.MRConfigID[:]) != 1 {
		return nil, failed("compose_hash", fmt.Errorf("%w: compose-hash event %q is not the one in MRCONFIGID %x",
			ErrBinding, compose, report.MRConfigID))
	}
	if !slices.Contains(v.Policy.AppIDs, appID) {
		return nil, failed("app_id", fmt.Errorf("%w: app id %q", tdx.ErrUnpinnedMeasurement, appID))
	}
	if !slices.Contains(v.Policy.KeyProviders, provider) {
		return nil, failed("key_provider", fmt.Errorf("%w: key provider %q", tdx.ErrUnpinnedMeasurement, provider))
	}
	if len(v.Policy.ComposeHashes) > 0 && !slices.Contains(v.Policy.ComposeHashes, compose) {
		return nil, failed("compose_hash", fmt.Errorf("%w: compose hash %q", tdx.ErrUnpinnedMeasurement, compose))
	}
	return &Verified{AppID: appID, ComposeHash: compose}, nil
}

// replay recomputes each RTMR3 event's digest from its fields, so a payload cannot be rewritten under a genuine digest,
// folds them from 48 zero bytes and requires the quoted register. It returns the payloads by event name; a name the
// policy reads may appear only once, since a second one would make which is meant a choice of the reader.
func replay(log string, report *tdx.Report) (map[string]string, error) {
	var entries []event
	if err := json.Unmarshal([]byte(log), &entries); err != nil {
		return nil, errors.New("event log is not the expected JSON")
	}
	var register [tdx.MeasurementSize]byte
	events := map[string]string{}
	for _, e := range entries {
		if e.Register != runtimeRegister {
			continue
		}
		payload, err := hex.DecodeString(e.Payload)
		if err != nil {
			return nil, fmt.Errorf("event %q payload is not hex", e.Name)
		}
		if _, seen := events[e.Name]; seen && (e.Name == eventAppID || e.Name == eventComposeHash || e.Name == eventKeyProvider) {
			return nil, fmt.Errorf("event %q appears more than once", e.Name)
		}
		events[e.Name] = e.Payload
		digest := sha512.New384()
		_ = binary.Write(digest, binary.LittleEndian, e.Type)
		digest.Write([]byte(":" + e.Name + ":"))
		digest.Write(payload)
		register = sha512.Sum384(digest.Sum(register[:]))
	}
	if subtle.ConstantTimeCompare(register[:], report.RTMR[runtimeRegister][:]) != 1 {
		return nil, fmt.Errorf("%w: replayed event log is not the quoted RTMR3", ErrBinding)
	}
	return events, nil
}
