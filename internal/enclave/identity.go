// Package enclave is the gateway's ephemeral identity: an Ed25519 key generated at start and, in a TD, quoted.
// It signs the TLS endorsement (endorse.go) and the catalog (catalog.go), whose preimages those files document byte for byte.
package enclave

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
)

// ErrNotAttested is returned when attestation artifacts are requested outside a TEE.
var ErrNotAttested = errors.New("enclave: not running in a TEE")

// ErrQuoteUnavailable is returned when a fresh quote cannot be produced right now (slot busy or agent failure).
var ErrQuoteUnavailable = errors.New("enclave: fresh quote unavailable")

// ErrAttestationBroken is returned when the TEE stops quoting after an attested start: never dev mode.
var ErrAttestationBroken = errors.New("enclave: TEE stopped quoting after attested start")

const (
	// BlockIDSize is the byte length of the block id bound into REPORT_DATA[0:32].
	BlockIDSize = 32
	// ReportDataSize is the full REPORT_DATA width: block id then pubkey.
	ReportDataSize = 64
)

// Identity is the gateway's ephemeral identity: a fresh key every start, never leaving the process.
type Identity struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	quote    []byte // startup quote (zero block id); nil outside a TEE
	eventLog []byte // boot event log for RTMR3 replay; nil only when unattested
	fetch    func([ReportDataSize]byte) (evidence, error)
	slot     chan struct{} // capacity 1: one quote round trip in flight
}

// reportDataFor is the v2 REPORT_DATA layout: a caller-supplied block id (freshness), then the pubkey.
func reportDataFor(blockID [BlockIDSize]byte, pub ed25519.PublicKey) [ReportDataSize]byte {
	var reportData [ReportDataSize]byte
	copy(reportData[:BlockIDSize], blockID[:])
	copy(reportData[BlockIDSize:], pub)
	return reportData
}

// NewIdentity generates the key and, in a TEE, the startup quote; off-TEE it runs unattested, a failing TEE is fatal.
func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclave: generate key: %w", err)
	}
	id := &Identity{pub: pub, priv: priv, fetch: fetchEvidence, slot: make(chan struct{}, 1)}

	ev, err := id.fetch(reportDataFor([BlockIDSize]byte{}, pub))
	switch {
	case err == nil:
		id.quote = ev.quote
		id.eventLog = ev.eventLog
	case errors.Is(err, ErrNotAttested):
		if devErr := id.applyDevSeed(); devErr != nil {
			return nil, devErr
		}
	default:
		return nil, fmt.Errorf("enclave: fetch quote: %w", err)
	}
	return id, nil
}

// applyDevSeed gives an unattested dev identity a fixed key from SEALEDIN_ENCLAVE_SEED so fixture signatures match; it runs
// off-TEE only and the seed is never set in a measured deployment.
func (id *Identity) applyDevSeed() error {
	seed := os.Getenv("SEALEDIN_ENCLAVE_SEED")
	if seed == "" {
		slog.Info("enclave: no TEE detected, running unattested")
		return nil
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("enclave: SEALEDIN_ENCLAVE_SEED must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed([]byte(seed))
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("enclave: derived dev key is not Ed25519")
	}
	id.priv = priv
	id.pub = pub
	slog.Warn("enclave: DEV key from SEALEDIN_ENCLAVE_SEED, NOT attested; never set this in production")
	return nil
}

// PublicKey returns a copy of the raw 32-byte Ed25519 public key.
func (id *Identity) PublicKey() ed25519.PublicKey {
	return slices.Clone(id.pub)
}

// PublicKeyHex returns the hex-encoded public key.
func (id *Identity) PublicKeyHex() string {
	return hex.EncodeToString(id.pub)
}

// Attested reports whether the identity carries a DCAP quote.
func (id *Identity) Attested() bool {
	return id.quote != nil
}

// EventLog is the boot event log for RTMR3 replay, nil only when unattested; dstack writes it before the app starts,
// so one copy fits every quote.
func (id *Identity) EventLog() []byte {
	return slices.Clone(id.eventLog)
}

// StartupQuote returns a copy of the startup DCAP quote (zero block id), or ErrNotAttested outside a TEE.
func (id *Identity) StartupQuote() ([]byte, error) {
	if id.quote == nil {
		return nil, ErrNotAttested
	}
	return slices.Clone(id.quote), nil
}

// QuoteFor fetches a fresh quote binding blockID. One fetch in flight at a time, bounded by ctx, so an unauthenticated
// flood cannot queue work against the host; an overrunning fetch finishes in the background still holding the slot.
func (id *Identity) QuoteFor(ctx context.Context, blockID [BlockIDSize]byte) ([]byte, error) {
	if id.quote == nil {
		return nil, ErrNotAttested
	}
	select {
	case id.slot <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: waiting for the quote slot: %w", ErrQuoteUnavailable, ctx.Err())
	}
	type result struct {
		quote []byte
		err   error
	}
	res := make(chan result, 1)
	go func() {
		defer func() { <-id.slot }()
		ev, err := id.fetch(reportDataFor(blockID, id.pub))
		res <- result{quote: ev.quote, err: err}
	}()
	select {
	case r := <-res:
		switch {
		case errors.Is(r.err, ErrNotAttested):
			// The host quoted at startup and refuses now: breakage, not dev mode (writeError must not see a 404).
			return nil, fmt.Errorf("%w: quote path rejected the request", ErrAttestationBroken)
		case r.err != nil:
			return nil, fmt.Errorf("%w: %w", ErrQuoteUnavailable, r.err)
		}
		return r.quote, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrQuoteUnavailable, ctx.Err())
	}
}
