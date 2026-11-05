package enclave

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

func ParseBlockID(raw string) ([BlockIDSize]byte, bool, error) {
	return parseBlockID(raw)
}

func ReportDataFor(blockID [BlockIDSize]byte, pub ed25519.PublicKey) [ReportDataSize]byte {
	return reportDataFor(blockID, pub)
}

// NewTestIdentity builds an attested-looking identity whose quote fetches run the given fake.
func NewTestIdentity(fetch func([ReportDataSize]byte) ([]byte, error)) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclave: generate key: %w", err)
	}
	wrapped := func(rd [ReportDataSize]byte) (evidence, error) {
		quote, fetchErr := fetch(rd)
		return evidence{quote: quote}, fetchErr
	}
	id := &Identity{pub: pub, priv: priv, fetch: wrapped, slot: make(chan struct{}, 1)}
	id.quote, err = fetch(reportDataFor([BlockIDSize]byte{}, pub))
	if err != nil {
		return nil, err
	}
	return id, nil
}

// FetchEvidenceDstack exposes the guest-agent client for tests against a fake agent socket.
func FetchEvidenceDstack(socket string, reportData [ReportDataSize]byte) ([]byte, []byte, error) {
	ev, err := fetchEvidenceDstack(socket, reportData)
	return ev.quote, ev.eventLog, err
}

// FetchEvidenceFrom runs the host dispatcher with the dstack socket path pointed at socket.
func FetchEvidenceFrom(socket string, reportData [ReportDataSize]byte) ([]byte, []byte, error) {
	ev, err := fetchEvidenceFrom(socket, reportData)
	return ev.quote, ev.eventLog, err
}

// NewTestIdentityWithEventLog is NewTestIdentity for a host that also serves a boot event log.
func NewTestIdentityWithEventLog(fetch func([ReportDataSize]byte) ([]byte, error), eventLog []byte) (*Identity, error) {
	id, err := NewTestIdentity(fetch)
	if err != nil {
		return nil, err
	}
	id.eventLog = eventLog
	return id, nil
}

// DeriveKeyFrom runs the key derivation against a fake agent socket.
func DeriveKeyFrom(socket, path, purpose string) ([KeySize]byte, error) {
	return deriveKeyFrom(context.Background(), socket, path, purpose)
}
