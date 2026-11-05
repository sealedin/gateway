// Package teeverify holds what the TDX and GPU verifiers share: the pinned trust anchors.
package teeverify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// PinnedCert parses an embedded PEM root and refuses it unless its SHA-256 fingerprint is the pinned one, so a
// swapped embed cannot widen the trust root unnoticed.
func PinnedCert(pemBytes []byte, fingerprintHex string) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("embedded root CA is not PEM")
	}
	fp := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(fp[:]); got != fingerprintHex {
		return nil, fmt.Errorf("embedded root CA fingerprint %s does not match the pin", got)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("embedded root CA: %w", err)
	}
	return cert, nil
}
