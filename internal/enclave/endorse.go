package enclave

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	endorseDomain   = "sealedin-tls-endorsement-v1" // wire-format tag; bump on any post-ship layout change
	edgeDialTimeout = 5 * time.Second
	notAfterLen     = 8 // unix seconds, big-endian
)

// Endorsement says the in-TD edge presents this TLS leaf; a wire contract, worthless until the client ties the key
// to the workload (quote + RTMR3). No freshness field: both keys are RAM-only, so a live :443 handshake is the proof.
type Endorsement struct {
	SPKISHA256 [sha256.Size]byte
	NotAfter   time.Time
}

// Message is the signed byte string: tag, NUL, SPKI digest (32B), not-after (8B big-endian).
func (e Endorsement) Message() []byte {
	msg := make([]byte, 0, len(endorseDomain)+1+sha256.Size+notAfterLen)
	msg = append(msg, endorseDomain...)
	msg = append(msg, 0)
	msg = append(msg, e.SPKISHA256[:]...)
	//nolint:gosec // not-after is never negative
	msg = binary.BigEndian.AppendUint64(msg, uint64(e.NotAfter.Unix()))
	return msg
}

// Endorse signs the endorsement with the enclave key.
func (id *Identity) Endorse(e Endorsement) []byte {
	return ed25519.Sign(id.priv, e.Message())
}

// CertSource returns the TLS leaf certificate the edge currently presents.
type CertSource func(ctx context.Context) (*x509.Certificate, error)

// Cached keeps the leaf for ttl so a /v1/tls storm cannot amplify into edge handshakes; errors are not cached.
func Cached(source CertSource, ttl time.Duration) CertSource {
	var (
		mu        sync.Mutex
		leaf      *x509.Certificate
		fetchedAt time.Time
	)
	return func(ctx context.Context) (*x509.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		if leaf != nil && time.Since(fetchedAt) < ttl {
			return leaf, nil
		}
		fresh, err := source(ctx)
		if err != nil {
			return nil, err
		}
		leaf, fetchedAt = fresh, time.Now()
		return leaf, nil
	}
}

// EdgeCert returns the leaf the edge at addr presents; verification is off because we endorse what we observe.
func EdgeCert(addr, serverName string) CertSource {
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // endorsing the observed cert, not trusting the channel
		MinVersion:         tls.VersionTLS12,
	}}
	return func(ctx context.Context) (*x509.Certificate, error) {
		ctx, cancel := context.WithTimeout(ctx, edgeDialTimeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dial edge %s: %w", addr, err)
		}
		defer func() { _ = conn.Close() }()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			return nil, fmt.Errorf("dial edge %s: unexpected connection type %T", addr, conn)
		}
		peers := tlsConn.ConnectionState().PeerCertificates
		if len(peers) == 0 {
			return nil, fmt.Errorf("edge %s presented no certificate", addr)
		}
		return peers[0], nil
	}
}
