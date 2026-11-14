package near

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	reportPath    = "/v1/attestation/report"
	maxReport     = 1 << 20
	attestTimeout = time.Minute // dial, handshake, report and DCAP for one connection
)

// dialer opens connections that have attested themselves: the report is requested on the connection it vouches for,
// before any credential or prompt crosses it, and the quote must carry the key that connection presented. A second
// connection is never trusted on the evidence of the first, since it may end at another instance.
type dialer struct {
	verifier *Verifier
	roots    *x509.CertPool // nil means the system roots
	log      *slog.Logger
}

// DialTLS is an http.Transport's DialTLSContext. It speaks HTTP/1.1 only, so the report request can be written by hand
// and the transport then takes over the same connection.
func (d *dialer) DialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, attestTimeout)
	defer cancel()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, failed("dial", err)
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, failed("dial", err)
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: d.roots, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}})
	attested, err := d.attest(ctx, conn, host)
	if err != nil {
		_ = conn.Close()
		d.log.Warn("near: connection refused by attestation", "err", err)
		return nil, err
	}
	d.log.Info("near: connection attested", "app_id", attested.verified.AppID,
		"compose_hash", attested.verified.ComposeHash, "attest_ms", time.Since(start).Milliseconds())
	return attested, nil
}

func (d *dialer) attest(ctx context.Context, conn *tls.Conn, host string) (*attestedConn, error) {
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, failed("tls", err)
	}
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, failed("tls", err)
	}
	peerSPKI := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, failed("nonce", err)
	}
	reader := bufio.NewReader(conn)
	report, err := fetchReport(ctx, conn, reader, host, nonce)
	if err != nil {
		return nil, failed("report", err)
	}
	verified, err := d.verifier.Verify(ctx, report, nonce, peerSPKI)
	if err != nil {
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, failed("tls", err)
	}
	return &attestedConn{Conn: conn, reader: reader, verified: verified}, nil
}

// fetchReport asks for the gateway report with no API key. Errors name no URL: its query is the nonce.
func fetchReport(ctx context.Context, conn net.Conn, reader *bufio.Reader, host string, nonce [NonceSize]byte) ([]byte, error) {
	query := url.Values{"signing_algo": {"ecdsa"}, "include_tls_fingerprint": {"true"}, "nonce": {hex.EncodeToString(nonce[:])}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+reportPath+"?"+query.Encode(), http.NoBody)
	if err != nil {
		return nil, errors.New("request")
	}
	req.Header.Set("Accept", "application/json")
	if err = req.Write(conn); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReport+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("read: %w", err)
	case len(body) > maxReport:
		return nil, fmt.Errorf("report exceeds %d bytes", maxReport)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	case resp.Close || reader.Buffered() != 0:
		return nil, errors.New("the gateway did not keep the attested connection open")
	}
	return body, nil
}

// attestedConn hands the transport the connection the report was read from, through the same buffered reader.
type attestedConn struct {
	net.Conn

	reader   *bufio.Reader
	verified *Verified
}

func (c *attestedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
