package enclave_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/enclave"
)

func newLeafCert(t *testing.T, notAfter time.Time) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func staticCert(cert *x509.Certificate) enclave.CertSource {
	return func(context.Context) (*x509.Certificate, error) { return cert, nil }
}

func TestEndorse(t *testing.T) {
	t.Parallel()
	id, err := enclave.NewIdentity()
	require.NoError(t, err)
	endorsement := enclave.Endorsement{SPKISHA256: sha256.Sum256([]byte("spki")), NotAfter: time.Unix(1800000000, 0)}

	msg := endorsement.Message()
	require.True(t, strings.HasPrefix(string(msg), "sealedin-tls-endorsement-v1\x00"))
	require.Len(t, msg, len("sealedin-tls-endorsement-v1")+1+32+8, "tag, NUL, spki(32), not_after(8)")

	sig := id.Endorse(endorsement)
	require.True(t, ed25519.Verify(id.PublicKey(), msg, sig))
	tampered := endorsement
	tampered.NotAfter = tampered.NotAfter.Add(time.Second)
	require.False(t, ed25519.Verify(id.PublicKey(), tampered.Message(), sig))
}

func TestEdgeCert(t *testing.T) {
	t.Parallel()
	t.Run("fetches the leaf", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(srv.Close)
		leaf, err := enclave.EdgeCert(strings.TrimPrefix(srv.URL, "https://"), "")(t.Context())
		require.NoError(t, err)
		require.Equal(t, srv.TLS.Certificates[0].Leaf.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo)
	})
	t.Run("unreachable", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, err := enclave.EdgeCert("127.0.0.1:1", "")(ctx)
		require.Error(t, err)
	})
}

func TestCached(t *testing.T) {
	t.Parallel()
	t.Run("dedupes within the ttl", func(t *testing.T) {
		t.Parallel()
		cert := newLeafCert(t, time.Unix(1800000000, 0))
		calls := 0
		source := enclave.Cached(func(context.Context) (*x509.Certificate, error) { calls++; return cert, nil }, time.Hour)
		for range 3 {
			leaf, err := source(t.Context())
			require.NoError(t, err)
			require.Same(t, cert, leaf)
		}
		require.Equal(t, 1, calls)
	})
	t.Run("does not cache errors", func(t *testing.T) {
		t.Parallel()
		calls := 0
		source := enclave.Cached(func(context.Context) (*x509.Certificate, error) {
			calls++
			return nil, errors.New("edge down")
		}, time.Hour)
		for range 2 {
			_, err := source(t.Context())
			require.Error(t, err)
		}
		require.Equal(t, 2, calls)
	})
}

func TestTLSEndpoint(t *testing.T) {
	t.Parallel()
	notAfter := time.Unix(1800000000, 0)
	cert := newLeafCert(t, notAfter)
	id, err := enclave.NewIdentity()
	require.NoError(t, err)
	srv := serve(t, id, staticCert(cert))

	status, got := getJSON(t, srv.URL+"/v1/tls")
	require.Equal(t, http.StatusOK, status)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	require.Equal(t, hex.EncodeToString(spki[:]), got.str(t, "spki_sha256"))
	require.InDelta(t, float64(notAfter.Unix()), got.num(t, "not_after"), 0)
	require.Equal(t, id.PublicKeyHex(), got.str(t, "pubkey"))
	sig, err := hex.DecodeString(got.str(t, "signature"))
	require.NoError(t, err)
	require.True(t, ed25519.Verify(id.PublicKey(), enclave.Endorsement{SPKISHA256: spki, NotAfter: notAfter}.Message(), sig))
}

func TestTLSEndpointEdgeUnavailable(t *testing.T) {
	t.Parallel()
	failing := func(context.Context) (*x509.Certificate, error) { return nil, errors.New("dial refused") }
	for name, source := range map[string]enclave.CertSource{"failing source": failing, "nil source": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			id, err := enclave.NewIdentity()
			require.NoError(t, err)
			status, got := getJSON(t, serve(t, id, source).URL+"/v1/tls")
			require.Equal(t, http.StatusServiceUnavailable, status)
			require.Contains(t, got.str(t, "error"), "edge certificate unavailable")
		})
	}
}
