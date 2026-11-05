package teeverify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/teeverify"
)

func TestPinnedCert(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1)},
		&x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	sum := sha256.Sum256(der)
	pin := hex.EncodeToString(sum[:])
	garbage := []byte("not a certificate")
	garbageSum := sha256.Sum256(garbage)

	tests := []struct {
		name    string
		pem     []byte
		pin     string
		wantErr string
	}{
		{"pinned", pemBytes, pin, ""},
		{"wrong pin", pemBytes, "00" + pin[2:], "does not match the pin"},
		{"not PEM", []byte("junk"), pin, "not PEM"},
		{"pinned garbage", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: garbage}),
			hex.EncodeToString(garbageSum[:]), "embedded root CA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert, pinErr := teeverify.PinnedCert(tc.pem, tc.pin)
			if tc.wantErr != "" {
				require.ErrorContains(t, pinErr, tc.wantErr)
				return
			}
			require.NoError(t, pinErr)
			require.Equal(t, der, cert.Raw)
		})
	}
}
