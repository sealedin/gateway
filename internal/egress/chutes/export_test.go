package chutes

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/sealedin/gateway/internal/teeverify/nvidia"
)

// DeriveKey exposes the HKDF step so tests can play the instance side.
func DeriveKey(shared, ct []byte, info string) []byte { return deriveKey(shared, ct, info) }

// SealChaCha produces nonce || ciphertext || tag as the chute does, with a fresh random nonce.
func SealChaCha(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(key)
	require.NoError(t, err)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	return aead.Seal(nonce, nonce, plaintext, nil)
}

// OpenChaCha opens nonce || ciphertext || tag.
func OpenChaCha(key, frame []byte) ([]byte, error) { return openChaCha(key, frame) }

// SetCatalogClock pins the catalog's clock.
func SetCatalogClock(c *Catalog, now func() time.Time) { c.now = now }

// SetClock pins the attester's clock.
func SetClock(a *Attester, now func() time.Time) { a.now = now }

// SetGetter replaces the attester's HTTP GET with a stub.
func SetGetter(a *Attester, get func(ctx context.Context, url, apiKey string) ([]byte, error)) {
	a.get = get
}

// CheckGPUs exposes the GPU step for live vectors, which lack the E2EE key the full Verify binds to.
func (v *Verifier) CheckGPUs(ctx context.Context, ev Evidence, nonce [nonceByteLen]byte) (*nvidia.Verdict, error) {
	return v.checkGPUs(ctx, ev, nonce)
}
