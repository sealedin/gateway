package enclave_test

// Reference vectors with openly committed key material; never reuse the seed outside tests.

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/enclave"
	"github.com/sealedin/gateway/internal/testvectors"
)

// demoSeed is the ed25519 seed every vector below derives from; its 32 ASCII bytes are the whole secret.
const demoSeed = testvectors.DemoSeed

func demoKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed([]byte(demoSeed))
	pub, ok := priv.Public().(ed25519.PublicKey)
	require.True(t, ok)
	return pub, priv
}

// demoBlockID is a recognizable non-zero stand-in for a real block id in the v2 report_data [0:32] half.
func demoBlockID() [enclave.BlockIDSize]byte {
	var id [enclave.BlockIDSize]byte
	for i := range id {
		id[i] = byte(i + 1)
	}
	return id
}

// demoQuote splices the v2 report_data into the golden quote, breaking the Intel signature; DCAP is a live-only check.
func demoQuote(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "attestation", "quote.hex"))
	require.NoError(t, err)
	quote, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	require.NoError(t, err)
	blockID := demoBlockID()
	copy(quote[reportDataOffset:], blockID[:])
	copy(quote[reportDataOffset+enclave.BlockIDSize:], pub)
	return quote
}

func TestDemoQuoteBindsKnownKey(t *testing.T) {
	t.Parallel()
	pub, _ := demoKey(t)
	quote := demoQuote(t, pub)

	blockID := demoBlockID()
	require.Equal(t, blockID[:], quote[reportDataOffset:reportDataOffset+enclave.BlockIDSize])
	require.Equal(t, []byte(pub), quote[reportDataOffset+enclave.BlockIDSize:reportDataOffset+reportDataLen])
}
