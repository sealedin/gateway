package enclave_test

import (
	"context"
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/enclave"
	"github.com/sealedin/gateway/internal/testvectors"
)

// The test environment has no TDX, so every identity here is unattested; attested paths run on TDX hosts only.

func TestNewIdentityUnattested(t *testing.T) {
	t.Parallel()
	id, err := enclave.NewIdentity()
	require.NoError(t, err)
	require.Len(t, id.PublicKey(), 32)
	require.Len(t, id.PublicKeyHex(), 64)
	require.False(t, id.Attested())
	_, err = id.StartupQuote()
	require.ErrorIs(t, err, enclave.ErrNotAttested)
	_, err = id.QuoteFor(context.Background(), [enclave.BlockIDSize]byte{1})
	require.ErrorIs(t, err, enclave.ErrNotAttested)

	second, err := enclave.NewIdentity()
	require.NoError(t, err)
	require.NotEqual(t, id.PublicKey(), second.PublicKey(), "every start generates a fresh key")
	leaked := id.PublicKey()
	clear(leaked)
	require.NotEqual(t, leaked, id.PublicKey(), "mutating the returned key must not affect the identity")
}

func TestReportDataLayout(t *testing.T) {
	t.Parallel()

	var blockID [enclave.BlockIDSize]byte
	for i := range blockID {
		blockID[i] = byte(i)
	}
	pub := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	for i := range pub {
		pub[i] = byte(0xff - i)
	}

	reportData := enclave.ReportDataFor(blockID, pub)

	require.Equal(t, blockID[:], reportData[:32])
	require.Equal(t, []byte(pub), reportData[32:])
}

// fakeFetch returns the report data it was handed as the "quote", so tests can read the binding back.
func fakeFetch(reportData [enclave.ReportDataSize]byte) ([]byte, error) {
	return reportData[:], nil
}

func TestQuoteForBindsBlockIDAndPubkey(t *testing.T) {
	t.Parallel()
	id, err := enclave.NewTestIdentity(fakeFetch)
	require.NoError(t, err)
	blockID := [enclave.BlockIDSize]byte{0: 0xaa, 31: 0xbb}

	quote, err := id.QuoteFor(context.Background(), blockID)
	require.NoError(t, err)

	require.Len(t, quote, enclave.ReportDataSize)
	require.Equal(t, blockID[:], quote[:enclave.BlockIDSize])
	require.Equal(t, []byte(id.PublicKey()), quote[enclave.BlockIDSize:])
}

func TestQuoteForSerializesFetches(t *testing.T) {
	t.Parallel()
	var inFlight, overlapped atomic.Int32
	id, err := enclave.NewTestIdentity(func(reportData [enclave.ReportDataSize]byte) ([]byte, error) {
		if inFlight.Add(1) > 1 {
			overlapped.Add(1)
		}
		time.Sleep(2 * time.Millisecond)
		inFlight.Add(-1)
		return reportData[:], nil
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			_, quoteErr := id.QuoteFor(context.Background(), [enclave.BlockIDSize]byte{byte(i)})
			assert.NoError(t, quoteErr)
		})
	}
	wg.Wait()

	require.Zero(t, overlapped.Load(), "quote fetches must never overlap")
}

func TestQuoteForBusySlotHonorsContext(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	// Armed only after the startup fetch, or the busy goroutine would slip through before the test listens.
	var armed atomic.Bool
	id, err := enclave.NewTestIdentity(func(reportData [enclave.ReportDataSize]byte) ([]byte, error) {
		if armed.Load() {
			entered <- struct{}{}
			<-release
		}
		return reportData[:], nil
	})
	require.NoError(t, err)
	defer close(release)
	armed.Store(true)

	go func() { _, _ = id.QuoteFor(context.Background(), [enclave.BlockIDSize]byte{1}) }()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = id.QuoteFor(ctx, [enclave.BlockIDSize]byte{2})

	require.ErrorIs(t, err, enclave.ErrQuoteUnavailable)
}

func TestQuoteForHostRefusalIsBreakageNotDevMode(t *testing.T) {
	t.Parallel()
	calls := 0
	id, err := enclave.NewTestIdentity(func(reportData [enclave.ReportDataSize]byte) ([]byte, error) {
		calls++
		if calls > 1 { // startup succeeds, every later fetch is refused
			return nil, enclave.ErrNotAttested
		}
		return reportData[:], nil
	})
	require.NoError(t, err)

	_, err = id.QuoteFor(context.Background(), [enclave.BlockIDSize]byte{1})

	require.ErrorIs(t, err, enclave.ErrAttestationBroken)
	require.NotErrorIs(t, err, enclave.ErrNotAttested, "runtime breakage must never read as dev mode")
}

// The dev seed lets an unattested identity reuse the fixture key; a wrong-sized seed is an error, not a random key.
func TestNewIdentityDevSeed(t *testing.T) {
	tests := []struct {
		name, seed, wantKey string
		wantErr             bool
	}{
		{"demo seed", testvectors.DemoSeed, testvectors.DemoPublicKeyHex, false},
		{"wrong size", "too-short", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SEALEDIN_ENCLAVE_SEED", tc.seed)
			id, err := enclave.NewIdentity()
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantKey, id.PublicKeyHex())
			require.False(t, id.Attested())
		})
	}
}
