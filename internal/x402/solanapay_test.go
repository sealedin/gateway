package x402_test

import (
	"crypto/sha256"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402client"
	"github.com/sealedin/gateway/internal/x402/x402test"
)

const twentyFive = 25_000_000

func spec(w *x402test.World, reference solana.PublicKey) x402client.SolanaPayTransfer {
	return x402client.SolanaPayTransfer{Payer: w.Payer, Treasury: w.Treasury, Mint: w.Policy.Mint, Amount: twentyFive,
		Reference: reference, Blockhash: solana.Hash{1}}
}

func idOf(t *testing.T, raw []byte) solana.Signature {
	t.Helper()
	tx, err := solana.TransactionFromBytes(raw)
	require.NoError(t, err)
	return tx.Signatures[0]
}

func TestClaimCodeOpensItsReference(t *testing.T) {
	t.Parallel()
	code := make([]byte, x402.ClaimCodeBytes)
	code[0] = 7
	got, err := x402.ParseClaimCode(base58.Encode(code))
	require.NoError(t, err)
	want := sha256.Sum256(append([]byte("sealedin-pay-reference-v1\x00"), code...))
	require.Equal(t, solana.PublicKeyFromBytes(want[:]), got)
	for _, bad := range []string{"", "0OIl", base58.Encode(code[:31]), base58.Encode(make([]byte, x402.ClaimCodeBytes+1))} {
		_, err = x402.ParseClaimCode(bad)
		require.ErrorIs(t, err, x402.ErrBadClaimCode)
	}
}

func TestReferenceAmountReadsWhatWalletsSend(t *testing.T) {
	t.Parallel()
	w := x402test.NewWorld(t)
	reference := x402test.Public(x402test.NewKey(t))
	for name, plain := range map[string]bool{"checked": false, "plain": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			transfer := spec(w, reference)
			transfer.Plain = plain
			raw, err := transfer.Build()
			require.NoError(t, err)
			got, err := w.Policy.ReferenceAmount(raw, idOf(t, raw), reference)
			require.NoError(t, err)
			require.Equal(t, uint64(twentyFive), got)
		})
	}
}

// Everything here is a real, signed transaction that must read as paying nothing, or as no transaction at all.
func TestReferenceAmountRefuses(t *testing.T) {
	t.Parallel()
	w := x402test.NewWorld(t)
	reference := x402test.Public(x402test.NewKey(t))
	other := x402test.Public(x402test.NewKey(t))
	tests := []struct {
		name   string
		mutate func(*x402client.SolanaPayTransfer)
	}{
		{"another reference", func(p *x402client.SolanaPayTransfer) { p.Reference = other }},
		{"another treasury", func(p *x402client.SolanaPayTransfer) { p.Treasury = other }},
		{"another mint, checked", func(p *x402client.SolanaPayTransfer) { p.Mint = other }},
		{"another mint, plain, so another account", func(p *x402client.SolanaPayTransfer) { p.Mint = other; p.Plain = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			transfer := spec(w, reference)
			tt.mutate(&transfer)
			raw, err := transfer.Build()
			require.NoError(t, err)
			got, err := w.Policy.ReferenceAmount(raw, idOf(t, raw), reference)
			require.NoError(t, err)
			require.Zero(t, got)
		})
	}
	t.Run("a reference that signs", func(t *testing.T) {
		t.Parallel()
		transfer := spec(w, x402test.Public(w.Payer))
		raw, err := transfer.Build()
		require.NoError(t, err)
		got, err := w.Policy.ReferenceAmount(raw, idOf(t, raw), x402test.Public(w.Payer))
		require.NoError(t, err)
		require.Zero(t, got)
	})
	t.Run("a rewritten message does not verify", func(t *testing.T) {
		t.Parallel()
		raw, err := spec(w, reference).Build()
		require.NoError(t, err)
		id := idOf(t, raw)
		raw[len(raw)-1] ^= 1
		_, err = w.Policy.ReferenceAmount(raw, id, reference)
		require.Error(t, err)
	})
	t.Run("validly signed bytes under another transaction's id", func(t *testing.T) {
		t.Parallel()
		raw, err := spec(w, reference).Build()
		require.NoError(t, err)
		_, err = w.Policy.ReferenceAmount(raw, solana.Signature{1}, reference)
		require.ErrorContains(t, err, "another transaction")
	})
}
