// Package x402test holds the fixtures of the x402 tests: throwaway keys, a compliant client transaction and a fake
// Solana RPC host; test-only.
package x402test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402client"
)

// Mint is the USDC mint the fixtures pay in.
const Mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

// Lighthouse is the wallet-assertion program the spec's Path 1 admits.
func Lighthouse() solana.PublicKey {
	return solana.MustPublicKeyFromBase58("L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95")
}

// NewKey generates a throwaway Ed25519 key.
func NewKey(tb testing.TB) ed25519.PrivateKey {
	tb.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(tb, err)
	return key
}

// Public is the account of a key.
func Public(key ed25519.PrivateKey) solana.PublicKey {
	return solana.PublicKeyFromBytes(key[ed25519.SeedSize:])
}

// Sign is a wallet's signature over a message.
func Sign(key ed25519.PrivateKey, msg []byte) []byte { return ed25519.Sign(key, msg) }

// World is one set of throwaway parties: a sponsor, a treasury and a paying client.
type World struct {
	Payer    ed25519.PrivateKey
	FeePayer *x402.FeePayer
	Keys     *x402.VirtualKeys
	Treasury solana.PublicKey
	Policy   x402.Policy

	memo int
}

// NewWorld generates the parties and the policy that accepts their payments.
func NewWorld(tb testing.TB) *World {
	tb.Helper()
	feePayer := x402.NewFeePayer(NewKey(tb))
	treasury := Public(NewKey(tb))
	policy, err := x402.NewPolicy(feePayer.Public(), treasury, solana.MustPublicKeyFromBase58(Mint))
	require.NoError(tb, err)
	keys := x402.NewVirtualKeys([x402.SecretBytes]byte{9})
	return &World{Payer: NewKey(tb), FeePayer: feePayer, Keys: keys, Treasury: treasury, Policy: policy}
}

// ClientTx is a compliant partially signed payment, with mutate applied to the message before the client signs it.
func (w *World) ClientTx(tb testing.TB, amount uint64, mutate func(*solana.Message)) []byte {
	tb.Helper()
	w.memo++
	msg, err := x402client.Payment{
		Payer:     w.Payer,
		FeePayer:  w.Policy.FeePayer,
		Treasury:  w.Treasury,
		Mint:      w.Policy.Mint,
		Amount:    amount,
		Blockhash: solana.Hash{1, 2, 3},
		Memo:      "0123456789abcdef0123456789abcdef" + string(rune('a'+w.memo%26)),
	}.Message()
	require.NoError(tb, err)
	if mutate != nil {
		mutate(msg)
	}
	raw, err := x402client.Sign(msg, w.Payer)
	require.NoError(tb, err)
	return raw
}
