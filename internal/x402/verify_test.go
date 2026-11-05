package x402_test

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402test"
)

const amount = 25_000_000

// The library orders the writable accounts by key, so only these two positions are fixed; the rest come from the instructions.
const (
	feePayerIdx = iota
	payerIdx
)

func mintIdx(m *solana.Message) uint16        { return m.Instructions[2].Accounts[1] }
func destinationIdx(m *solana.Message) uint16 { return m.Instructions[2].Accounts[2] }
func tokenIdx(m *solana.Message) uint16       { return m.Instructions[2].ProgramIDIndex }
func memoIdx(m *solana.Message) uint16        { return m.Instructions[3].ProgramIDIndex }

func budgetLimit(units uint32) []byte {
	data := make([]byte, 5)
	data[0] = 2
	binary.LittleEndian.PutUint32(data[1:], units)
	return data
}

func budgetPrice(micro uint64) []byte {
	data := make([]byte, 9)
	data[0] = 3
	binary.LittleEndian.PutUint64(data[1:], micro)
	return data
}

func transfer(value uint64, decimals byte) []byte {
	data := make([]byte, 10)
	data[0] = 12
	binary.LittleEndian.PutUint64(data[1:], value)
	data[9] = decimals
	return data
}

func TestVerifyAcceptsTheStaticLayout(t *testing.T) {
	t.Parallel()
	w := x402test.NewWorld(t)
	got, err := w.Policy.VerifyUnsigned(w.ClientTx(t, amount, nil))
	require.NoError(t, err)
	require.Equal(t, uint64(amount), got.Amount)
	require.Equal(t, x402test.Public(w.Payer), got.Payer)
	// Two signatures at 5000 lamports, plus 50000 CU at 1000 microlamports each.
	require.Equal(t, uint64(10_050), got.FeeLamports)
}

// The wallet-injected Lighthouse and Memo instructions of the spec's Path 1 stay on the fast path.
func TestVerifyAcceptsWalletInjectedTail(t *testing.T) {
	t.Parallel()
	w := x402test.NewWorld(t)
	raw := w.ClientTx(t, amount, func(m *solana.Message) {
		m.AccountKeys = append(m.AccountKeys, x402test.Lighthouse())
		lighthouse := uint16(len(m.AccountKeys) - 1)
		m.Header.NumReadonlyUnsignedAccounts++
		memo := m.Instructions[3]
		m.Instructions = append(m.Instructions[:3],
			solana.CompiledInstruction{ProgramIDIndex: lighthouse, Data: []byte{1}},
			solana.CompiledInstruction{ProgramIDIndex: lighthouse, Data: []byte{2}},
			solana.CompiledInstruction{ProgramIDIndex: lighthouse, Data: []byte{3}},
			memo)
	})
	_, err := w.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
}

// Every rejection the sponsor policy demands, each on a transaction that differs from a good one in that respect only.
func TestVerifyRejects(t *testing.T) {
	t.Parallel()
	otherKey := x402test.Public(x402test.NewKey(t))
	tests := []struct {
		name   string
		mutate func(w *x402test.World, m *solana.Message)
		reason string
	}{
		{"wrong mint", func(_ *x402test.World, m *solana.Message) { m.AccountKeys[mintIdx(m)] = otherKey }, x402.ReasonMintMismatch},
		{"wrong destination", func(_ *x402test.World, m *solana.Message) {
			m.AccountKeys[destinationIdx(m)] = otherKey
		}, x402.ReasonRecipientMismatch},
		{"token-2022 program", func(_ *x402test.World, m *solana.Message) {
			m.AccountKeys[tokenIdx(m)] = solana.Token2022ProgramID
		}, x402.ReasonNoTransfer},
		{"transfer instead of transfer checked", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[2].Data = append([]byte{3}, m.Instructions[2].Data[1:9]...)
		}, x402.ReasonNoTransfer},
		{"wrong decimals", func(_ *x402test.World, m *solana.Message) { m.Instructions[2].Data = transfer(amount, 9) }, x402.ReasonNoTransfer},
		{"zero amount", func(_ *x402test.World, m *solana.Message) { m.Instructions[2].Data = transfer(0, 6) }, x402.ReasonNoTransfer},
		{"two transfers", func(_ *x402test.World, m *solana.Message) {
			m.Instructions = append(m.Instructions[:4], m.Instructions[2])
		}, x402.ReasonUnexpectedProgram},
		{"transfer moved into the tail", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[2], m.Instructions[3] = m.Instructions[3], m.Instructions[2]
		}, x402.ReasonNoTransfer},
		{"fee payer in an instruction", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[3].Accounts = []uint16{feePayerIdx}
		}, x402.ReasonFeePayerInInstruction},
		{"fee payer as authority", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[2].Accounts[3] = feePayerIdx
		}, x402.ReasonFeePayerInInstruction},
		{"fee payer as source", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[2].Accounts[0] = feePayerIdx
		}, x402.ReasonFeePayerInInstruction},
		{"authority is not the client", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[2].Accounts[3] = mintIdx(m)
		}, x402.ReasonNoTransfer},
		{"multisig authority", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[2].Accounts = append(m.Instructions[2].Accounts, mintIdx(m))
		}, x402.ReasonNoTransfer},
		{"source equals destination", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[2].Accounts[0] = destinationIdx(m)
		}, x402.ReasonNoTransfer},
		{"extra signer", func(_ *x402test.World, m *solana.Message) { m.Header.NumRequiredSignatures = 3 }, x402.ReasonSignerSet},
		{"read-only fee payer", func(_ *x402test.World, m *solana.Message) { m.Header.NumReadonlySignedAccounts = 2 }, x402.ReasonSignerSet},
		{"other fee payer", func(_ *x402test.World, m *solana.Message) { m.AccountKeys[feePayerIdx] = otherKey }, x402.ReasonFeePayerMismatch},
		{"client equals fee payer", func(w *x402test.World, m *solana.Message) {
			m.AccountKeys[payerIdx] = w.Policy.FeePayer
		}, x402.ReasonSignerSet},
		{"duplicate account", func(_ *x402test.World, m *solana.Message) {
			m.AccountKeys = append(m.AccountKeys, m.AccountKeys[mintIdx(m)])
			m.Header.NumReadonlyUnsignedAccounts++
		}, x402.ReasonSignerSet},
		{"unexpected program in the tail", func(_ *x402test.World, m *solana.Message) {
			m.AccountKeys[memoIdx(m)] = otherKey
		}, x402.ReasonUnexpectedProgram},
		{"no memo", func(_ *x402test.World, m *solana.Message) {
			m.AccountKeys = append(m.AccountKeys, x402test.Lighthouse())
			m.Header.NumReadonlyUnsignedAccounts++
			lighthouse := uint16(len(m.AccountKeys) - 1)
			m.Instructions[3] = solana.CompiledInstruction{ProgramIDIndex: lighthouse, Data: []byte{1}}
		}, x402.ReasonMemo},
		{"empty memo", func(_ *x402test.World, m *solana.Message) { m.Instructions[3].Data = nil }, x402.ReasonMemo},
		{"too few instructions", func(_ *x402test.World, m *solana.Message) { m.Instructions = m.Instructions[:2] }, x402.ReasonInstructionCount},
		{"too many instructions", func(_ *x402test.World, m *solana.Message) {
			memo := m.Instructions[3]
			m.Instructions = append(m.Instructions, memo, memo, memo, memo)
		}, x402.ReasonInstructionCount},
		{"memo slot 7 not memo", func(_ *x402test.World, m *solana.Message) {
			m.AccountKeys = append(m.AccountKeys, x402test.Lighthouse())
			m.Header.NumReadonlyUnsignedAccounts++
			memo := m.Instructions[3]
			lighthouse := solana.CompiledInstruction{ProgramIDIndex: uint16(len(m.AccountKeys) - 1), Data: []byte{1}}
			m.Instructions = append(m.Instructions[:3], memo, lighthouse, lighthouse, lighthouse)
		}, x402.ReasonUnexpectedProgram},
		{"compute limit missing", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[0] = m.Instructions[1]
		}, x402.ReasonComputeBudget},
		{"compute price missing", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[1] = m.Instructions[0]
		}, x402.ReasonComputeBudget},
		{"compute unit limit over the cap", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[0].Data = budgetLimit(x402.MaxComputeUnits + 1)
		}, x402.ReasonComputeBudget},
		{"excessive priority fee", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[1].Data = budgetPrice(x402.MaxComputeUnitPrice + 1)
		}, x402.ReasonComputeBudget},
		{"overflowing priority fee", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[1].Data = budgetPrice(1 << 63)
		}, x402.ReasonComputeBudget},
		{"compute budget with accounts", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[0].Accounts = []uint16{mintIdx(m)}
		}, x402.ReasonComputeBudget},
		{"lookup table", func(_ *x402test.World, m *solana.Message) {
			m.AddressTableLookups = solana.MessageAddressTableLookupSlice{{AccountKey: otherKey, WritableIndexes: []byte{0}}}
		}, x402.ReasonLookupTable},
		{"legacy message", func(_ *x402test.World, m *solana.Message) {
			_, err := m.SetVersion(solana.MessageVersionLegacy)
			require.NoError(t, err)
		}, x402.ReasonVersion},
		{"oversized", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[3].Data = make([]byte, 1232)
		}, x402.ReasonTooLarge},
		{"version 1 message, refused by its version even when over the version 0 size", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[3].Data = make([]byte, 1232)
			_, err := m.SetVersion(solana.MessageVersionV1)
			require.NoError(t, err)
		}, x402.ReasonVersion},
		{"out of bounds account", func(_ *x402test.World, m *solana.Message) {
			m.Instructions[3].Accounts = []uint16{200}
		}, x402.ReasonMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := x402test.NewWorld(t)
			raw := w.ClientTx(t, amount, func(m *solana.Message) { tc.mutate(w, m) })
			_, err := w.Policy.VerifyUnsigned(raw)
			require.Equal(t, tc.reason, x402.Reason(err), "err: %v", err)
		})
	}
}

func TestVerifyRejectsBadEnvelope(t *testing.T) {
	t.Parallel()
	w := x402test.NewWorld(t)
	good := w.ClientTx(t, amount, nil)
	flipped := func(at int) []byte {
		out := append([]byte(nil), good...)
		out[at] ^= 1
		return out
	}
	tests := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"empty", nil, x402.ReasonMalformed},
		{"truncated", good[:len(good)-1], x402.ReasonMalformed},
		{"trailing bytes", append(append([]byte(nil), good...), 0), x402.ReasonMalformed},
		{"client signature invalid", flipped(1 + 64), x402.ReasonClientSignature},
		{"message altered after signing", flipped(len(good) - 2), x402.ReasonClientSignature},
		{"sponsor signature already present", flipped(1), x402.ReasonSponsorSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := w.Policy.VerifyUnsigned(tc.raw)
			require.Equal(t, tc.reason, x402.Reason(err), "err: %v", err)
		})
	}
}

// A settled transaction carries the sponsor's own valid signature, which an RPC host cannot forge.
func TestVerifySettled(t *testing.T) {
	t.Parallel()
	w := x402test.NewWorld(t)
	raw := w.ClientTx(t, amount, nil)
	pay, err := w.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	signed := w.FeePayer.CoSign(pay)

	got, err := w.Policy.VerifySettled(signed)
	require.NoError(t, err)
	require.Equal(t, pay.Payer, got.Payer)
	require.Equal(t, uint64(amount), got.Amount)

	_, err = w.Policy.VerifySettled(raw)
	require.Equal(t, x402.ReasonSponsorSignature, x402.Reason(err), "an unsigned transaction never settled")
}

// The key never prints: neither through a log line nor through a debug format.
func TestFeePayerPrintsOnlyItsPublicKey(t *testing.T) {
	t.Parallel()
	key := x402test.NewKey(t)
	feePayer := x402.NewFeePayer(key)
	want := x402test.Public(key).String()
	for _, format := range []string{"%v", "%+v", "%s", "%#v"} {
		require.Equal(t, want, fmt.Sprintf(format, feePayer))
	}
}

// The ATA the policy pins is the canonical derivation, not whatever a test configured.
func TestPolicyDerivesTreasuryATA(t *testing.T) {
	t.Parallel()
	treasury := solana.MustPublicKeyFromBase58("2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4")
	mint := solana.MustPublicKeyFromBase58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
	want, _, err := solana.FindAssociatedTokenAddressWithProgram(treasury, mint, solana.TokenProgramID)
	require.NoError(t, err)
	policy, err := x402.NewPolicy(solana.PublicKey{1}, treasury, mint)
	require.NoError(t, err)
	require.Equal(t, want, policy.TreasuryATA)
}

// The transfer tag verify.go keeps as a literal, so the token program's rpc dependencies stay out of the sales binary.
func TestTransferCheckedTagMatchesTheTokenProgram(t *testing.T) {
	t.Parallel()
	require.Equal(t, token.Instruction_TransferChecked, transfer(1, 6)[0])
}

// The program ids the policy names are the ones the spec names.
func TestProgramIDsMatchTheSpec(t *testing.T) {
	t.Parallel()
	require.Equal(t, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", solana.TokenProgramID.String())
	require.Equal(t, "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", solana.MemoProgramID.String())
	require.Equal(t, "ComputeBudget111111111111111111111111111111", solana.ComputeBudget.String())
	require.Equal(t, "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95", x402test.Lighthouse().String())
}

// The value is stable, so recovery can hand it back, and differs per payment and per secret.
func TestVirtualKeyIsPerPaymentAndSecret(t *testing.T) {
	t.Parallel()
	keys := x402.NewVirtualKeys([x402.SecretBytes]byte{1})
	first := keys.ForPayment("digest-a")
	require.Equal(t, first, keys.ForPayment("digest-a"))
	require.Regexp(t, `^sk-[0-9a-f]{64}$`, first)
	require.NotEqual(t, first, keys.ForPayment("digest-b"))
	require.NotEqual(t, first, x402.NewVirtualKeys([x402.SecretBytes]byte{2}).ForPayment("digest-a"))
}

func TestParseFeePayerKey(t *testing.T) {
	t.Parallel()
	key := x402test.NewKey(t)
	got, err := x402.ParseFeePayerKey(solana.PrivateKey(key).String())
	require.NoError(t, err)
	require.Equal(t, key, got)
	const secretLooking = "4wBqpZM9k7dVhZ3Xn2Qf"
	mismatched := solana.PrivateKey(append(append([]byte(nil), key[:32]...), x402test.NewKey(t)[32:]...)).String()
	for _, bad := range []string{"", secretLooking, "not base58 0OIl", strings.Repeat("07", 32), mismatched} {
		_, err = x402.ParseFeePayerKey(bad)
		require.Error(t, err)
		if bad != "" {
			require.NotContains(t, err.Error(), bad, "an error never repeats the key")
		}
	}
}

// A former fee payer's transaction still verifies, its own signature checked; a forged one does not, and the current
// sponsor's check still refuses it.
func TestVerifyLandedAcceptsTheFeePayerItNames(t *testing.T) {
	t.Parallel()
	w := x402test.NewWorld(t)
	raw := w.ClientTx(t, 20_000_000, nil)
	pay, err := w.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	signed := w.FeePayer.CoSign(pay)

	current := w.Policy
	current.FeePayer = x402test.Public(x402test.NewKey(t))
	_, err = current.VerifySettled(signed)
	require.Error(t, err, "not this sponsor's")
	got, err := current.VerifyLanded(signed)
	require.NoError(t, err)
	require.Equal(t, w.FeePayer.Public(), got.Tx.Message.AccountKeys[0])

	forged := append([]byte(nil), signed...)
	forged[1] ^= 0xff // the fee payer's signature
	_, err = current.VerifyLanded(forged)
	require.Error(t, err)
}

func FuzzVerifyNeverPanics(f *testing.F) {
	w := x402test.NewWorld(f)
	f.Add(w.ClientTx(f, amount, nil))
	f.Add([]byte{2})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if pay, err := w.Policy.VerifyUnsigned(raw); err == nil {
			require.Equal(t, w.Policy.FeePayer, pay.Tx.Message.AccountKeys[feePayerIdx], "accepted a foreign fee payer")
		}
	})
}
