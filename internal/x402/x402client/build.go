// Package x402client builds the client side of an x402 exact payment on Solana: the operator's smoke tool and the tests
// use it, the measured services do not.
package x402client

import (
	"crypto/ed25519"
	"fmt"

	"github.com/gagliardetto/solana-go"
	computebudget "github.com/gagliardetto/solana-go/programs/compute-budget"
	"github.com/gagliardetto/solana-go/programs/memo"
	"github.com/gagliardetto/solana-go/programs/token"
)

// Compute budget a client asks for: well above what a transfer and a memo consume, well under the sponsor's caps.
const (
	computeUnitLimit = 50_000
	computeUnitPrice = 1_000
	usdcDecimals     = 6
)

// Payment is what the client's wallet pays.
type Payment struct {
	Payer     ed25519.PrivateKey
	FeePayer  solana.PublicKey
	Treasury  solana.PublicKey
	Mint      solana.PublicKey
	Amount    uint64
	Blockhash solana.Hash
	Memo      string
}

// Message compiles the payment into the static version-0 layout the sponsor accepts: compute limit, compute price,
// TransferChecked, memo.
func (p Payment) Message() (*solana.Message, error) {
	payer := solana.PublicKeyFromBytes(p.Payer[ed25519.SeedSize:])
	source, _, err := solana.FindAssociatedTokenAddress(payer, p.Mint)
	if err != nil {
		return nil, fmt.Errorf("x402client: source ATA: %w", err)
	}
	destination, _, err := solana.FindAssociatedTokenAddress(p.Treasury, p.Mint)
	if err != nil {
		return nil, fmt.Errorf("x402client: destination ATA: %w", err)
	}
	tx, err := solana.NewTransaction([]solana.Instruction{
		computebudget.NewSetComputeUnitLimitInstruction(computeUnitLimit).Build(),
		computebudget.NewSetComputeUnitPriceInstruction(computeUnitPrice).Build(),
		token.NewTransferCheckedInstruction(p.Amount, usdcDecimals, source, p.Mint, destination, payer, nil).Build(),
		memo.NewMemoInstruction([]byte(p.Memo)).Build(),
	}, p.Blockhash, solana.TransactionPayer(p.FeePayer))
	if err != nil {
		return nil, fmt.Errorf("x402client: compile: %w", err)
	}
	if _, err = tx.Message.SetVersion(solana.MessageVersionV0); err != nil {
		return nil, fmt.Errorf("x402client: version: %w", err)
	}
	return &tx.Message, nil
}

// Sign serializes msg with the payer's signature in place and the sponsor's still empty: what PAYMENT-SIGNATURE carries.
func Sign(msg *solana.Message, payer ed25519.PrivateKey) ([]byte, error) {
	raw, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("x402client: message: %w", err)
	}
	tx := solana.Transaction{Message: *msg, Signatures: make([]solana.Signature, msg.Header.NumRequiredSignatures)}
	for i := 1; i < len(tx.Signatures); i++ {
		copy(tx.Signatures[i][:], ed25519.Sign(payer, raw))
	}
	out, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("x402client: transaction: %w", err)
	}
	return out, nil
}

// SolanaPayTransfer is what a wallet builds from a Solana Pay transfer request: the payer pays its own fee, and the reference
// is an extra read-only account on the transfer, the last instruction.
type SolanaPayTransfer struct {
	Payer     ed25519.PrivateKey
	Treasury  solana.PublicKey
	Mint      solana.PublicKey
	Amount    uint64
	Reference solana.PublicKey
	Blockhash solana.Hash
	Plain     bool // a Transfer rather than a TransferChecked, as some wallets send
}

// Build returns the signed transaction.
func (p SolanaPayTransfer) Build() ([]byte, error) {
	payer := solana.PublicKeyFromBytes(p.Payer[ed25519.SeedSize:])
	source, _, err := solana.FindAssociatedTokenAddress(payer, p.Mint)
	if err != nil {
		return nil, fmt.Errorf("x402client: source ATA: %w", err)
	}
	destination, _, err := solana.FindAssociatedTokenAddress(p.Treasury, p.Mint)
	if err != nil {
		return nil, fmt.Errorf("x402client: destination ATA: %w", err)
	}
	transfer := solana.Instruction(token.NewTransferInstruction(p.Amount, source, destination, payer, nil).Build())
	if !p.Plain {
		transfer = token.NewTransferCheckedInstruction(p.Amount, usdcDecimals, source, p.Mint, destination, payer, nil).Build()
	}
	data, err := transfer.Data()
	if err != nil {
		return nil, fmt.Errorf("x402client: transfer: %w", err)
	}
	accounts := append(transfer.Accounts(), solana.Meta(p.Reference))
	tx, err := solana.NewTransaction([]solana.Instruction{
		computebudget.NewSetComputeUnitLimitInstruction(computeUnitLimit).Build(),
		computebudget.NewSetComputeUnitPriceInstruction(computeUnitPrice).Build(),
		memo.NewMemoInstruction([]byte("a wallet's memo means nothing"), payer).Build(),
		solana.NewInstruction(solana.TokenProgramID, accounts, data),
	}, p.Blockhash, solana.TransactionPayer(payer))
	if err != nil {
		return nil, fmt.Errorf("x402client: compile: %w", err)
	}
	if _, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key == payer {
			private := solana.PrivateKey(p.Payer)
			return &private
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("x402client: sign: %w", err)
	}
	return tx.MarshalBinary()
}
