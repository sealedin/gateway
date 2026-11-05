// Package x402 settles x402 exact payments on Solana as their fee payer: Path 1 of the scheme only (static layout, no
// smart wallets, no splits, no sponsored ATA creation), every check failing closed. Wire format: the spec's
// schemes/exact/scheme_exact_svm.md and transports-v2/http.md, whose sections the comments cite.
package x402

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/gagliardetto/solana-go"
	computebudget "github.com/gagliardetto/solana-go/programs/compute-budget"
)

const (
	// MaxComputeUnits is the reference cap of §2.2.1.
	MaxComputeUnits = 400_000
	// MaxComputeUnitPrice is the Path 1 cap of §2.2.1, in microlamports per compute unit.
	MaxComputeUnitPrice = 5_000_000
	// MaxFeeLamports is the most one settlement can cost the fee payer: both signatures plus the capped priority fee.
	MaxFeeLamports = signatureCount*lamportsPerSignature + MaxComputeUnits*MaxComputeUnitPrice/microPerLamport

	maxTransactionBytes  = 1232 // §1.5, legacy and version 0
	maxDecodedBytes      = 4096 // §1.5, version 1: decoded only to refuse it by its version
	signatureCount       = 2    // the client and the sponsor, §2.1.4
	signaturesPrefixLen  = 1    // compact-u16 of signatureCount
	lamportsPerSignature = 5_000
	microPerLamport      = 1_000_000
	minInstructions      = 3 // §3.1
	maxInstructions      = 7
	tailSlotMemoOnly     = 6 // the last optional slot admits only Memo
	usdcDecimals         = 6

	computeLimitDataLen = 5
	computePriceDataLen = 9
	transferCheckedTag  = 12 // pinned in tests against programs/token, kept out of this binary with its rpc dependencies
	transferDataLen     = 10
	transferAccounts    = 4 // source, mint, destination, authority; more would be a multisig

	lighthouseProgram = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
)

// Rejection reasons, the errorReason of a failed settlement; named after the spec's invalid_exact_svm_payload family.
const (
	ReasonMalformed             = "invalid_payload"
	ReasonTooLarge              = "invalid_exact_svm_payload_transaction_too_large"
	ReasonVersion               = "unsupported_transaction_version"
	ReasonLookupTable           = "smart_wallet_alt_resolution_not_available" // §2.1.2
	ReasonSignerSet             = "invalid_exact_svm_payload_signer_set"
	ReasonInstructionCount      = "invalid_exact_svm_payload_transaction_instructions_length"
	ReasonFeePayerInInstruction = "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts"
	ReasonComputeBudget         = "invalid_exact_svm_payload_compute_budget"
	ReasonNoTransfer            = "invalid_exact_svm_payload_no_transfer_instruction"
	ReasonMintMismatch          = "invalid_exact_svm_payload_mint_mismatch"
	ReasonRecipientMismatch     = "invalid_exact_svm_payload_recipient_mismatch"
	ReasonAmountMismatch        = "invalid_exact_svm_payload_amount_mismatch"
	ReasonUnexpectedProgram     = "invalid_exact_svm_payload_unexpected_program"
	ReasonMemo                  = "invalid_exact_svm_payload_memo"
	ReasonClientSignature       = "invalid_exact_svm_payload_signature"
	ReasonSponsorSignature      = "invalid_exact_svm_payload_sponsor_signature"
	ReasonRequirements          = "invalid_payment_requirements"
	ReasonSimulationFailed      = "invalid_exact_svm_payload_transaction_simulation_failed"
	ReasonInsufficientFunds     = "insufficient_funds"
	ReasonTransactionFailed     = "invalid_transaction_state"
	ReasonPending               = "settlement_pending"
	ReasonDuplicate             = "duplicate_settlement"
	ReasonPayerBarred           = "invalid_exact_svm_payload_payer_failed_recently"
	ReasonPayerUnresolved       = "invalid_exact_svm_payload_payer_has_unresolved_transaction"
	ReasonFeePayerMismatch      = "invalid_exact_svm_payload_fee_payer_mismatch"
)

// RejectionError is a payment the policy refuses; Reason is the wire code, the detail stays in logs. Transaction is the
// on-chain id and is set only once that id is public: before then it is the sponsor's signature, the one thing a client
// must not get without having passed simulation.
type RejectionError struct {
	Reason      string
	Detail      string
	Transaction string
	Payer       string
}

func (r *RejectionError) Error() string { return "x402: " + r.Reason + ": " + r.Detail }

func reject(reason, format string, args ...any) *RejectionError {
	return &RejectionError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Reason is the wire code of a RejectionError, empty for nil and for any other error.
func Reason(err error) string {
	if r, ok := errors.AsType[*RejectionError](err); ok {
		return r.Reason
	}
	return ""
}

// Policy is what a payment must do: pay Mint to the treasury's ATA, fees on FeePayer and nothing else on it.
type Policy struct {
	FeePayer    solana.PublicKey
	Treasury    solana.PublicKey
	Mint        solana.PublicKey
	TreasuryATA solana.PublicKey
}

// NewPolicy derives the treasury's associated token account under the SPL token program, USDC's only program.
func NewPolicy(feePayer, treasury, mint solana.PublicKey) (Policy, error) {
	ata, _, err := solana.FindAssociatedTokenAddressWithProgram(treasury, mint, solana.TokenProgramID)
	if err != nil {
		return Policy{}, fmt.Errorf("x402: treasury ATA: %w", err)
	}
	return Policy{FeePayer: feePayer, Treasury: treasury, Mint: mint, TreasuryATA: ata}, nil
}

// Payment is a transaction that passed the policy; every field is read from the verified bytes.
type Payment struct {
	Tx          *solana.Transaction
	Raw         []byte
	Payer       solana.PublicKey
	Source      solana.PublicKey // the token account paying
	Amount      uint64           // base units of the mint
	FeeLamports uint64           // what landing it costs the fee payer, failed or not

	reservedDay string // the UTC day its fee is booked on
}

func (p Payment) message() []byte {
	return p.Raw[signaturesPrefixLen+signatureCount*ed25519.SignatureSize:]
}

// Digest names the payment before anyone signs it: the sponsor's deterministic signature makes a message one transaction,
// and a client re-signing it cannot make a second. Unlike the transaction's id, it reveals nothing.
func (p Payment) Digest() string {
	sum := sha256.Sum256(p.message())
	return hex.EncodeToString(sum[:])
}

// VerifyUnsigned checks a client's partially signed transaction before the sponsor signs anything.
func (p Policy) VerifyUnsigned(raw []byte) (Payment, error) {
	pay, err := p.verifyLayout(raw)
	if err != nil {
		return Payment{}, err
	}
	if pay.Tx.Signatures[0] != (solana.Signature{}) {
		return Payment{}, reject(ReasonSponsorSignature, "fee payer slot is not empty")
	}
	return pay, nil
}

// VerifyLanded is VerifySettled for whichever fee payer the transaction names, so a key survives a change of fee payer. The
// signature then says only that the named account signed; what such a payment may get is the caller's to limit.
func (p Policy) VerifyLanded(raw []byte) (Payment, error) {
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return Payment{}, reject(ReasonMalformed, "%v", err)
	}
	if len(tx.Message.AccountKeys) > 0 {
		p.FeePayer = tx.Message.AccountKeys[0]
	}
	return p.VerifySettled(raw)
}

// VerifySettled checks a transaction read back from the chain: the same policy, and the fee payer's own signature, which an
// RPC host cannot forge without that key.
func (p Policy) VerifySettled(raw []byte) (Payment, error) {
	pay, err := p.verifyLayout(raw)
	if err != nil {
		return Payment{}, err
	}
	if !ed25519.Verify(p.FeePayer[:], pay.message(), pay.Tx.Signatures[0][:]) {
		return Payment{}, reject(ReasonSponsorSignature, "fee payer signature does not verify")
	}
	return pay, nil
}

func (p Policy) verifyLayout(raw []byte) (Payment, error) {
	if len(raw) > maxDecodedBytes {
		return Payment{}, reject(ReasonTooLarge, "%d bytes", len(raw))
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return Payment{}, reject(ReasonMalformed, "%v", err)
	}
	msg := &tx.Message
	if msg.GetVersion() != solana.MessageVersionV0 { // §1.5: before inspecting anything else
		return Payment{}, reject(ReasonVersion, "only version 0 is accepted")
	}
	if len(raw) > maxTransactionBytes {
		return Payment{}, reject(ReasonTooLarge, "%d bytes", len(raw))
	}
	if err = checkCanonical(tx, raw); err != nil {
		return Payment{}, err
	}
	if len(msg.AddressTableLookups) != 0 { // §2.1.2: this sponsor resolves none, so it accepts none
		return Payment{}, reject(ReasonLookupTable, "%d tables", len(msg.AddressTableLookups))
	}
	if err = p.checkSigners(tx); err != nil {
		return Payment{}, err
	}
	if err = msg.Sanitize(); err != nil {
		return Payment{}, reject(ReasonMalformed, "%v", err)
	}
	if err = checkShape(msg); err != nil {
		return Payment{}, err
	}
	fee, err := checkComputeBudget(msg)
	if err != nil {
		return Payment{}, err
	}
	amount, err := p.checkTransfer(msg)
	if err != nil {
		return Payment{}, err
	}
	if err = checkTail(msg); err != nil {
		return Payment{}, err
	}
	source := msg.AccountKeys[msg.Instructions[minInstructions-1].Accounts[0]]
	pay := Payment{Tx: tx, Raw: raw, Payer: msg.AccountKeys[1], Source: source, Amount: amount, FeeLamports: fee}
	if !ed25519.Verify(pay.Payer[:], pay.message(), tx.Signatures[1][:]) {
		return Payment{}, reject(ReasonClientSignature, "client signature does not verify")
	}
	return pay, nil
}

// checkCanonical refuses anything the library would re-encode differently (trailing bytes above all), so the bytes that
// get signed and sent are exactly the ones the checks read.
func checkCanonical(tx *solana.Transaction, raw []byte) error {
	again, err := tx.MarshalBinary()
	if err != nil || !bytes.Equal(again, raw) {
		return reject(ReasonMalformed, "not a canonical encoding")
	}
	return nil
}

// checkSigners is §2.1.4: exactly the sponsor, writable and first, plus one client, with no account listed twice.
func (p Policy) checkSigners(tx *solana.Transaction) error {
	msg := &tx.Message
	if msg.Header.NumRequiredSignatures != signatureCount || len(tx.Signatures) != signatureCount ||
		msg.Header.NumReadonlySignedAccounts >= signatureCount || len(msg.AccountKeys) < signatureCount {
		return reject(ReasonSignerSet, "want one fee payer and one client")
	}
	if msg.AccountKeys[0] != p.FeePayer {
		return reject(ReasonFeePayerMismatch, "fee payer is %s", msg.AccountKeys[0])
	}
	seen := make(map[solana.PublicKey]struct{}, len(msg.AccountKeys))
	for _, key := range msg.AccountKeys {
		if _, dup := seen[key]; dup {
			return reject(ReasonSignerSet, "account %s listed twice", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// checkShape is the instruction count of §3.1 and the isolation of §2.1.1: no instruction may name the fee payer, so the
// runtime can charge it only the network fee.
func checkShape(msg *solana.Message) error {
	if n := len(msg.Instructions); n < minInstructions || n > maxInstructions {
		return reject(ReasonInstructionCount, "%d instructions", n)
	}
	for i, ins := range msg.Instructions {
		if slices.Contains(ins.Accounts, 0) {
			return reject(ReasonFeePayerInInstruction, "instruction %d", i)
		}
	}
	return nil
}

// checkComputeBudget is §2.2.1 and returns the exact fee: the runtime charges the requested limit, not what executes.
func checkComputeBudget(msg *solana.Message) (uint64, error) {
	limitIns, priceIns := msg.Instructions[0], msg.Instructions[1]
	budget := solana.ComputeBudget
	if msg.AccountKeys[limitIns.ProgramIDIndex] != budget || msg.AccountKeys[priceIns.ProgramIDIndex] != budget ||
		len(limitIns.Accounts) != 0 || len(priceIns.Accounts) != 0 ||
		len(limitIns.Data) != computeLimitDataLen || limitIns.Data[0] != computebudget.Instruction_SetComputeUnitLimit ||
		len(priceIns.Data) != computePriceDataLen || priceIns.Data[0] != computebudget.Instruction_SetComputeUnitPrice {
		return 0, reject(ReasonComputeBudget, "first two instructions must set the compute unit limit, then the price")
	}
	limit := uint64(binary.LittleEndian.Uint32(limitIns.Data[1:]))
	price := binary.LittleEndian.Uint64(priceIns.Data[1:])
	if limit == 0 || limit > MaxComputeUnits || price > MaxComputeUnitPrice {
		return 0, reject(ReasonComputeBudget, "limit %d, price %d", limit, price)
	}
	return signatureCount*lamportsPerSignature + (limit*price+microPerLamport-1)/microPerLamport, nil
}

// checkTransfer is §1.2 and §1.4 on the only slot the static layout has for a transfer; returns the amount.
func (p Policy) checkTransfer(msg *solana.Message) (uint64, error) {
	ins := msg.Instructions[minInstructions-1]
	if msg.AccountKeys[ins.ProgramIDIndex] != solana.TokenProgramID || len(ins.Data) != transferDataLen ||
		ins.Data[0] != transferCheckedTag || ins.Data[transferDataLen-1] != usdcDecimals || len(ins.Accounts) != transferAccounts {
		return 0, reject(ReasonNoTransfer, "third instruction must be the token program's TransferChecked")
	}
	source, mint, destination, authority := ins.Accounts[0], ins.Accounts[1], ins.Accounts[2], ins.Accounts[3]
	switch {
	case msg.AccountKeys[mint] != p.Mint:
		return 0, reject(ReasonMintMismatch, "mint %s", msg.AccountKeys[mint])
	case msg.AccountKeys[destination] != p.TreasuryATA:
		return 0, reject(ReasonRecipientMismatch, "destination %s", msg.AccountKeys[destination])
	case authority != 1:
		return 0, reject(ReasonNoTransfer, "the client must be the transfer authority")
	case source == destination:
		return 0, reject(ReasonNoTransfer, "source equals destination")
	}
	amount := binary.LittleEndian.Uint64(ins.Data[1:])
	if amount == 0 {
		return 0, reject(ReasonNoTransfer, "zero amount")
	}
	return amount, nil
}

// checkTail admits the optional instructions of §3.1: Lighthouse or Memo, Memo only in the last slot, and at least one
// non-empty Memo. A second transfer or any other program fails here.
func checkTail(msg *solana.Message) error {
	lighthouse := solana.MustPublicKeyFromBase58(lighthouseProgram)
	memos := 0
	for i := minInstructions; i < len(msg.Instructions); i++ {
		ins := msg.Instructions[i]
		program := msg.AccountKeys[ins.ProgramIDIndex]
		switch {
		case program == solana.MemoProgramID:
			if len(ins.Data) == 0 {
				return reject(ReasonMemo, "empty memo")
			}
			memos++
		case program == lighthouse && i < tailSlotMemoOnly:
		default:
			return reject(ReasonUnexpectedProgram, "instruction %d: %s", i, program)
		}
	}
	if memos == 0 {
		return reject(ReasonMemo, "no memo")
	}
	return nil
}
