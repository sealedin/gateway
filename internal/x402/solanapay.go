package x402

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
)

const (
	referenceDomain = "sealedin-pay-reference-v1"
	// ClaimCodeBytes is the size of the secret a buyer's browser generates.
	ClaimCodeBytes = 32

	transferTag         = 3 // SPL token Transfer: source, destination, owner
	transferDataBytes   = 9
	transferFixed       = 3
	transferCheckedFix  = 4 // source, mint, destination, owner
	amountOffset        = 1
	maxSignatures       = 127 // one byte of compact length, far past what a transaction can carry
	claimsPerSecond     = 2   // each poll that reaches the chain costs an RPC call on the provider's quota
	claimsBurst         = 20
	negativeTTL         = 3 * time.Second
	referenceTxTTL      = time.Hour
	maxFetchesPerClaim  = 8    // each costs an RPC call; a later poll reads on where this one stopped
	referenceListLimit  = 1000 // the node's own maximum
	referenceCacheLimit = 10_000
)

// ErrBadClaimCode means a code is not the base58 of 32 bytes. It never repeats the code.
var ErrBadClaimCode = errors.New("code must be the base58 of 32 bytes")

// ParseClaimCode decodes a claim code and returns the on-chain reference it opens. Whoever holds the code can take the key,
// so it stops here: no caller gets it back.
func ParseClaimCode(code string) (solana.PublicKey, error) {
	raw, err := base58.Decode(code)
	if err != nil || len(raw) != ClaimCodeBytes {
		return solana.PublicKey{}, ErrBadClaimCode
	}
	hash := sha256.New()
	hash.Write([]byte(referenceDomain + "\x00"))
	hash.Write(raw)
	return solana.PublicKeyFromBytes(hash.Sum(nil)), nil
}

// ReferencePayment is one transaction that paid the treasury under a reference.
type ReferencePayment struct {
	ID     solana.Signature
	Amount uint64
}

// ReferenceAmount reads what the landed transaction id paid the treasury under reference: every top-level Transfer or
// TransferChecked into the treasury's account that names the reference read-only and unsigned. Wallets add compute budget,
// priority fee, memo and account creation instructions around it, so nothing else about the layout is checked, and nothing a
// memo says counts. Zero means it paid nothing here. The bytes must be id's own, signed, so a lying host cannot show other
// contents under an id the other host confirms; the destination and the reference must be in the signed keys, since what a
// node says about lookup tables is unsigned.
func (p Policy) ReferenceAmount(raw []byte, id solana.Signature, reference solana.PublicKey) (uint64, error) {
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return 0, fmt.Errorf("x402: reference transaction: %w", err)
	}
	if err = verifySignatures(tx, raw); err != nil {
		return 0, err
	}
	if tx.Signatures[0] != id {
		return 0, errors.New("x402: the node returned another transaction")
	}
	if !referenceIsPassive(&tx.Message, reference) {
		return 0, nil
	}
	var total uint64
	for _, ins := range tx.Message.Instructions {
		amount := p.transferUnder(ins, tx.Message.AccountKeys, reference)
		if total+amount < total {
			return 0, errors.New("x402: amounts overflow")
		}
		total += amount
	}
	return total, nil
}

func verifySignatures(tx *solana.Transaction, raw []byte) error {
	count := len(tx.Signatures)
	if count == 0 || count > maxSignatures || count != int(tx.Message.Header.NumRequiredSignatures) {
		return errors.New("x402: reference transaction: bad signature count")
	}
	message := raw[1+count*ed25519.SignatureSize:]
	for i, signature := range tx.Signatures {
		if !ed25519.Verify(tx.Message.AccountKeys[i][:], message, signature[:]) {
			return errors.New("x402: reference transaction: a signature does not verify")
		}
	}
	return nil
}

// referenceIsPassive says the reference is a signed key that neither signs nor is writable, as the Solana Pay spec has it.
func referenceIsPassive(msg *solana.Message, reference solana.PublicKey) bool {
	i := slices.Index(msg.AccountKeys, reference)
	return i >= 0 && i >= len(msg.AccountKeys)-int(msg.Header.NumReadonlyUnsignedAccounts) && i >= int(msg.Header.NumRequiredSignatures)
}

// transferUnder is the instruction's amount if it pays the treasury under the reference, else zero. A plain Transfer names no
// mint, and the destination settles that: the treasury's associated account holds only this mint. An account from a lookup table
// reads as the zero key, so it can be a source but never the destination or the reference.
func (p Policy) transferUnder(ins solana.CompiledInstruction, keys []solana.PublicKey, reference solana.PublicKey) uint64 {
	if int(ins.ProgramIDIndex) >= len(keys) || keys[ins.ProgramIDIndex] != solana.TokenProgramID || len(ins.Data) == 0 {
		return 0
	}
	accounts := make([]solana.PublicKey, len(ins.Accounts))
	for i, index := range ins.Accounts {
		if int(index) < len(keys) {
			accounts[i] = keys[index]
		}
	}
	var fixed, destination int
	switch {
	case ins.Data[0] == transferTag && len(ins.Data) == transferDataBytes:
		fixed, destination = transferFixed, 1
	case ins.Data[0] == transferCheckedTag && len(ins.Data) == transferDataLen && ins.Data[transferDataLen-1] == usdcDecimals:
		fixed, destination = transferCheckedFix, 2
	default:
		return 0
	}
	if len(accounts) <= fixed || accounts[destination] != p.TreasuryATA || accounts[0] == p.TreasuryATA {
		return 0
	}
	if fixed == transferCheckedFix && accounts[1] != p.Mint {
		return 0
	}
	if !slices.Contains(accounts[fixed:], reference) {
		return 0
	}
	return binary.LittleEndian.Uint64(ins.Data[amountOffset:])
}

// referenceTx is a confirmed transaction's reading, kept so a poll does not pay for it again.
type referenceTx struct {
	amount  uint64
	expires time.Time
}

// referenceTxKey is one transaction under one reference: a transaction may name two, and reads differently under each.
type referenceTxKey struct {
	id        solana.Signature
	reference solana.PublicKey
}

// referenceCache holds readings of confirmed transactions; losing one costs only an RPC call.
type referenceCache struct {
	mu      sync.Mutex
	entries map[referenceTxKey]referenceTx
}

func (c *referenceCache) get(key referenceTxKey, now time.Time) (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || now.After(entry.expires) {
		return 0, false
	}
	return entry.amount, true
}

func (c *referenceCache) put(key referenceTxKey, amount uint64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= referenceCacheLimit {
		c.entries = map[referenceTxKey]referenceTx{}
	}
	c.entries[key] = referenceTx{amount: amount, expires: now.Add(referenceTxTTL)}
}

// PaymentsFor reads what was paid under a reference, confirmed on both hosts, oldest first. Pending says more may yet show:
// something is unconfirmed, or this poll's reads ran out. Nothing here costs SOL or touches the fee meter.
func (s *Settler) PaymentsFor(ctx context.Context, reference solana.PublicKey) ([]ReferencePayment, bool, error) {
	key := reference.String()
	if s.claimNegative.Held(key) {
		return nil, true, nil
	}
	if !s.ClaimLimiter.Allow() {
		return nil, false, ErrRateLimited
	}
	call, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()
	listed, err := s.primary.SignaturesForAddress(call, key, referenceListLimit)
	if err != nil {
		return nil, false, fmt.Errorf("x402: list signatures: %w", err)
	}
	if len(listed) == 0 {
		s.claimNegative.Claim(key)
		return nil, true, nil
	}
	var paid []ReferencePayment
	pending := false
	fetches := maxFetchesPerClaim
	for _, entry := range slices.Backward(listed) { // the node lists newest first, and the oldest is the likeliest payment
		if entry.Failure != "" {
			continue
		}
		id, amount, settled, readErr := s.reading(ctx, entry.Signature, reference, &fetches)
		if readErr != nil { // anyone can tag a public reference, so one bad transaction must not hold up the others
			s.Logger.Warn("x402: a transaction under a reference cannot be read yet", "tx", entry.Signature, "err", readErr)
			pending = true
			continue
		}
		pending = pending || !settled
		if amount > 0 {
			paid = append(paid, ReferencePayment{ID: id, Amount: amount})
		}
	}
	return paid, pending, nil
}

// reading is a listed transaction's amount, from memory if it can be, spending one of this poll's reads if not. Settled says the
// answer is final: unconfirmed, or out of reads, it is not.
func (s *Settler) reading(
	ctx context.Context, signature string, reference solana.PublicKey, fetches *int,
) (solana.Signature, uint64, bool, error) {
	id, err := solana.SignatureFromBase58(signature)
	if err != nil {
		return id, 0, false, fmt.Errorf("x402: listed signature: %w", err)
	}
	cacheKey := referenceTxKey{id: id, reference: reference}
	if amount, known := s.referenced.get(cacheKey, s.Now()); known {
		return id, amount, true, nil
	}
	if *fetches == 0 {
		return id, 0, false, nil
	}
	*fetches--
	amount, confirmed, err := s.readReferenced(ctx, id, reference)
	if err != nil || !confirmed {
		return id, 0, false, err
	}
	s.referenced.put(cacheKey, amount, s.Now())
	return id, amount, true, nil
}

// readReferenced is one transaction's reading once it holds on both hosts; a failed or unrelated one reads as zero.
func (s *Settler) readReferenced(ctx context.Context, id solana.Signature, reference solana.PublicKey) (uint64, bool, error) {
	call, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()
	got, err := s.primary.Transaction(call, id.String())
	if err != nil {
		return 0, false, fmt.Errorf("x402: read transaction: %w", err)
	}
	if got == nil {
		return 0, false, nil
	}
	if got.Failure != "" {
		return 0, true, nil
	}
	amount, err := s.policy.ReferenceAmount(got.Raw, id, reference)
	if err != nil {
		s.Logger.Warn("x402: a transaction under a reference does not read", "tx", id, "err", err)
		return 0, true, nil
	}
	second, cancelSecond := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancelSecond()
	status, err := s.confirmer.SignatureStatus(second, id.String())
	if err != nil {
		return 0, false, fmt.Errorf("x402: independent status: %w", err)
	}
	if status == nil || !status.Confirmed || status.Failure != "" {
		return 0, false, nil
	}
	return amount, true, nil
}
