package x402

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/gagliardetto/solana-go"
	"golang.org/x/time/rate"

	"github.com/sealedin/gateway/internal/solanarpc"
)

const (
	// claimTTL outlives every way sent bytes can still land: the wait plus a blockhash's life of 150 slots.
	claimTTL = 3 * time.Minute
	// CreditBudget is what the gateway calls after a settlement may take.
	CreditBudget = 30 * time.Second
	// HandlerBudget bounds what a request holds its claim for, each part enforced by its own deadline.
	HandlerBudget = preSendBudget + waitBudget + CreditBudget

	preSendBudget    = 25 * time.Second // the credit check, the simulation and the status check
	waitBudget       = MaxTimeoutSeconds * time.Second
	activeTTL        = HandlerBudget + 10*time.Second // so a claim outlives its handler even at the worst case
	rpcCallTimeout   = solanarpc.CallTimeout
	hintTimeout      = 2 * time.Second  // a hint is best effort: an unauthenticated 402 must not wait for it
	blockhashHintTTL = 10 * time.Second // nor may each 402 cost an RPC call, failed ones included
	pollInterval     = time.Second
	// The platform gateway hides the client address from the edge, so the buckets are global, one per route so that a
	// flood of recovery requests cannot starve purchases.
	attemptsPerSecond = 0.5
	attemptsBurst     = 10
	recoverWindow     = 2 * time.Minute // how far a recovery proof's timestamp may be from now
	proofTTL          = 2 * recoverWindow
	reconcileAfter    = claimTTL       // by then a transaction has landed or never will
	failedPayerTTL    = 24 * time.Hour // a source whose transaction landed failed cost a fee; it does not get a second one
)

// Failures that are nobody's payment.
var (
	ErrFeeCeiling       = errors.New("x402: daily fee ceiling reached")
	ErrFeePayerUnfunded = errors.New("x402: fee payer has no funds")
	ErrRateLimited      = errors.New("x402: too many attempts")
	ErrBadRecovery      = errors.New("x402: malformed recovery request")
	ErrProofInvalid     = errors.New("x402: recovery proof does not verify")
	ErrProofSpent       = errors.New("x402: recovery proof already used")
	ErrNotOnChain       = errors.New("x402: transaction not found at confirmed commitment")
	ErrBusy             = errors.New("x402: transaction is being handled")
)

// Terms are the payment terms a challenge states: measured in production, a devnet set only on the unattested branch.
type Terms struct {
	Network  string // CAIP-2
	Treasury solana.PublicKey
	Mint     solana.PublicKey
}

// ParseTerms reads the terms from their text form; a placeholder treasury is no address and fails here.
func ParseTerms(network, treasury, mint string) (Terms, error) {
	if network == "" {
		return Terms{}, errors.New("x402: no network")
	}
	payTo, err := solana.PublicKeyFromBase58(treasury)
	if err != nil {
		return Terms{}, fmt.Errorf("x402: treasury: %w", err)
	}
	asset, err := solana.PublicKeyFromBase58(mint)
	if err != nil {
		return Terms{}, fmt.Errorf("x402: mint: %w", err)
	}
	return Terms{Network: network, Treasury: payTo, Mint: asset}, nil
}

// CreditCheck says whether the caller already holds a credit for a payment's digest, the check that survives a restart.
type CreditCheck func(ctx context.Context, digest string) (bool, error)

// Settled is a payment on chain, its transaction claimed until Release so no other request can credit it meanwhile.
type Settled struct {
	Payment

	ID       solana.Signature
	LandedAt time.Time // the block's time; zero when just settled here, and on a recovery when the node reports none
	// FormerFeePayer marks a recovery of a transaction another fee payer signed: it can return what was issued, never issue.
	FormerFeePayer bool
	release        func()
}

// Release ends the claim once the credit is done.
func (s *Settled) Release() { s.release() }

// Settler verifies, simulates, co-signs, sends and confirms payments; it holds the fee payer key and nothing else does.
type Settler struct {
	Terms          Terms
	Meter          *FeeMeter
	Limiter        *rate.Limiter // settlement attempts
	RecoverLimiter *rate.Limiter // recovery attempts carrying a valid proof
	ClaimLimiter   *rate.Limiter // claims that reach the chain, unauthenticated
	Poll           time.Duration
	Wait           time.Duration // how long a sent transaction is watched
	ReconcileAfter time.Duration // when a transaction left pending is looked at again
	Now            func() time.Time
	Logger         *slog.Logger

	policy        Policy
	feePayer      *FeePayer
	keys          *VirtualKeys
	primary       *solanarpc.Client // simulation, sending, status
	confirmer     *solanarpc.Client // an independent host a confirmation must also hold on
	active        *Claims           // payment digests a request is working on right now
	sent          *Claims           // payment digests that left the process and may still land
	proofs        *Claims           // recovery proofs already spent
	failed        *Claims           // payers and source accounts whose transaction landed failed
	proven        *Claims           // payers with a settled purchase behind them
	unsettled     *Claims           // payers and source accounts with a transaction not yet resolved
	claimNegative *Claims           // references a claim just found nothing under
	referenced    referenceCache    // readings of confirmed transactions under a reference

	hintMu         sync.Mutex
	hint           Extra
	hintUntil      time.Time
	hintRefreshing bool
}

// NewSettler wires a settler with the measured limits.
func NewSettler(
	terms Terms, feePayer *FeePayer, keys *VirtualKeys, primary, confirmer *solanarpc.Client, logger *slog.Logger,
) (*Settler, error) {
	policy, err := NewPolicy(feePayer.Public(), terms.Treasury, terms.Mint)
	if err != nil {
		return nil, err
	}
	s := &Settler{
		Terms:          terms,
		Meter:          &FeeMeter{Ceiling: DailyFeeCeilingLamports, FailureCeiling: DailyFailureCeilingLamports, Now: time.Now},
		Limiter:        rate.NewLimiter(attemptsPerSecond, attemptsBurst),
		RecoverLimiter: rate.NewLimiter(attemptsPerSecond, attemptsBurst),
		ClaimLimiter:   rate.NewLimiter(claimsPerSecond, claimsBurst),
		Poll:           pollInterval,
		Wait:           waitBudget,
		ReconcileAfter: reconcileAfter,
		Now:            time.Now,
		Logger:         logger,
		policy:         policy,
		feePayer:       feePayer,
		keys:           keys,
		primary:        primary,
		confirmer:      confirmer,
	}
	now := func() time.Time { return s.Now() }
	s.active = &Claims{TTL: activeTTL, Now: now}
	s.sent = &Claims{TTL: claimTTL, Now: now}
	s.proofs = &Claims{TTL: proofTTL, Now: now}
	s.failed = &Claims{TTL: failedPayerTTL, Now: now}
	s.proven = &Claims{TTL: failedPayerTTL, Now: now}
	s.unsettled = &Claims{TTL: failedPayerTTL, Now: now} // released by the outcome or the reconciliation
	s.claimNegative = &Claims{TTL: negativeTTL, Now: now}
	return s, nil
}

// VirtualKey is the gateway key of a payment's digest.
func (s *Settler) VirtualKey(digest string) string { return s.keys.ForPayment(digest) }

// ReferenceKey is the gateway key of a Solana Pay reference.
func (s *Settler) ReferenceKey(reference solana.PublicKey) string {
	return s.keys.ForReference(reference[:])
}

// TransferKey is the value of a Solana Pay transfer's marker, which never leaves.
func (s *Settler) TransferKey(id solana.Signature) string { return s.keys.ForTransfer(id[:]) }

func (s *Settler) bareRequirements(amount uint64) Requirements {
	return Requirements{
		Scheme:            scheme,
		Network:           s.Terms.Network,
		Amount:            strconv.FormatUint(amount, 10),
		Asset:             s.Terms.Mint.String(),
		PayTo:             s.Terms.Treasury.String(),
		MaxTimeoutSeconds: MaxTimeoutSeconds,
		Extra:             Extra{FeePayer: s.policy.FeePayer.String()},
	}
}

// Challenge is the PAYMENT-REQUIRED object for one payment, with a blockhash hint when one is available.
func (s *Settler) Challenge(ctx context.Context, resource Resource, amount uint64, reason string) Required {
	req := s.bareRequirements(amount)
	hint := s.blockhashHint(ctx)
	req.Extra.RecentBlockhash, req.Extra.LastValidBlockHeight = hint.RecentBlockhash, hint.LastValidBlockHeight
	return Required{X402Version: Version, Error: reason, Resource: resource, Accepts: []Requirements{req}}
}

// blockhashHint is best effort: without it the client fetches its own blockhash (scheme §PaymentRequirements). The call
// runs outside the lock, one at a time, so a stalled host costs a 402 nothing but its hint.
func (s *Settler) blockhashHint(ctx context.Context) Extra {
	s.hintMu.Lock()
	if s.Now().Before(s.hintUntil) || s.hintRefreshing {
		defer s.hintMu.Unlock()
		return s.hint
	}
	s.hintRefreshing = true
	s.hintMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, hintTimeout)
	defer cancel()
	hash, height, err := s.primary.LatestBlockhash(ctx)
	hint := Extra{}
	if err != nil {
		s.Logger.Warn("x402: no blockhash hint", "err", err)
	} else {
		hint = Extra{RecentBlockhash: hash, LastValidBlockHeight: strconv.FormatUint(height, 10)}
	}
	s.hintMu.Lock()
	defer s.hintMu.Unlock()
	s.hint, s.hintUntil, s.hintRefreshing = hint, s.Now().Add(blockhashHintTTL), false
	return hint
}

// checkAccepted compares the terms the client says it accepted with the terms of this request; the hints may differ.
func (s *Settler) checkAccepted(accepted Requirements, amount uint64) error {
	want := s.bareRequirements(amount)
	accepted.Extra.RecentBlockhash, accepted.Extra.LastValidBlockHeight = "", ""
	accepted.MaxTimeoutSeconds = want.MaxTimeoutSeconds
	if accepted != want {
		return reject(ReasonRequirements, "accepted terms differ from the challenge")
	}
	return nil
}

// Settle takes a client's payment from its bytes to a confirmed transaction, or refuses it. Everything before simulation
// works on the message's digest: the sponsor's signature, which is also the transaction's id, is computed only once
// simulation passed, or when the id is already public.
func (s *Settler) Settle(ctx context.Context, payload Payload, raw []byte, amount uint64, credited CreditCheck) (*Settled, error) {
	pay, err := s.checkPayment(payload, raw, amount)
	if err != nil {
		return nil, err
	}
	if !s.Limiter.Allow() {
		return nil, ErrRateLimited
	}
	digest := pay.Digest()
	if !s.active.Claim(digest) {
		return nil, reject(ReasonDuplicate, "being settled")
	}
	id, err := s.submitOnce(ctx, pay, credited)
	if err != nil {
		s.active.Release(digest)
		return nil, err
	}
	return &Settled{Payment: pay, ID: id, release: func() { s.active.Release(digest) }}, nil
}

func (s *Settler) checkPayment(payload Payload, raw []byte, amount uint64) (Payment, error) {
	if err := s.checkAccepted(payload.Accepted, amount); err != nil {
		return Payment{}, err
	}
	pay, err := s.policy.VerifyUnsigned(raw)
	if err != nil {
		return Payment{}, err
	}
	if pay.Amount != amount {
		return Payment{}, reject(ReasonAmountMismatch, "paying %d for %d", pay.Amount, amount)
	}
	if s.failed.Held(pay.Payer.String()) || s.failed.Held(pay.Source.String()) {
		return Payment{}, reject(ReasonPayerBarred, "%s", pay.Payer)
	}
	return pay, nil
}

func (s *Settler) submitOnce(ctx context.Context, pay Payment, credited CreditCheck) (solana.Signature, error) {
	digest := pay.Digest()
	if !s.sent.Claim(digest) {
		return solana.Signature{}, s.publicDuplicate(pay) // only bytes that left the process stay claimed here
	}
	preSend, cancel := context.WithTimeout(ctx, preSendBudget)
	defer cancel()
	has, err := credited(preSend, digest)
	if err == nil && !has {
		call, cancelCall := context.WithTimeout(preSend, rpcCallTimeout)
		defer cancelCall()
		err = s.simulate(call, pay)
	}
	if err != nil {
		s.sent.Release(digest) // nothing was committed, so the client may fix what failed and retry these bytes
		return solana.Signature{}, err
	}
	if has {
		return solana.Signature{}, s.publicDuplicate(pay)
	}
	if pay.reservedDay, err = s.reserve(pay); err != nil {
		s.sent.Release(digest)
		return solana.Signature{}, err
	}
	id := s.feePayer.TransactionID(pay)
	call, cancelCall := context.WithTimeout(preSend, rpcCallTimeout)
	defer cancelCall()
	known, err := s.seen(call, id.String())
	if err == nil && known {
		err = s.publicDuplicate(pay)
	} else if err != nil {
		s.sent.Release(digest)
	}
	if err != nil {
		s.unreserve(pay)
		return solana.Signature{}, err
	}
	return id, s.send(ctx, pay, id)
}

// reserve books the fee before the signature reaches any host. One transaction unresolved at a time per wallet and per
// source account, proven or not: holding fees hostage then takes real USDC per slot.
func (s *Settler) reserve(pay Payment) (string, error) {
	payer, source := pay.Payer.String(), pay.Source.String()
	if !s.unsettled.Claim(payer) {
		return "", reject(ReasonPayerUnresolved, "%s", payer)
	}
	if !s.unsettled.Claim(source) {
		s.unsettled.Release(payer)
		return "", reject(ReasonPayerUnresolved, "%s", source)
	}
	day, ok := s.Meter.Reserve(pay.FeeLamports, s.proven.Held(payer))
	if !ok {
		s.unsettled.Release(payer)
		s.unsettled.Release(source)
		return "", ErrFeeCeiling
	}
	return day, nil
}

func (s *Settler) unreserve(pay Payment) {
	s.Meter.Refund(pay.FeeLamports, pay.reservedDay)
	s.releaseUnsettled(pay)
}

func (s *Settler) releaseUnsettled(pay Payment) {
	s.unsettled.Release(pay.Payer.String())
	s.unsettled.Release(pay.Source.String())
}

// publicDuplicate may name the id: a credit on record or a transaction that left means the bytes are public already.
func (s *Settler) publicDuplicate(pay Payment) *RejectionError {
	return &RejectionError{Reason: ReasonDuplicate, Detail: "already settled", Transaction: s.feePayer.TransactionID(pay).String(),
		Payer: pay.Payer.String()}
}

// seen says whether a node knows the transaction at any commitment, failed or not: its bytes are public from then on and
// prove nothing about who presents them.
func (s *Settler) seen(ctx context.Context, id string) (bool, error) {
	status, err := s.primary.SignatureStatus(ctx, id)
	if err != nil {
		return false, fmt.Errorf("x402: status: %w", err)
	}
	return status != nil, nil
}

func (s *Settler) simulate(ctx context.Context, pay Payment) error {
	failure, err := s.primary.Simulate(ctx, pay.Raw)
	if err != nil {
		return fmt.Errorf("x402: simulate: %w", err)
	}
	switch failure {
	case "":
		return nil
	case `"InsufficientFundsForFee"`, `"AccountNotFound"`:
		// These two name the fee account, which is ours: the operator's funding routine, never the client's fault.
		s.Logger.Error("x402: fee payer unfunded", "fee_payer", s.feePayer.String(), "failure", failure)
		return ErrFeePayerUnfunded
	case `{"InstructionError":[2,{"Custom":1}]}`: // the transfer's slot, the token program's InsufficientFunds
		return reject(ReasonInsufficientFunds, "%s", failure)
	default:
		return reject(ReasonSimulationFailed, "%s", failure)
	}
}

// send signs and broadcasts, then watches. The client may hang up from here on: the payment still has to be seen through,
// or a settled transaction goes unanswered. A refused send is the only failure that means the bytes did not leave.
func (s *Settler) send(ctx context.Context, pay Payment, id solana.Signature) error {
	idText := id.String()
	settle, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.Wait)
	defer cancel()
	call, cancelCall := context.WithTimeout(settle, rpcCallTimeout)
	defer cancelCall()
	sent, err := s.primary.Send(call, s.feePayer.CoSign(pay))
	if rpcErr, refused := errors.AsType[*solanarpc.Error](err); refused && rpcErr.Definite() {
		s.unreserve(pay)
		s.sent.Release(pay.Digest())
		return fmt.Errorf("x402: send refused: %w", err)
	}
	if err != nil {
		s.Logger.Warn("x402: send outcome unknown", "tx", idText, "err", err) // watched as if sent, the fee stays booked
	} else if sent != idText {
		s.Logger.Error("x402: node reported another signature", "tx", idText, "reported", sent)
	}
	s.Logger.Info("x402: sent", "tx", idText, "fee_lamports", pay.FeeLamports, "fees_today_lamports", s.Meter.Spent())
	err = s.confirm(settle, idText)
	if err == nil {
		s.markSettled(pay)
		return nil
	}
	if rejection, ok := errors.AsType[*RejectionError](err); ok {
		rejection.Transaction, rejection.Payer = idText, pay.Payer.String()
		switch rejection.Reason {
		case ReasonTransactionFailed:
			s.markFailed(pay)
		case ReasonPending:
			time.AfterFunc(s.ReconcileAfter, func() { s.reconcile(pay, idText) }) //nolint:contextcheck // minutes after the reply
		}
	}
	return err
}

func (s *Settler) markSettled(pay Payment) {
	s.Meter.Resolved(pay.FeeLamports, pay.reservedDay)
	s.proven.Claim(pay.Payer.String())
	s.releaseUnsettled(pay)
}

// markFailed keeps the fee, which was spent, and bars the wallet and the source for a day.
func (s *Settler) markFailed(pay Payment) {
	s.failed.Claim(pay.Payer.String())
	s.failed.Claim(pay.Source.String())
	s.releaseUnsettled(pay)
}

// reconcile settles the books of a transaction left pending once it has landed or never will. A dropped transaction cost
// nothing, so its fee comes back, or griefers could fill the ceiling for free; only both hosts knowing nothing shows that.
// This is bookkeeping and no credit depends on it. Any doubt keeps the fee booked, the safe side, and frees the wallet.
func (s *Settler) reconcile(pay Payment, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcCallTimeout)
	defer cancel()
	status, err := s.primary.SignatureStatus(ctx, id)
	switch {
	case err != nil:
		s.Logger.Warn("x402: pending transaction not reconciled", "tx", id, "err", err)
		s.releaseUnsettled(pay)
	case status == nil:
		if second, secondErr := s.confirmer.SignatureStatus(ctx, id); secondErr == nil && second == nil {
			s.unreserve(pay)
			return
		}
		s.releaseUnsettled(pay)
	case status.Failure != "":
		s.markFailed(pay)
	case status.Confirmed:
		s.markSettled(pay)
	default:
		s.releaseUnsettled(pay)
	}
}

// confirm polls the primary until the transaction is confirmed and then holds out for the independent host too.
func (s *Settler) confirm(ctx context.Context, id string) error {
	for _, node := range []*solanarpc.Client{s.primary, s.confirmer} {
		if err := s.watch(ctx, node, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Settler) watch(ctx context.Context, node *solanarpc.Client, id string) error {
	ticker := time.NewTicker(s.Poll)
	defer ticker.Stop()
	for {
		call, cancel := context.WithTimeout(ctx, rpcCallTimeout)
		status, err := node.SignatureStatus(call, id)
		cancel()
		switch {
		case err != nil:
			s.Logger.Warn("x402: status unavailable", "tx", id, "err", err)
		case status == nil, !status.Confirmed:
		case status.Failure != "":
			return reject(ReasonTransactionFailed, "%s", status.Failure)
		default:
			return nil
		}
		select {
		case <-ctx.Done():
			return reject(ReasonPending, "no confirmation in %s", s.Wait)
		case <-ticker.C:
		}
	}
}

// RecoverRequest is the whole contract of a recovery: the transaction, the payer who proves it and the proof.
type RecoverRequest struct {
	Transaction string `json:"transaction"`
	Payer       string `json:"payer"`
	Timestamp   int64  `json:"timestamp"`
	Signature   string `json:"signature"`
}

// Recover checks a payer's proof, which costs nothing, then the chain, and claims the transaction for the caller's credit.
func (s *Settler) Recover(ctx context.Context, req RecoverRequest) (*Settled, error) {
	id, payer, err := s.checkProof(req)
	if err != nil {
		return nil, err
	}
	if !s.RecoverLimiter.Allow() {
		return nil, ErrRateLimited
	}
	pay, landedAt, err := s.confirmed(ctx, id)
	if err != nil {
		return nil, err
	}
	if pay.Payer != payer {
		return nil, ErrProofInvalid
	}
	digest := pay.Digest()
	if !s.active.Claim(digest) {
		return nil, ErrBusy
	}
	if !s.proofs.Claim(req.Signature) {
		s.active.Release(digest)
		return nil, ErrProofSpent
	}
	return &Settled{Payment: pay, ID: id, LandedAt: landedAt, FormerFeePayer: pay.Tx.Message.AccountKeys[0] != s.feePayer.Public(),
		release: func() { s.active.Release(digest) }}, nil
}

func (s *Settler) checkProof(req RecoverRequest) (solana.Signature, solana.PublicKey, error) {
	id, err := solana.SignatureFromBase58(req.Transaction)
	if err != nil {
		return id, solana.PublicKey{}, fmt.Errorf("%w: transaction must be a base58 signature", ErrBadRecovery)
	}
	payer, err := solana.PublicKeyFromBase58(req.Payer)
	if err != nil {
		return id, payer, fmt.Errorf("%w: payer must be a base58 address", ErrBadRecovery)
	}
	proof, err := solana.SignatureFromBase58(req.Signature)
	if err != nil {
		return id, payer, fmt.Errorf("%w: signature must be a base58 signature", ErrBadRecovery)
	}
	if age := s.Now().Sub(time.Unix(req.Timestamp, 0)); age > recoverWindow || age < -recoverWindow {
		return id, payer, fmt.Errorf("%w: timestamp must be within %s of now", ErrBadRecovery, recoverWindow)
	}
	if !VerifyRecoverProof(payer, id, req.Timestamp, proof) {
		return id, payer, ErrProofInvalid
	}
	return id, payer, nil
}

// confirmed reads a transaction back from the chain: it must have landed successfully, carry its own fee payer's signature,
// pass the whole policy, and be confirmed on the independent host too. That fee payer may be a former one, see FormerFeePayer.
func (s *Settler) confirmed(ctx context.Context, id solana.Signature) (Payment, time.Time, error) {
	call, cancel := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancel()
	got, err := s.primary.Transaction(call, id.String())
	if err != nil {
		return Payment{}, time.Time{}, fmt.Errorf("x402: read transaction: %w", err)
	}
	if got == nil {
		return Payment{}, time.Time{}, ErrNotOnChain
	}
	if got.Failure != "" {
		return Payment{}, time.Time{}, reject(ReasonTransactionFailed, "%s", got.Failure)
	}
	pay, err := s.policy.VerifyLanded(got.Raw)
	if err != nil {
		return Payment{}, time.Time{}, err
	}
	if pay.Tx.Signatures[0] != id {
		return Payment{}, time.Time{}, reject(ReasonSponsorSignature, "node returned another transaction")
	}
	second, cancelSecond := context.WithTimeout(ctx, rpcCallTimeout)
	defer cancelSecond()
	status, err := s.confirmer.SignatureStatus(second, id.String())
	if err != nil {
		return Payment{}, time.Time{}, fmt.Errorf("x402: independent status: %w", err)
	}
	if status == nil || !status.Confirmed || status.Failure != "" {
		return Payment{}, time.Time{}, reject(ReasonPending, "not confirmed on the independent host")
	}
	return pay, got.BlockTime, nil
}
