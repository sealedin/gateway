package sales

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
)

// issueWindow is how long after landing a payment with no key on record still gets one: long enough to outlast an outage,
// short enough that a lost database or a deleted key does not reissue every payment ever made.
const issueWindow = 7 * 24 * time.Hour

// topUpRecoveryReply is what the payer of a finished top-up learns.
type topUpRecoveryReply struct {
	CreditedUSD float64 `json:"credited_usd"`
	Transaction string  `json:"transaction"`
}

func (s *Sales) recoverKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req x402.RecoverRequest
	if err := httpjson.DecodeStrict(r, maxBodyBytes, &req); err != nil {
		httpjson.Error(w, httpjson.DecodeStatus(err), err.Error())
		return
	}
	settled, err := s.settler.Recover(r.Context(), req)
	if err != nil {
		s.writeRecoverFailure(r.Context(), w, err)
		return
	}
	defer settled.Release()
	ctx, cancel := creditContext(r)
	defer cancel()
	s.recoverCredit(ctx, w, settled) //nolint:contextcheck // detached on purpose, see creditContext
}

func (s *Sales) writeRecoverFailure(ctx context.Context, w http.ResponseWriter, err error) {
	s.rejected.Add(1)
	rejection, isRejection := errors.AsType[*x402.RejectionError](err)
	level := slog.LevelInfo
	if isRejection && rejection.Reason == x402.ReasonPending { // the same alert as a pending purchase
		level = slog.LevelError
	}
	s.logger.Log(ctx, level, "x402: recovery refused", "err", err, "rejected_total", s.rejected.Load())
	switch {
	case isRejection:
		httpjson.Error(w, http.StatusConflict, rejection.Reason)
	case errors.Is(err, x402.ErrBadRecovery):
		httpjson.Error(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, x402.ErrProofInvalid):
		w.WriteHeader(http.StatusUnauthorized)
	case errors.Is(err, x402.ErrRateLimited):
		httpjson.Error(w, http.StatusTooManyRequests, "too many attempts, retry shortly")
	case errors.Is(err, x402.ErrNotOnChain):
		httpjson.Error(w, http.StatusNotFound, "transaction not found at confirmed commitment")
	case errors.Is(err, x402.ErrProofSpent):
		httpjson.Error(w, http.StatusConflict, "this recovery proof was already used, sign a new one")
	case errors.Is(err, x402.ErrBusy):
		httpjson.Error(w, http.StatusConflict, "this transaction is being handled, retry shortly with a new proof")
	default:
		s.logger.Error("x402: recovery unavailable", "err", err)
		httpjson.Error(w, http.StatusServiceUnavailable, "cannot read the chain, retry shortly")
	}
}

// recoverCredit finishes what a crash or a lost key left, read from the gateway alone so it survives a restart: a top-up, a
// key to hand back, or a key never issued. The same key comes back every time, so a payer cannot revoke a leaked one.
func (s *Sales) recoverCredit(ctx context.Context, w http.ResponseWriter, settled *x402.Settled) {
	digest := settled.Digest()
	existing, err := s.gateway.LookupAlias(ctx, AliasFor(digest))
	switch {
	case errors.Is(err, usage.ErrKeyUnknown) && settled.FormerFeePayer:
		// Nothing on record says this enclave ever handled it, and anyone can pay a fee: issuing would be a second way in.
		s.logger.Error("x402: a former fee payer's transaction has no key, operator must reconcile", "tx", settled.ID)
		httpjson.Error(w, http.StatusConflict, "no key on record and settled under a former fee payer; the operator must reconcile it")
	case errors.Is(err, usage.ErrKeyUnknown):
		s.issueRecent(ctx, w, settled)
	case err != nil:
		s.settledButNotCredited(w, settled, err)
	case existing.Metadata[markerKindField] == markerKindTopUp:
		s.recoverTopUp(ctx, w, settled, existing)
	case existing.Blocked:
		// The operator's revocation: a proof must not undo it.
		s.logger.Warn("x402: recovery of a revoked key refused", "tx", settled.ID, "alias", existing.Alias)
		httpjson.Error(w, http.StatusConflict, "this key was revoked")
	default:
		s.returnKey(w, settled, existing)
	}
}

// returnKey re-derives the key on record. A row whose token is not that derivation was not issued here, so it fails closed.
func (s *Sales) returnKey(w http.ResponseWriter, settled *x402.Settled, row usage.KeyInfo) {
	key := s.settler.VirtualKey(settled.Digest())
	if usage.TokenHash(key) != row.Token {
		s.logger.Error("x402: key on record is not the derived one, operator must reconcile", "tx", settled.ID, "alias", row.Alias)
		httpjson.Error(w, http.StatusConflict, "the key on record cannot be recovered")
		return
	}
	s.logger.Info("x402: key recovered", "tx", settled.ID, "alias", row.Alias)
	s.writeKey(w, settled, key, row)
}

// issueRecent issues the key a crash left unissued. A row that vanished from an old payment may have been spent or deleted
// on purpose, so only a recent one counts as a crash; a node reporting no block time cannot show that.
func (s *Sales) issueRecent(ctx context.Context, w http.ResponseWriter, settled *x402.Settled) {
	if s.settler.Now().Sub(settled.LandedAt) > issueWindow {
		s.logger.Error("x402: old transaction has no key, operator must reconcile", "tx", settled.ID, "landed_at", settled.LandedAt)
		httpjson.Error(w, http.StatusConflict, "this payment is too old to issue a key automatically")
		return
	}
	s.issueKey(ctx, w, settled)
}

func (s *Sales) recoverTopUp(ctx context.Context, w http.ResponseWriter, settled *x402.Settled, marker usage.KeyInfo) {
	target, ok := marker.Metadata[markerTargetField].(string)
	if !ok {
		s.settledButNotCredited(w, settled, errors.New("sales: top-up marker names no target"))
		return
	}
	_, err := s.applyTopUp(ctx, target, marker.Alias, settled.Amount)
	if errors.Is(err, errTargetGone) {
		s.logger.Error("x402: top-up target gone, operator must reconcile", "tx", settled.ID, "alias", marker.Alias)
		httpjson.Error(w, http.StatusConflict, "the key this top-up was for no longer exists")
		return
	}
	if err != nil {
		s.settledButNotCredited(w, settled, err)
		return
	}
	// The amount only: the payer of a top-up need not be the key's holder, and its budget is the holder's business.
	s.setHeader(w, x402.HeaderResponse, s.success(settled))
	httpjson.Write(w, http.StatusOK, topUpRecoveryReply{CreditedUSD: toUSD(settled.Amount), Transaction: settled.ID.String()})
}
