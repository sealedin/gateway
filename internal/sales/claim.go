package sales

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gagliardetto/solana-go"

	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
)

const (
	claimRoute       = "/v1/keys/claim"
	claimAliasPrefix = "pay-"
	claimTxPrefix    = "pay-tx-"
	retryAfter       = "3" // seconds; a poll within this is answered from the negative cache anyway

	// The machine-readable reasons of a final refusal.
	reasonBadCode           = "bad_code"
	reasonBelowMinimum      = "below_minimum"
	reasonRevoked           = "revoked"
	reasonCreditedElsewhere = "credited_elsewhere"
	reasonTargetGone        = "target_gone"
)

// claimFailure is the body of a refusal the buyer's page shows.
type claimFailure struct {
	Error       string `json:"error"`
	Reason      string `json:"reason"`
	Transaction string `json:"transaction,omitempty"`
}

// claim turns what was paid under the reference behind a code into a key. It can be repeated: the key and each transaction's
// credit are derived, so nothing happens twice. The code never goes in a log, a URL or an error.
func (s *Sales) claim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Code string `json:"code"`
	}
	if err := httpjson.DecodeStrict(r, maxBodyBytes, &req); err != nil {
		httpjson.Write(w, httpjson.DecodeStatus(err), claimFailure{Error: "the body must be a JSON object with a code", Reason: reasonBadCode})
		return
	}
	reference, err := x402.ParseClaimCode(req.Code)
	if err != nil {
		httpjson.Write(w, http.StatusBadRequest, claimFailure{Error: err.Error(), Reason: reasonBadCode})
		return
	}
	target, ok := s.topUpTarget(w, r)
	if !ok {
		return
	}
	paid, pending, err := s.settler.PaymentsFor(r.Context(), reference)
	switch {
	case errors.Is(err, x402.ErrRateLimited):
		w.Header().Set("Retry-After", retryAfter)
		httpjson.Error(w, http.StatusTooManyRequests, "too many attempts, retry shortly")
		return
	case err != nil:
		s.logger.Error("x402: claim cannot read the chain", "err", err)
		httpjson.Error(w, http.StatusServiceUnavailable, "cannot read the chain, retry shortly")
		return
	}
	credible, under := s.splitByMinimum(paid)
	if len(credible) == 0 {
		s.answerNothingCredible(w, under, pending)
		return
	}
	ctx, cancel := creditContext(r)
	defer cancel()
	s.creditClaim(ctx, w, reference, target, credible) //nolint:contextcheck // detached on purpose, see creditContext
}

// splitByMinimum keeps what can be credited. What cannot stays in the treasury, so it is logged for the operator to reconcile.
func (s *Sales) splitByMinimum(paid []x402.ReferencePayment) ([]x402.ReferencePayment, []x402.ReferencePayment) {
	var credible, under []x402.ReferencePayment
	for _, payment := range paid {
		if payment.Amount >= minPurchaseUSD*baseUnitsPerUSD {
			credible = append(credible, payment)
			continue
		}
		under = append(under, payment)
		if s.reconciling.Claim(payment.ID.String()) { // a poll repeats this, and anyone can pay dust and poll
			s.logger.Error("x402: a payment under the minimum was not credited, operator must reconcile",
				"tx", payment.ID, "amount", payment.Amount)
		}
	}
	return credible, under
}

func (s *Sales) answerNothingCredible(w http.ResponseWriter, under []x402.ReferencePayment, pending bool) {
	if len(under) == 0 || pending {
		w.Header().Set("Retry-After", retryAfter)
		httpjson.Write(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}
	last := under[len(under)-1]
	httpjson.Write(w, http.StatusConflict, claimFailure{
		Error: fmt.Sprintf("the payment of %s USD is below the %d USD minimum, so nothing was issued; contact support with the transaction",
			strconv.FormatFloat(toUSD(last.Amount), 'f', -1, 64), minPurchaseUSD),
		Reason: reasonBelowMinimum, Transaction: last.ID.String(),
	})
}

func (s *Sales) creditClaim(
	ctx context.Context, w http.ResponseWriter, reference solana.PublicKey, target string, paid []x402.ReferencePayment,
) {
	key := ""
	if target == "" {
		key = s.settler.ReferenceKey(reference)
		row, err := s.claimRow(ctx, reference, key)
		if errors.Is(err, errRevoked) {
			s.logger.Warn("x402: a claim on a revoked key refused", "last_tx", paid[len(paid)-1].ID)
			httpjson.Write(w, http.StatusConflict, claimFailure{Error: "this key was revoked", Reason: reasonRevoked})
			return
		}
		if err != nil {
			s.claimUnfinished(w, err)
			return
		}
		target = row.Token
	}
	creditedHere := false
	for _, payment := range paid {
		decided, err := s.creditTransfer(ctx, payment, target)
		creditedHere = creditedHere || decided == target
		if errors.Is(err, errTargetGone) {
			s.logger.Error("x402: the key a payment was credited to is gone, operator must reconcile", "tx", payment.ID)
			httpjson.Write(w, http.StatusConflict, claimFailure{Error: "the key this payment was for no longer exists",
				Reason: reasonTargetGone, Transaction: payment.ID.String()})
			return
		}
		if err != nil {
			s.claimUnfinished(w, err)
			return
		}
	}
	info, err := s.gateway.LookupKey(ctx, target)
	if err != nil {
		s.claimUnfinished(w, err)
		return
	}
	last := paid[len(paid)-1].ID.String()
	if !creditedHere { // an earlier claim for another key took every payment
		httpjson.Write(w, http.StatusConflict, claimFailure{Error: "this payment was already credited to another key",
			Reason: reasonCreditedElsewhere, Transaction: last})
		return
	}
	reply := replyFor(info)
	reply.Key = key
	reply.Transaction = last
	httpjson.Write(w, http.StatusOK, reply)
}

var errRevoked = errors.New("sales: revoked")

// claimRow makes sure the reference's key exists, with no budget until a transaction's credit lands on it.
func (s *Sales) claimRow(ctx context.Context, reference solana.PublicKey, key string) (usage.KeyInfo, error) {
	alias := claimAliasPrefix + hex.EncodeToString(reference[:])[:aliasHashChars]
	row, err := s.ensureRow(ctx, alias, usage.KeyLimits{Models: s.models, RPMLimit: usage.DefaultRPMLimit, Key: key})
	switch {
	case err != nil:
		return usage.KeyInfo{}, err
	case row.Blocked:
		return usage.KeyInfo{}, errRevoked
	case row.Alias != alias:
		return usage.KeyInfo{}, errors.New("sales: the row is not this reference's key")
	}
	return row, nil
}

// creditTransfer credits one transaction once, as a top-up does: a durable marker first, naming the key, then the credit, which
// records the marker in the same update. The first marker decides the key, so a second claim cannot move the money.
// It returns the key that got it.
func (s *Sales) creditTransfer(ctx context.Context, payment x402.ReferencePayment, target string) (string, error) {
	digest := sha256.Sum256(payment.ID[:])
	alias := claimTxPrefix + hex.EncodeToString(digest[:])[:aliasHashChars]
	key := s.settler.TransferKey(payment.ID)
	marker := usage.KeyLimits{Models: s.models, RPMLimit: markerRPM, Key: key, Blocked: true,
		Metadata: map[string]any{markerKindField: markerKindTopUp, markerTargetField: target}}
	row, err := s.ensureRow(ctx, alias, marker)
	if err != nil {
		return "", err
	}
	decided, ok := row.Metadata[markerTargetField].(string)
	if !ok || row.Metadata[markerKindField] != markerKindTopUp {
		return "", errors.New("sales: the row under this transfer is not its marker")
	}
	_, err = s.applyTopUp(ctx, decided, alias, payment.Amount)
	return decided, err
}

// ensureRow reads a derived key's row, creating it the first time. The gateway refuses an alias it has already, so a claim that
// lost a race sees an error and then the row.
func (s *Sales) ensureRow(ctx context.Context, alias string, limits usage.KeyLimits) (usage.KeyInfo, error) {
	row, err := s.gateway.LookupKey(ctx, limits.Key)
	if !errors.Is(err, usage.ErrKeyUnknown) {
		return row, err
	}
	if _, err = s.gateway.Issue(ctx, alias, limits); err != nil {
		s.logger.Info("x402: issuing a claim's row failed, reading it back", "alias", alias, "err", err)
	}
	return s.gateway.LookupKey(ctx, limits.Key)
}

func (s *Sales) claimUnfinished(w http.ResponseWriter, err error) {
	s.logger.Error("x402: a confirmed payment is not credited yet", "err", err)
	w.Header().Set("Retry-After", retryAfter)
	httpjson.Error(w, http.StatusServiceUnavailable, "the payment is confirmed but the gateway is unavailable, retry shortly")
}
