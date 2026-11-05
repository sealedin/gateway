package sales

import (
	"context"
	"errors"
	"maps"
	"math"
	"net/http"
	"slices"
	"strings"

	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
)

// The marker a top-up leaves under its transaction's alias, and the list of credits a key keeps in its metadata.
const (
	markerKindField   = "x402_kind"
	markerKindTopUp   = "top-up"
	markerTargetField = "x402_target"
	appliedField      = "x402_topups"
	markerRPM         = 1
)

// errTargetGone means a top-up's key was deleted; whether it was credited can no longer be told.
var errTargetGone = errors.New("sales: top-up target gone")

// topUpTarget reads the bearer of a top-up, refusing a bad key before anyone pays; empty for a purchase of a new key.
func (s *Sales) topUpTarget(w http.ResponseWriter, r *http.Request) (string, bool) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return "", true
	}
	key, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || !strings.HasPrefix(key, "sk-") { // a token hash is a handle, not proof of holding the key
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	}
	if !s.lookups.Allow() {
		w.Header().Set("Retry-After", retryAfter)
		httpjson.Error(w, http.StatusTooManyRequests, "too many attempts, retry shortly")
		return "", false
	}
	info, err := s.gateway.LookupKey(r.Context(), key)
	switch {
	case errors.Is(err, usage.ErrKeyUnknown), err == nil && info.Blocked:
		w.WriteHeader(http.StatusUnauthorized)
		return "", false
	case err != nil:
		s.logger.Error("x402: gateway call failed", "err", err)
		httpjson.Error(w, http.StatusBadGateway, "gateway unavailable")
		return "", false
	}
	return info.Token, true
}

// finishTopUp leaves a durable marker under the transaction's alias, then credits the key; a crash at either step leaves
// recovery able to tell what happened, so a transaction is credited once. The marker has the value a key for this payment
// would have, so the two cannot both exist; it is blocked and its value never leaves.
func (s *Sales) finishTopUp(ctx context.Context, w http.ResponseWriter, settled *x402.Settled, target string) {
	digest := settled.Digest()
	alias := AliasFor(digest)
	key := s.settler.VirtualKey(digest)
	marker := usage.KeyLimits{Models: s.models, RPMLimit: markerRPM, Key: key, Blocked: true,
		Metadata: map[string]any{markerKindField: markerKindTopUp, markerTargetField: target}}
	if _, err := s.gateway.Issue(ctx, alias, marker); err != nil {
		s.settledButNotCredited(w, settled, err)
		return
	}
	// The upsert may have kept a key that lost a race: crediting the target too would pay twice.
	row, err := s.gateway.LookupKey(ctx, key)
	if err == nil && (row.Metadata[markerKindField] != markerKindTopUp || row.Metadata[markerTargetField] != target) {
		err = errors.New("sales: the row under this payment is not its top-up marker")
	}
	if err != nil {
		s.settledButNotCredited(w, settled, err)
		return
	}
	info, err := s.applyTopUp(ctx, target, alias, settled.Amount)
	if err != nil {
		s.settledButNotCredited(w, settled, err)
		return
	}
	s.writeReply(w, settled, replyFor(info))
}

// applyTopUp credits the key once per alias: the budget and the record of the credit change in one update.
func (s *Sales) applyTopUp(ctx context.Context, target, alias string, amount uint64) (usage.KeyInfo, error) {
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	info, err := s.gateway.LookupKey(ctx, target)
	if errors.Is(err, usage.ErrKeyUnknown) {
		return usage.KeyInfo{}, errTargetGone
	}
	if err != nil {
		return usage.KeyInfo{}, err
	}
	applied, _ := info.Metadata[appliedField].([]any)
	if slices.Contains(applied, any(alias)) {
		return info, nil
	}
	metadata := make(map[string]any, len(info.Metadata)+1)
	maps.Copy(metadata, info.Metadata)
	metadata[appliedField] = append(slices.Clone(applied), alias)
	budget := math.Round((info.MaxBudgetUSD+toUSD(amount))*baseUnitsPerUSD) / baseUnitsPerUSD
	if err = s.gateway.SetBudget(ctx, target, budget, metadata); err != nil {
		return usage.KeyInfo{}, err
	}
	s.logger.Info("x402: topped up", "alias", info.Alias, "topped_up_total", s.toppedUp.Add(1))
	info.MaxBudgetUSD = budget
	return info, nil
}
