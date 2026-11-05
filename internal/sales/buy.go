package sales

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
)

const (
	minPurchaseUSD  = 20 // per purchase; per-day limits are deliberately not enforced here
	maxPurchaseUSD  = 500
	baseUnitsPerUSD = 1_000_000 // USDC has six decimals and buys credits 1:1
	fractionDigits  = len("000000")
)

// amountPattern is a plain decimal of at most six fraction digits: no exponents, no sign, no string in disguise.
var amountPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})(\.[0-9]{1,6})?$`)

func (s *Sales) buy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	amount, err := decodeAmount(r)
	if err != nil {
		httpjson.Error(w, httpjson.DecodeStatus(err), err.Error())
		return
	}
	target, ok := s.topUpTarget(w, r)
	if !ok {
		return
	}
	header := r.Header.Get(x402.HeaderSignature)
	if header == "" {
		s.writeChallenge(w, r, amount, x402.HeaderSignature+" header is required")
		return
	}
	payload, raw, err := x402.DecodePayload(header)
	if err != nil {
		s.rejected.Add(1)
		httpjson.Error(w, http.StatusBadRequest, x402.ReasonMalformed)
		return
	}
	settled, err := s.settler.Settle(r.Context(), payload, raw, amount, s.credited)
	if err != nil {
		s.writeBuyFailure(w, r, amount, err)
		return
	}
	defer settled.Release()
	s.logger.Info("x402: settled", "tx", settled.ID, "amount", settled.Amount)
	ctx, cancel := creditContext(r)
	defer cancel()
	if target != "" {
		s.finishTopUp(ctx, w, settled, target) //nolint:contextcheck // detached on purpose, see creditContext
		return
	}
	s.issueKey(ctx, w, settled) //nolint:contextcheck // detached on purpose, see creditContext
}

// creditContext detaches from the client: the money moved, so hanging up must not abandon the credit.
func creditContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), x402.CreditBudget)
}

// credited says whether a payment already has a key at the gateway. A row under the alias with another token is not this
// payment's: 128 bits of alias prove less than the token does, and a yes here makes the transaction's id public.
func (s *Sales) credited(ctx context.Context, digest string) (bool, error) {
	row, err := s.gateway.LookupAlias(ctx, AliasFor(digest))
	if errors.Is(err, usage.ErrKeyUnknown) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("x402: alias lookup: %w", err)
	}
	if row.Token != usage.TokenHash(s.settler.VirtualKey(digest)) {
		return false, errors.New("x402: the key under this alias is not this payment's")
	}
	return true, nil
}

// issueKey is the one place a payment becomes a new key. In a race the gateway's upsert succeeds without changing the row,
// so the reply is read back from the row, and a row that is not this payment's key gets no reply with a key in it.
func (s *Sales) issueKey(ctx context.Context, w http.ResponseWriter, settled *x402.Settled) {
	digest := settled.Digest()
	alias := AliasFor(digest)
	key := s.settler.VirtualKey(digest)
	_, err := s.gateway.Issue(ctx, alias, usage.KeyLimits{MaxBudgetUSD: toUSD(settled.Amount), Models: s.models,
		RPMLimit: usage.DefaultRPMLimit, Key: key})
	if err != nil {
		s.settledButNotCredited(w, settled, err)
		return
	}
	row, err := s.gateway.LookupKey(ctx, key)
	if err == nil && (row.Alias != alias || row.Blocked) {
		err = errors.New("sales: the issued row is not this payment's key")
	}
	if err != nil {
		s.settledButNotCredited(w, settled, err)
		return
	}
	s.logger.Info("x402: issued", "tx", settled.ID, "alias", alias, "issued_total", s.issued.Add(1))
	s.writeKey(w, settled, key, row)
}

func decodeAmount(r *http.Request) (uint64, error) {
	var req struct {
		AmountUSD json.RawMessage `json:"amount_usd"`
	}
	if err := httpjson.DecodeStrict(r, maxBodyBytes, &req); err != nil {
		return 0, err
	}
	base, ok := parseBaseUnits(string(req.AmountUSD))
	if !ok || base < minPurchaseUSD*baseUnitsPerUSD || base > maxPurchaseUSD*baseUnitsPerUSD {
		return 0, fmt.Errorf("amount_usd must be a number from %d to %d with at most 6 decimals", minPurchaseUSD, maxPurchaseUSD)
	}
	return base, nil
}

// parseBaseUnits converts the literal digits, never through a float: 20.000001 USD is exactly 20000001 base units.
func parseBaseUnits(literal string) (uint64, bool) {
	if !amountPattern.MatchString(literal) {
		return 0, false
	}
	whole, fraction, _ := strings.Cut(literal, ".")
	digits := whole + fraction + strings.Repeat("0", fractionDigits-len(fraction))
	base, err := strconv.ParseUint(digits, 10, 64)
	return base, err == nil
}

func toUSD(base uint64) float64 { return float64(base) / baseUnitsPerUSD }
