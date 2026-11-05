package sales

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
)

const settledNotCredited = "payment settled but the key is not issued yet: call " + recoverRoute

// saleReply is the body of a credited purchase; a top-up leaves Key empty, the caller already holding it.
type saleReply struct {
	Key          string   `json:"key,omitempty"`
	Alias        string   `json:"alias"`
	MaxBudgetUSD float64  `json:"max_budget_usd"`
	RPMLimit     int      `json:"rpm_limit"`
	Models       []string `json:"models"`
	Transaction  string   `json:"transaction"`
}

func replyFor(info usage.KeyInfo) saleReply {
	return saleReply{Alias: info.Alias, MaxBudgetUSD: info.MaxBudgetUSD, RPMLimit: info.RPMLimit, Models: info.Models}
}

// failureReply is the body of a failure that concerns a transaction.
type failureReply struct {
	Error       string `json:"error"`
	Transaction string `json:"transaction,omitempty"`
}

func (s *Sales) setHeader(w http.ResponseWriter, name string, v any) {
	value, err := x402.EncodeHeader(v)
	if err != nil {
		s.logger.Error("x402: header", "name", name, "err", err)
		return
	}
	w.Header().Set(name, value)
}

func resourceFor(r *http.Request) x402.Resource {
	return x402.Resource{URL: "https://" + r.Host + buyRoute, Description: "A virtual key with credits", MimeType: "application/json"}
}

func (s *Sales) writeChallenge(w http.ResponseWriter, r *http.Request, amount uint64, reason string) {
	s.setHeader(w, x402.HeaderRequired, s.settler.Challenge(r.Context(), resourceFor(r), amount, reason))
	httpjson.Write(w, http.StatusPaymentRequired, struct{}{})
}

// writeBuyFailure maps a settlement error to its reply. A payment's own failure names its reason; a challenge goes with
// it only while nothing left the process, since a transaction that may still land must not invite a second payment.
func (s *Sales) writeBuyFailure(w http.ResponseWriter, r *http.Request, amount uint64, err error) {
	s.rejected.Add(1)
	if errors.Is(err, x402.ErrRateLimited) {
		httpjson.Error(w, http.StatusTooManyRequests, "too many attempts, retry shortly")
		return
	}
	rejection, isRejection := errors.AsType[*x402.RejectionError](err)
	if !isRejection {
		s.logger.Error("x402: settlement unavailable", "err", err, "rejected_total", s.rejected.Load())
		httpjson.Error(w, http.StatusServiceUnavailable, "settlement unavailable, retry shortly")
		return
	}
	level := slog.LevelInfo
	if rejection.Reason == x402.ReasonPending { // the alert: a rate-limited second host leaves every purchase here
		level = slog.LevelError
	}
	s.logger.Log(r.Context(), level, "x402: payment refused", "tx", rejection.Transaction, "reason", rejection.Reason,
		"detail", rejection.Detail, "rejected_total", s.rejected.Load())
	status := http.StatusPaymentRequired
	message := rejection.Reason
	switch rejection.Reason {
	case x402.ReasonMalformed:
		status = http.StatusBadRequest
	case x402.ReasonDuplicate:
		status = http.StatusConflict
		message += ": if the key was lost, call " + recoverRoute
	}
	s.setHeader(w, x402.HeaderResponse, x402.Settlement{ErrorReason: rejection.Reason, Transaction: rejection.Transaction,
		Network: s.settler.Terms.Network, Payer: rejection.Payer})
	if status == http.StatusPaymentRequired && rejection.Transaction == "" {
		s.setHeader(w, x402.HeaderRequired, s.settler.Challenge(r.Context(), resourceFor(r), amount, rejection.Reason))
	}
	httpjson.Write(w, status, failureReply{Error: message, Transaction: rejection.Transaction})
}

// settledButNotCredited is the one reply where money moved and the key did not: it says how to get the key.
func (s *Sales) settledButNotCredited(w http.ResponseWriter, settled *x402.Settled, err error) {
	s.logger.Error("x402: settled but not credited", "tx", settled.ID, "err", err)
	s.setHeader(w, x402.HeaderResponse, s.success(settled))
	httpjson.Write(w, http.StatusBadGateway, failureReply{Error: settledNotCredited, Transaction: settled.ID.String()})
}

func (s *Sales) success(settled *x402.Settled) x402.Settlement {
	return x402.Settlement{Success: true, Transaction: settled.ID.String(), Network: s.settler.Terms.Network, Payer: settled.Payer.String()}
}

func (s *Sales) writeKey(w http.ResponseWriter, settled *x402.Settled, key string, row usage.KeyInfo) {
	reply := replyFor(row)
	reply.Key = key
	s.writeReply(w, settled, reply)
}

func (s *Sales) writeReply(w http.ResponseWriter, settled *x402.Settled, reply saleReply) {
	reply.Transaction = settled.ID.String()
	s.setHeader(w, x402.HeaderResponse, s.success(settled))
	httpjson.Write(w, http.StatusOK, reply)
}
