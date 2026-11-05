// Package keys is the operator's key issuance on the identity's private listener: bearer-authenticated, every key scoped
// to the measured catalog, backed by the gateway's admin API with the in-CVM master key the client never sees.
package keys

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/usage"
)

const (
	// MaxBudgetUSD is the measured ceiling of one key's budget: a typo or a stolen operator token cannot mint an
	// unbounded key.
	MaxBudgetUSD = 10_000
	// MaxRPMLimit is the measured ceiling of one key's rate limit.
	MaxRPMLimit  = 600
	maxBodyBytes = 4 << 10 // alias, budget, rpm: anything larger is not a request of ours
)

// aliasPattern bounds what a key alias may be; it is echoed to LiteLLM and back, nothing else.
var aliasPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

var errBadAlias = errors.New("alias must match " + aliasPattern.String())

// Service issues and looks up virtual keys; an empty Operator refuses every request.
type Service struct {
	Gateway  *usage.Gateway
	Operator string   // bearer the edge-only route requires
	Models   []string // the measured catalog every key is scoped to
	Logger   *slog.Logger

	rejected atomic.Int64 // bearer failures since start, logged so a probing client is visible
}

// log is the injected logger, or the process default when a caller wired none.
func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.Default()
	}
	return s.Logger
}

// Register mounts the two routes on mux; both demand the operator bearer.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/keys", s.authed(s.issue))
	mux.HandleFunc("GET /v1/keys/{alias}", s.authed(s.lookup))
}

// authed answers 401 with no body unless the bearer equals the operator key; empty never matches empty.
func (s *Service) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || s.Operator == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.Operator)) != 1 {
			s.log().Warn("keys: bearer rejected", "path", r.URL.Path, "rejected_total", s.rejected.Add(1))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// issueRequest is the whole request contract: unknown fields are rejected, so a caller cannot widen the scope.
type issueRequest struct {
	Alias        string   `json:"alias"`
	MaxBudgetUSD *float64 `json:"max_budget_usd"`
	RPMLimit     *int     `json:"rpm_limit"`
}

func (s *Service) issue(w http.ResponseWriter, r *http.Request) {
	req, err := decodeIssue(r)
	if err != nil {
		httpjson.Error(w, httpjson.DecodeStatus(err), err.Error())
		return
	}
	rpm := usage.DefaultRPMLimit
	if req.RPMLimit != nil {
		rpm = *req.RPMLimit
	}
	issued, err := s.Gateway.Issue(r.Context(), req.Alias, usage.KeyLimits{
		MaxBudgetUSD: *req.MaxBudgetUSD,
		Models:       s.Models,
		RPMLimit:     rpm,
	})
	if err != nil {
		s.writeGatewayError(w, err)
		return
	}
	s.log().Info("keys: issued", "alias", issued.Alias, "max_budget_usd", issued.MaxBudgetUSD, "rpm_limit", issued.RPMLimit)
	httpjson.Write(w, http.StatusOK, map[string]any{
		"key":            issued.Key,
		"alias":          issued.Alias,
		"max_budget_usd": issued.MaxBudgetUSD,
		"rpm_limit":      issued.RPMLimit,
		"models":         issued.Models,
	})
}

func decodeIssue(r *http.Request) (issueRequest, error) {
	var req issueRequest
	if err := httpjson.DecodeStrict(r, maxBodyBytes, &req); err != nil {
		return req, err
	}
	switch {
	case !aliasPattern.MatchString(req.Alias):
		return req, errBadAlias
	case req.MaxBudgetUSD == nil || !(*req.MaxBudgetUSD > 0) || *req.MaxBudgetUSD > MaxBudgetUSD:
		return req, fmt.Errorf("max_budget_usd must be a number > 0 and <= %d", MaxBudgetUSD)
	case req.RPMLimit != nil && (*req.RPMLimit <= 0 || *req.RPMLimit > MaxRPMLimit):
		return req, fmt.Errorf("rpm_limit must be an integer > 0 and <= %d", MaxRPMLimit)
	}
	return req, nil
}

func (s *Service) lookup(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("alias")
	if !aliasPattern.MatchString(alias) {
		httpjson.Error(w, http.StatusBadRequest, errBadAlias.Error())
		return
	}
	info, err := s.Gateway.LookupAlias(r.Context(), alias)
	if errors.Is(err, usage.ErrKeyUnknown) {
		httpjson.Error(w, http.StatusNotFound, "unknown alias")
		return
	}
	if err != nil {
		s.writeGatewayError(w, err)
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"alias":          info.Alias,
		"spend_usd":      info.SpendUSD,
		"max_budget_usd": info.MaxBudgetUSD,
	})
}

// writeGatewayError logs the detail and answers a generic 502: the admin API's errors are the operator's, not a client's.
func (s *Service) writeGatewayError(w http.ResponseWriter, err error) {
	s.log().Error("keys: gateway call failed", "err", err)
	httpjson.Error(w, http.StatusBadGateway, "gateway unavailable")
}
