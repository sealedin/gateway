// Package bonus gives a one-time credit to X accounts that follow ours. It runs outside the enclave, as the operator: it signs
// a visitor in with X, checks the follow, has the gateway issue a key through the operator's own route, so nothing measured
// changes, and sends the visitor back to the site with the outcome. Whoever runs it can read the keys it hands out, as with
// any hand-issued key.
package bonus

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/sealedin/gateway/internal/operator"
)

const (
	startRoute    = "/x/start"
	callbackRoute = "/x/callback"
	resultPath    = "/bonus" // the site page that reads the outcome from the fragment

	cookieName = "bonus_oauth"
	cookieTTL  = 10 * time.Minute

	aliasPrefix    = "bonus-x-"
	aliasDomain    = "sealedin-bonus-x-v1"
	aliasHashChars = 32 // 128 bits of the digest

	// Each claim that reaches X costs two paid reads, so anyone holding fresh codes could spend our credits.
	claimsPerSecond = 1
	claimsBurst     = 20
)

// Config is the promotion.
type Config struct {
	PublicURL     string        // this service's own origin, for the redirect back from X
	SiteURL       string        // the site whose bonus page shows the outcome
	Account       string        // the X account to follow, without the @
	BudgetUSD     float64       // what one bonus key may spend
	RPMLimit      int           // its rate limit
	MaxKeys       int           // the promotion ends after this many
	MinAccountAge time.Duration // younger X accounts get nothing: fresh accounts are what a farm makes
}

// Service holds the routes' state.
type Service struct {
	cfg     Config
	x       *X
	keys    *operator.Client
	ledger  *Ledger
	logger  *slog.Logger
	limiter *rate.Limiter

	issueMu sync.Mutex // the lookup and the issue of one alias are one step
}

// New wires the routes.
func New(cfg Config, x *X, keys *operator.Client, ledger *Ledger, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, x: x, keys: keys, ledger: ledger, logger: logger,
		limiter: rate.NewLimiter(claimsPerSecond, claimsBurst)}
}

// Register mounts the routes on mux.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+startRoute, s.start)
	mux.HandleFunc("GET "+callbackRoute, s.callback)
}

func (s *Service) redirectURI() string { return s.cfg.PublicURL + callbackRoute }

// AliasFor is the key alias of an X account: a digest, so the gateway's records name no account, though anyone holding the
// records can test a known account against them.
func AliasFor(accountID string) string {
	digest := sha256.Sum256([]byte(aliasDomain + "\x00" + accountID))
	return aliasPrefix + hex.EncodeToString(digest[:])[:aliasHashChars]
}

// start sends the browser to X. The state and the PKCE verifier wait in a cookie, so the service keeps nothing per visitor.
func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	if s.over() {
		s.finish(w, r, ResultOver, "")
		return
	}
	state, verifier := rand.Text(), rand.Text()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: state + "." + verifier, Path: "/x", MaxAge: int(cookieTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, s.x.AuthorizeLink(s.redirectURI(), state, verifier), http.StatusFound)
}

func (s *Service) over() bool { return s.ledger.Count() >= s.cfg.MaxKeys }

// callback is where X returns the visitor. Everything that can refuse for free runs before the first paid call.
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/x", MaxAge: -1, HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode})
	query := r.URL.Query()
	verifier, ok := verifierFor(r, query.Get("state"))
	code := query.Get("code")
	switch {
	case query.Get("error") != "":
		s.finish(w, r, resultCancelled, "")
		return
	case !ok || code == "":
		s.finish(w, r, ResultExpired, "")
		return
	case s.over():
		s.finish(w, r, ResultOver, "")
		return
	case !s.limiter.Allow():
		s.finish(w, r, resultBusy, "")
		return
	}
	token, err := s.x.Exchange(r.Context(), s.redirectURI(), code, verifier)
	if err != nil {
		s.unavailable(w, r, err)
		return
	}
	account, err := s.x.Me(r.Context(), token)
	if err != nil {
		s.unavailable(w, r, err)
		return
	}
	if time.Since(account.CreatedAt) < s.cfg.MinAccountAge {
		s.finish(w, r, ResultTooNew, "")
		return
	}
	follows, err := s.x.Follows(r.Context(), token, s.cfg.Account)
	if err != nil {
		s.unavailable(w, r, err)
		return
	}
	if !follows {
		s.finish(w, r, ResultNotFollowing, "")
		return
	}
	s.issue(w, r, AliasFor(account.ID))
}

// verifierFor returns the PKCE verifier of the sign-in this browser started, if state is that sign-in's.
func verifierFor(r *http.Request, state string) (string, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	want, verifier, ok := strings.Cut(cookie.Value, ".")
	if !ok || want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(state)) != 1 {
		return "", false
	}
	return verifier, true
}

// issue gives the account its key once. The gateway refuses an alias it has, and only its first reply carries the key, so a
// second visit can only be told that the bonus was taken.
func (s *Service) issue(w http.ResponseWriter, r *http.Request, alias string) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	taken, err := s.keys.Exists(r.Context(), alias)
	switch {
	case err != nil:
		s.unavailable(w, r, err)
		return
	case taken:
		s.finish(w, r, ResultTaken, "")
		return
	case s.over(): // the last one may have gone while this visitor was at X
		s.finish(w, r, ResultOver, "")
		return
	}
	key, err := s.keys.Issue(r.Context(), alias, s.cfg.BudgetUSD, s.cfg.RPMLimit)
	if err != nil {
		s.unavailable(w, r, err)
		return
	}
	if err = s.ledger.Add(alias); err != nil {
		s.logger.Error("bonus: issued but not recorded, add the alias to the ledger by hand", "alias", alias, "err", err)
	}
	s.logger.Info("bonus: issued", "alias", alias, "issued_total", s.ledger.Count(), "max", s.cfg.MaxKeys)
	s.finish(w, r, ResultIssued, key)
}

func (s *Service) unavailable(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("bonus: claim failed", "err", err)
	s.finish(w, r, resultUnavailable, "")
}

// The outcomes the site page is told, which is also how a test tells them apart.
const (
	ResultIssued       = "issued"
	ResultNotFollowing = "not_following"
	ResultTooNew       = "too_new"
	ResultTaken        = "taken"
	ResultOver         = "over"
	ResultExpired      = "expired"
	resultCancelled    = "cancelled"
	resultBusy         = "busy"
	resultUnavailable  = "unavailable"
)

// finish sends the browser to the site's bonus page with the outcome, and the key if one was issued, in the fragment: a
// fragment reaches no server and no log, and the page removes it from the address before anything else reads it. The key
// travels at most once, so nothing may keep the redirect.
func (s *Service) finish(w http.ResponseWriter, r *http.Request, result, key string) {
	fragment := url.Values{"result": {result}}
	if key != "" {
		fragment.Set("key", key)
	}
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, s.cfg.SiteURL+resultPath+"#"+fragment.Encode(), http.StatusSeeOther)
}
