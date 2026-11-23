// Package bonus gives a one-time credit to X accounts that follow ours. It runs outside the enclave, as the operator: it signs
// a visitor in with X, checks the follow, and has the gateway issue a key through the operator's own route, so nothing measured
// changes. Whoever runs it can read the keys it hands out, as with any hand-issued key.
package bonus

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	startRoute    = "/x/start"
	callbackRoute = "/x/callback"

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
	SiteURL       string        // where the pages link to
	Account       string        // the X account to follow, without the @
	BudgetUSD     float64       // what one bonus key may spend
	RPMLimit      int           // its rate limit
	MaxKeys       int           // the promotion ends after this many
	MinAccountAge time.Duration // younger X accounts get nothing: fresh accounts are what a farm makes
}

// Service holds the routes' state.
type Service struct {
	cfg      Config
	x        *X
	keys     *Operator
	ledger   *Ledger
	logger   *slog.Logger
	limiter  *rate.Limiter
	template *template.Template

	issueMu sync.Mutex // the lookup and the issue of one alias are one step
}

// New wires the routes.
func New(cfg Config, x *X, keys *Operator, ledger *Ledger, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, x: x, keys: keys, ledger: ledger, logger: logger,
		limiter: rate.NewLimiter(claimsPerSecond, claimsBurst), template: template.Must(template.New("page").Parse(pageSource))}
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
		s.page(w, http.StatusOK, viewOf(TitleOver))
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
		s.page(w, http.StatusOK, viewOf(titleCancelled))
		return
	case !ok || code == "":
		s.page(w, http.StatusBadRequest, viewOf(titleExpired))
		return
	case s.over():
		s.page(w, http.StatusOK, viewOf(TitleOver))
		return
	case !s.limiter.Allow():
		s.page(w, http.StatusTooManyRequests, viewOf(titleBusy))
		return
	}
	token, err := s.x.Exchange(r.Context(), s.redirectURI(), code, verifier)
	if err != nil {
		s.unavailable(w, err)
		return
	}
	account, err := s.x.Me(r.Context(), token)
	if err != nil {
		s.unavailable(w, err)
		return
	}
	if time.Since(account.CreatedAt) < s.cfg.MinAccountAge {
		s.page(w, http.StatusOK, viewOf(TitleTooNew))
		return
	}
	follows, err := s.x.Follows(r.Context(), token, s.cfg.Account)
	if err != nil {
		s.unavailable(w, err)
		return
	}
	if !follows {
		s.page(w, http.StatusOK, viewOf(TitleNotFollowing))
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
		s.unavailable(w, err)
		return
	case taken:
		s.page(w, http.StatusOK, viewOf(TitleTaken))
		return
	case s.over(): // the last one may have gone while this visitor was at X
		s.page(w, http.StatusOK, viewOf(TitleOver))
		return
	}
	key, err := s.keys.Issue(r.Context(), alias, s.cfg.BudgetUSD, s.cfg.RPMLimit)
	if err != nil {
		s.unavailable(w, err)
		return
	}
	if err = s.ledger.Add(alias); err != nil {
		s.logger.Error("bonus: issued but not recorded, add the alias to the ledger by hand", "alias", alias, "err", err)
	}
	s.logger.Info("bonus: issued", "alias", alias, "issued_total", s.ledger.Count(), "max", s.cfg.MaxKeys)
	issued := viewOf(TitleIssued)
	issued.Key = key
	s.page(w, http.StatusOK, issued)
}

func (s *Service) unavailable(w http.ResponseWriter, err error) {
	s.logger.Error("bonus: claim failed", "err", err)
	s.page(w, http.StatusBadGateway, viewOf(titleUnavailable))
}

// view is one page. Retry offers the sign-in again, Follow links to the account.
type view struct {
	Title  string
	Text   string
	Key    string
	Retry  bool
	Follow bool
}

// The pages' titles, which is also how a test tells them apart.
const (
	TitleIssued       = "Your key"
	TitleNotFollowing = "Follow us first"
	TitleTooNew       = "Account too new"
	TitleTaken        = "Already taken"
	TitleOver         = "The promotion is over"
	titleCancelled    = "Sign-in cancelled"
	titleExpired      = "Sign-in expired"
	titleBusy         = "Busy"
	titleUnavailable  = "Try again"
)

func viewOf(title string) view {
	v := view{Title: title, Retry: true}
	switch title {
	case TitleIssued:
		v.Text = "Save it now: it is shown once and cannot be recovered. It works as any key does, and paying later tops it up."
		v.Retry = false
	case TitleNotFollowing:
		v.Text = "The bonus goes to accounts that follow us on X. Follow, then try again."
		v.Follow = true
	case TitleTooNew:
		v.Text = "The bonus goes to X accounts older than this one."
		v.Retry = false
	case TitleTaken:
		v.Text = "This X account got its bonus before. The key was shown then and cannot be shown again."
		v.Retry = false
	case TitleOver:
		v.Text = "Every bonus has been given. You can still buy a key."
		v.Retry = false
	case titleCancelled:
		v.Text = "Nothing was issued."
	case titleExpired:
		v.Text = "Start again from this browser."
	case titleBusy:
		v.Text = "Too many sign-ins right now. Try again in a minute."
	default:
		v.Text = "We could not finish the check. Nothing was issued."
	}
	return v
}

const pageStyle = "body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem}" +
	"code{display:block;padding:1rem;background:#f2f2f2;word-break:break-all}"

const pageSource = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.View.Title}} | SealedIn</title>
<style>` + pageStyle + `</style>
</head><body><h1>{{.View.Title}}</h1><p>{{.View.Text}}</p>
{{if .View.Key}}<code>{{.View.Key}}</code>{{end}}
{{if .View.Follow}}<p><a href="https://x.com/{{.Account}}" target="_blank" rel="noopener">@{{.Account}} on X</a></p>{{end}}
<p>{{if .View.Retry}}<a href="` + startRoute + `">Sign in with X</a> · {{end}}<a href="{{.Site}}">{{.Site}}</a></p>
</body></html>
`

// page renders one view. A key is on it at most once, so nothing may keep or forward the page.
func (s *Service) page(w http.ResponseWriter, status int, v view) {
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	data := struct {
		View    view
		Account string
		Site    string
	}{v, s.cfg.Account, s.cfg.SiteURL}
	if err := s.template.Execute(w, data); err != nil {
		s.logger.Error("bonus: page", "err", err)
	}
}
