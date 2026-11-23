package bonus_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sealedin/gateway/internal/bonus"
)

const (
	testOperator = "operator-token"
	testKey      = "sk-bonus-key"
	testAccount  = "ours"
)

// world is the service between a fake X and a fake gateway.
type world struct {
	t       *testing.T
	service *bonus.Service
	mux     *http.ServeMux
	ledger  string

	follows   bool
	createdAt time.Time
	xCalls    int
	verifier  string // what the token call received
	issued    map[string]map[string]any
}

func newWorld(t *testing.T, maxKeys int) *world {
	t.Helper()
	w := &world{t: t, follows: true, createdAt: time.Now().Add(-365 * 24 * time.Hour), issued: map[string]map[string]any{},
		ledger: filepath.Join(t.TempDir(), "ledger")}

	x := http.NewServeMux()
	x.HandleFunc("POST /2/oauth2/token", func(rw http.ResponseWriter, r *http.Request) {
		w.xCalls++
		w.verifier = r.FormValue("code_verifier")
		if r.FormValue("code") != "good-code" || r.FormValue("client_id") != "client" {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = rw.Write([]byte(`{"access_token":"user-token"}`))
	})
	x.HandleFunc("GET /2/users/me", func(rw http.ResponseWriter, _ *http.Request) {
		w.xCalls++
		created := w.createdAt.UTC().Format(time.RFC3339)
		_ = json.NewEncoder(rw).Encode(map[string]any{"data": map[string]any{"id": "42", "created_at": created}})
	})
	x.HandleFunc("GET /2/users/by/username/"+testAccount, func(rw http.ResponseWriter, r *http.Request) {
		w.xCalls++
		if r.Header.Get("Authorization") != "Bearer user-token" || r.URL.Query().Get("user.fields") != "connection_status" {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		status := []string{}
		if w.follows {
			status = []string{"following"}
		}
		_ = json.NewEncoder(rw).Encode(map[string]any{"data": map[string]any{"connection_status": status}})
	})
	xServer := httptest.NewServer(x)
	t.Cleanup(xServer.Close)

	gw := http.NewServeMux()
	gw.HandleFunc("POST /v1/keys", func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testOperator {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		alias, _ := body["alias"].(string)
		w.issued[alias] = body
		_ = json.NewEncoder(rw).Encode(map[string]any{"key": testKey})
	})
	gw.HandleFunc("GET /v1/keys/{alias}", func(rw http.ResponseWriter, r *http.Request) {
		if _, ok := w.issued[r.PathValue("alias")]; !ok {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = rw.Write([]byte(`{}`))
	})
	gwServer := httptest.NewServer(gw)
	t.Cleanup(gwServer.Close)

	ledger, err := bonus.OpenLedger(w.ledger)
	if err != nil {
		t.Fatal(err)
	}
	cfg := bonus.Config{PublicURL: "https://bonus.example", SiteURL: "https://site.example", Account: testAccount, BudgetUSD: 10,
		RPMLimit: 20, MaxKeys: maxKeys, MinAccountAge: 30 * 24 * time.Hour}
	xClient := &bonus.X{ClientID: "client", AuthorizeURL: "https://x.example/authorize", APIBase: xServer.URL, HTTP: xServer.Client()}
	operator := &bonus.Operator{BaseURL: gwServer.URL, Token: testOperator, HTTP: gwServer.Client()}
	w.service = bonus.New(cfg, xClient, operator, ledger, slog.New(slog.DiscardHandler))
	w.mux = http.NewServeMux()
	w.service.Register(w.mux)
	return w
}

// signIn starts a sign-in and returns the cookie and the state X would send back.
func (w *world) signIn() (*http.Cookie, url.Values) {
	w.t.Helper()
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x/start", http.NoBody))
	if rec.Code != http.StatusFound {
		w.t.Fatalf("start: status %d", rec.Code)
	}
	link, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		w.t.Fatal(err)
	}
	return rec.Result().Cookies()[0], link.Query()
}

func (w *world) callback(cookie *http.Cookie, query string) *httptest.ResponseRecorder {
	w.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x/callback?"+query, http.NoBody)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, req)
	return rec
}

// claim runs a whole sign-in the way a browser would.
func (w *world) claim() *httptest.ResponseRecorder {
	w.t.Helper()
	cookie, sent := w.signIn()
	return w.callback(cookie, "code=good-code&state="+sent.Get("state"))
}

// landing is where a reply sends the browser and the outcome it carries in the fragment.
func landing(t *testing.T, rec *httptest.ResponseRecorder) (string, url.Values) {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	target, fragment, _ := strings.Cut(rec.Header().Get("Location"), "#")
	outcome, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatal(err)
	}
	return target, outcome
}

func TestFollowerGetsOneKey(t *testing.T) {
	w := newWorld(t, 5)
	cookie, sent := w.signIn()
	if sent.Get("redirect_uri") != "https://bonus.example/x/callback" || sent.Get("code_challenge_method") != "S256" ||
		!strings.Contains(sent.Get("scope"), "follows.read") {
		t.Fatalf("authorize link: %v", sent)
	}

	rec := w.callback(cookie, "code=good-code&state="+sent.Get("state"))
	target, outcome := landing(t, rec)
	if target != "https://site.example/bonus" || outcome.Get("result") != bonus.ResultIssued || outcome.Get("key") != testKey {
		t.Fatalf("sent to %s with %v", target, outcome)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the redirect with the key may be cached")
	}
	challenge := sha256.Sum256([]byte(w.verifier))
	if base64.RawURLEncoding.EncodeToString(challenge[:]) != sent.Get("code_challenge") {
		t.Error("the verifier sent to X is not the one the challenge was made from")
	}
	body := w.issued[bonus.AliasFor("42")]
	if body == nil || body["max_budget_usd"] != 10.0 || body["rpm_limit"] != 20.0 {
		t.Fatalf("issued: %v", w.issued)
	}
	recorded, _ := os.ReadFile(w.ledger)
	if strings.TrimSpace(string(recorded)) != bonus.AliasFor("42") {
		t.Errorf("ledger: %q", recorded)
	}

	if _, again := landing(t, w.claim()); again.Get("result") != bonus.ResultTaken || again.Has("key") {
		t.Errorf("second claim: %v", again)
	}
	if len(w.issued) != 1 {
		t.Errorf("issued %d keys", len(w.issued))
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*world)
		want  string
	}{
		{"not following", func(w *world) { w.follows = false }, bonus.ResultNotFollowing},
		{"account too new", func(w *world) { w.createdAt = time.Now().Add(-time.Hour) }, bonus.ResultTooNew},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, 5)
			c.setup(w)
			_, outcome := landing(t, w.claim())
			if outcome.Get("result") != c.want || outcome.Has("key") || len(w.issued) != 0 {
				t.Fatalf("outcome %v, issued %v", outcome, w.issued)
			}
		})
	}
}

func TestForeignStateCostsNothing(t *testing.T) {
	w := newWorld(t, 5)
	cookie, _ := w.signIn()
	for _, rec := range []*httptest.ResponseRecorder{
		w.callback(cookie, "code=good-code&state=someone-elses"),
		w.callback(nil, "code=good-code&state=anything"),
	} {
		if _, outcome := landing(t, rec); outcome.Get("result") != bonus.ResultExpired {
			t.Errorf("outcome %v", outcome)
		}
	}
	if w.xCalls != 0 || len(w.issued) != 0 {
		t.Fatalf("x calls %d, issued %v", w.xCalls, w.issued)
	}
}

func TestPromotionEndsAtTheCapAcrossRestarts(t *testing.T) {
	w := newWorld(t, 1)
	if _, first := landing(t, w.claim()); first.Get("key") != testKey {
		t.Fatalf("first claim: %v", first)
	}
	ledger, err := bonus.OpenLedger(w.ledger) // what a restart reads
	if err != nil || ledger.Count() != 1 {
		t.Fatalf("reopened ledger: %v, %v", ledger, err)
	}
	calls := w.xCalls
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x/start", http.NoBody))
	if _, outcome := landing(t, rec); outcome.Get("result") != bonus.ResultOver || w.xCalls != calls {
		t.Fatalf("start after the cap: %v", outcome)
	}
}
