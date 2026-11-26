package coinpay_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sealedin/gateway/internal/coinpay"
	"github.com/sealedin/gateway/internal/operator"
)

const (
	testOperator = "operator-token"
	testSite     = "https://site.example"
	testPublic   = "https://pay.example"
	xmrRate      = 0.002 // XMR per USD: 500 USD a coin
)

// world is the service between a fake forwarder and a fake gateway.
type world struct {
	t       *testing.T
	mux     *http.ServeMux
	service *coinpay.Service
	signer  *rsa.PrivateKey
	orders  string
	now     time.Time

	rate      float64                   // what the forwarder quotes now
	callbacks map[string]string         // address by callback URL, as the forwarder holds them
	payouts   map[string]string         // payout address by ticker, as the forwarder was told
	issued    map[string]map[string]any // gateway keys by alias
	open      func(now time.Time) *coinpay.Store
	tamper    func(*http.Request) // what happens to a callback after it was signed
}

func newWorld(t *testing.T) *world {
	t.Helper()
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, signer: signer, rate: xmrRate, now: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
		callbacks: map[string]string{}, payouts: map[string]string{}, issued: map[string]map[string]any{},
		orders: filepath.Join(t.TempDir(), "orders")}

	forwarder := http.NewServeMux()
	forwarder.HandleFunc("GET /crypto/info.php", func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte(`{
			"xmr": {"coin": "Monero", "ticker": "xmr", "minimum_transaction_coin": "0.01000000"},
			"ada": {"coin": "Cardano", "ticker": "ada", "minimum_transaction_coin": "5"},
			"trc20": {"usdt": {"coin": "USDT", "ticker": "usdt", "minimum_transaction_coin": "10.00000000"}},
			"base": {"usdc": {"coin": "USD Coin", "ticker": "usdc", "minimum_transaction_coin": "3"}}
		}`))
	})
	forwarder.HandleFunc("GET /crypto/xmr/convert.php", func(rw http.ResponseWriter, r *http.Request) {
		usd, parseErr := strconv.ParseFloat(r.URL.Query().Get("value"), 64)
		if parseErr != nil || r.URL.Query().Get("from") != "usd" {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(rw).Encode(map[string]string{"status": "success", "value_coin": formatCoin(usd * w.rate),
			"exchange_rate": formatCoin(w.rate)})
	})
	forwarder.HandleFunc("GET /crypto/xmr/wallet.php", func(rw http.ResponseWriter, r *http.Request) {
		callback := r.URL.Query().Get("callback")
		w.payouts["xmr"] = r.URL.Query().Get("address")
		digest := sha256.Sum256([]byte(callback))
		w.callbacks[callback] = "4in" + base64.RawURLEncoding.EncodeToString(digest[:])[:12]
		_ = json.NewEncoder(rw).Encode(map[string]string{"address_in": w.callbacks[callback], "callback_url": callback})
	})
	forwarderServer := httptest.NewServer(forwarder)
	t.Cleanup(forwarderServer.Close)

	gw := http.NewServeMux()
	gw.HandleFunc("GET /v1/keys/{alias}", func(rw http.ResponseWriter, r *http.Request) {
		if _, ok := w.issued[r.PathValue("alias")]; !ok {
			rw.WriteHeader(http.StatusNotFound)
		}
	})
	gw.HandleFunc("POST /v1/keys", func(rw http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Header.Get("Authorization") != "Bearer "+testOperator || json.NewDecoder(r.Body).Decode(&body) != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		alias, _ := body["alias"].(string)
		w.issued[alias] = body
		_ = json.NewEncoder(rw).Encode(map[string]string{"key": "sk-" + alias})
	})
	gwServer := httptest.NewServer(gw)
	t.Cleanup(gwServer.Close)

	pay, err := coinpay.NewPayGate(forwarderServer.URL, forwarderServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	pay.Keys = map[string]*rsa.PublicKey{"v1": &signer.PublicKey}
	cfg := coinpay.Config{PublicURL: testPublic, SiteURL: testSite, MinUSD: 20, MaxUSD: 500, RPMLimit: 60, QuoteTTL: time.Hour,
		Payouts: map[string]string{"xmr": "4ours", "tron": "Tours"}}
	keys := &operator.Client{BaseURL: gwServer.URL, Token: testOperator, HTTP: gwServer.Client()}
	w.open = func(now time.Time) *coinpay.Store {
		store, openErr := coinpay.OpenStore(w.orders, 24*time.Hour, 48*time.Hour, now)
		if openErr != nil {
			t.Fatal(openErr)
		}
		w.service = coinpay.New(cfg, pay, keys, store, slog.New(slog.DiscardHandler))
		w.service.Now = func() time.Time { return w.now }
		w.mux = http.NewServeMux()
		w.service.Register(w.mux)
		return store
	}
	w.open(w.now)
	return w
}

func formatCoin(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func str(v any) string {
	s, _ := v.(string)
	return s
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (w *world) do(req *http.Request) (int, map[string]any, string) {
	w.t.Helper()
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, req)
	var reply map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &reply)
	return rec.Code, reply, rec.Body.String()
}

// order opens an order and returns what the buyer learns.
func (w *world) order(ticker string, usd float64) (int, map[string]any) {
	w.t.Helper()
	body := mustJSON(w.t, map[string]any{"ticker": ticker, "usd": usd})
	code, reply, _ := w.do(httptest.NewRequest(http.MethodPost, "/pay/orders", bytes.NewReader(body)))
	return code, reply
}

func (w *world) status(order, claim any) (int, map[string]any) {
	w.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/pay/orders/"+str(order), http.NoBody)
	req.Header.Set("Authorization", "Bearer "+str(claim))
	code, reply, _ := w.do(req)
	return code, reply
}

// pay is the forwarder calling back about a payment of coin to the order, signed the way it signs.
func (w *world) pay(order map[string]any, coin, txid string, change func(url.Values, *http.Request)) (int, string) {
	w.t.Helper()
	id, _ := order["order"].(string)
	address, _ := order["address"].(string)
	query := url.Values{"order": {id}, "coin": {"xmr"}, "value_coin": {coin}, "txid_in": {txid}, "address_in": {address},
		"pending": {"0"}}
	req := httptest.NewRequest(http.MethodGet, "/pay/callback?"+query.Encode(), http.NoBody)
	if change != nil {
		change(query, req)
		req.URL.RawQuery = query.Encode()
	}
	if req.Header.Get("X-Paygate-Signature") == "" {
		digest := sha256.Sum256([]byte(testPublic + "/pay/callback?" + req.URL.RawQuery))
		signature, err := rsa.SignPKCS1v15(rand.Reader, w.signer, crypto.SHA256, digest[:])
		if err != nil {
			w.t.Fatal(err)
		}
		req.Header.Set("X-Paygate-Signature", base64.StdEncoding.EncodeToString(signature))
		if req.Header.Get("X-Paygate-Key-Id") == "" {
			req.Header.Set("X-Paygate-Key-Id", "v1")
		}
	}
	if w.tamper != nil {
		w.tamper(req)
	}
	code, _, body := w.do(req)
	return code, body
}

func TestAnOrderShowsTheBuyerTheForwardersAddressForOurPayout(t *testing.T) {
	w := newWorld(t)
	code, order := w.order("xmr", 20)
	if code != http.StatusCreated || order["amount"] != "0.04" || order["status"] != "pending" || str(order["claim"]) == "" {
		t.Fatalf("order: %d %v", code, order)
	}
	if w.payouts["xmr"] != "4ours" {
		t.Fatalf("the forwarder pays out to %q", w.payouts["xmr"])
	}
	if w.callbacks[testPublic+"/pay/callback?order="+str(order["order"])] != order["address"] {
		t.Fatalf("the forwarder holds %v, the buyer was shown %v", w.callbacks, order["address"])
	}
	if _, pending := w.status(order["order"], order["claim"]); pending["status"] != "pending" || pending["key"] != nil {
		t.Fatalf("before payment: %v", pending)
	}
}

func TestAPaidOrderBecomesAKeyOnce(t *testing.T) {
	w := newWorld(t)
	_, order := w.order("xmr", 20)
	for range 2 { // the forwarder may report a payment more than once
		if code, body := w.pay(order, "0.04", "tx1", nil); code != http.StatusOK || body != "ok" {
			t.Fatalf("callback: %d %q", code, body)
		}
	}
	alias := "coin-" + str(order["order"])
	if len(w.issued) != 1 || w.issued[alias]["max_budget_usd"] != 20.0 || w.issued[alias]["rpm_limit"] != 60.0 {
		t.Fatalf("issued: %v", w.issued)
	}
	code, paid := w.status(order["order"], order["claim"])
	if code != http.StatusOK || paid["status"] != "paid" || paid["key"] != "sk-"+alias || paid["credited_usd"] != 20.0 {
		t.Fatalf("after payment: %d %v", code, paid)
	}
	if again, body := w.pay(order, "0.04", "tx2", nil); again != http.StatusOK || body != "ok" || len(w.issued) != 1 {
		t.Fatalf("a second payment: %d %q, issued %v", again, body, w.issued)
	}
}

func TestTheKeyIsReadOnlyWithTheClaimSecret(t *testing.T) {
	w := newWorld(t)
	_, order := w.order("xmr", 20)
	w.pay(order, "0.04", "tx1", nil)
	for name, claim := range map[string]string{"wrong": "nope", "empty": ""} {
		if code, reply := w.status(order["order"], claim); code != http.StatusNotFound || reply != nil {
			t.Errorf("%s claim: %d %v", name, code, reply)
		}
	}
	if code, _ := w.status("nosuchorder", order["claim"]); code != http.StatusNotFound {
		t.Errorf("unknown order: %d", code)
	}
}

func TestACallbackIsCreditedOnlyWhenItIsTheForwardersAndMatchesTheOrder(t *testing.T) {
	w := newWorld(t)
	_, order := w.order("xmr", 20)
	for name, c := range map[string]struct {
		change func(url.Values, *http.Request)
		want   int
	}{
		"forged signature": {func(_ url.Values, r *http.Request) { r.Header.Set("X-Paygate-Signature", "AAAA") }, http.StatusForbidden},
		"unknown key id":   {func(_ url.Values, r *http.Request) { r.Header.Set("X-Paygate-Key-Id", "v9") }, http.StatusForbidden},
		"another coin":     {func(q url.Values, _ *http.Request) { q.Set("coin", "btc") }, http.StatusBadRequest},
		"another address":  {func(q url.Values, _ *http.Request) { q.Set("address_in", "4other") }, http.StatusBadRequest},
		"no amount":        {func(q url.Values, _ *http.Request) { q.Set("value_coin", "lots") }, http.StatusBadRequest},
		"unconfirmed":      {func(q url.Values, _ *http.Request) { q.Set("pending", "1") }, http.StatusOK},
		"unknown order":    {func(q url.Values, _ *http.Request) { q.Set("order", "nosuchorder") }, http.StatusOK},
	} {
		if code, _ := w.pay(order, "0.04", "tx1", c.change); code != c.want {
			t.Errorf("%s: status %d, want %d", name, code, c.want)
		}
		if len(w.issued) != 0 {
			t.Fatalf("%s: issued %v", name, w.issued)
		}
	}
	// A signature over the query as sent does not cover a query altered on the way.
	w.tamper = func(r *http.Request) {
		r.URL.RawQuery = strings.Replace(r.URL.RawQuery, "value_coin=0.04", "value_coin=40", 1)
	}
	if code, _ := w.pay(order, "0.04", "tx1", nil); code != http.StatusForbidden || len(w.issued) != 0 {
		t.Fatalf("an altered callback: %d, issued %v", code, w.issued)
	}
}

func TestAPaymentIsCreditedForWhatItIsWorth(t *testing.T) {
	for name, c := range map[string]struct {
		coin     string
		late     bool
		wantUSD  float64
		wantKeys int
	}{
		"half paid":             {"0.02", false, 10, 1},
		"overpaid to the cap":   {"2", false, 500, 1},
		"dust":                  {"0.00001", false, 0, 0},
		"late, at today's rate": {"0.04", true, 10, 1}, // the coin halved after the quote lapsed
	} {
		w := newWorld(t)
		_, order := w.order("xmr", 20)
		if c.late {
			w.now = w.now.Add(2 * time.Hour)
			w.rate = 2 * xmrRate
		}
		if code, body := w.pay(order, c.coin, "tx1", nil); code != http.StatusOK || body != "ok" {
			t.Fatalf("%s: callback %d %q", name, code, body)
		}
		_, paid := w.status(order["order"], order["claim"])
		if len(w.issued) != c.wantKeys || paid["status"] != "paid" || (c.wantKeys == 1 && paid["credited_usd"] != c.wantUSD) {
			t.Errorf("%s: issued %v, order %v", name, w.issued, paid)
		}
	}
}

func TestAnOrderNeedsAnOfferedCoinAndAnAmountInRange(t *testing.T) {
	w := newWorld(t)
	for name, c := range map[string]struct {
		ticker string
		usd    float64
	}{
		"no payout address": {"base/usdc", 20},
		"unmapped network":  {"ada", 20},
		"a path":            {"xmr/../btc", 20},
		"too little":        {"xmr", 19.99},
		"too much":          {"xmr", 500.01},
	} {
		if code, reply := w.order(c.ticker, c.usd); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, code, reply)
		}
	}
	if len(w.callbacks) != 0 {
		t.Fatalf("refused orders reached the forwarder: %v", w.callbacks)
	}
	code, reply, _ := w.do(httptest.NewRequest(http.MethodGet, "/pay/coins", http.NoBody))
	coins := mustJSON(t, reply["coins"])
	want := `[{"minimum":10,"name":"USDT","ticker":"trc20/usdt"},{"minimum":0.01,"name":"Monero","ticker":"xmr"}]`
	if code != http.StatusOK || !jsonEqual(t, string(coins), want) || reply["min_usd"] != 20.0 {
		t.Fatalf("coins: %d %s", code, coins)
	}
}

// The forwarder keeps a payment under its minimum for the coin, so such an order must not be opened.
func TestAnOrderPricedUnderTheForwardersMinimumIsRefused(t *testing.T) {
	w := newWorld(t)
	w.rate = xmrRate / 10 // 20 USD is now 0.004 XMR, and the forwarder takes no less than 0.01
	code, reply := w.order("xmr", 20)
	if code != http.StatusBadRequest || !strings.Contains(string(mustJSON(t, reply["error"])), "50 USD") || len(w.callbacks) != 0 {
		t.Fatalf("order: %d %v, callbacks %v", code, reply, w.callbacks)
	}
	if code, reply = w.order("xmr", 50); code != http.StatusCreated {
		t.Fatalf("order at the minimum: %d %v", code, reply)
	}
}

func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return bytes.Equal(mustJSON(t, x), mustJSON(t, y))
}

func TestOrdersSurviveARestartAndKeysAreDroppedInTime(t *testing.T) {
	w := newWorld(t)
	_, paid := w.order("xmr", 20)
	_, unpaid := w.order("xmr", 30)
	w.pay(paid, "0.04", "tx1", nil)

	w.open(w.now.Add(time.Hour))
	if _, reply := w.status(paid["order"], paid["claim"]); reply["key"] == "" || reply["status"] != "paid" {
		t.Fatalf("after a restart: %v", reply)
	}
	if code, body := w.pay(unpaid, "0.06", "tx2", nil); code != http.StatusOK || body != "ok" || len(w.issued) != 2 {
		t.Fatalf("an order paid after a restart: %d %q %v", code, body, w.issued)
	}

	w.open(w.now.Add(72 * time.Hour))
	_, reply := w.status(paid["order"], paid["claim"])
	if reply["status"] != "paid" || reply["key"] != "" {
		t.Fatalf("a key kept past its time: %v", reply)
	}
	if strings.Contains(readFile(t, w.orders), "sk-") {
		t.Fatal("the orders file still holds a key")
	}
}

func TestTheBrowserRoutesAnswerTheSiteOnlyAndTheCallbackNoBrowser(t *testing.T) {
	w := newWorld(t)
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/pay/orders", http.NoBody))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != testSite ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("preflight: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	w.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pay/callback", http.NoBody))
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("callback: %d %v", rec.Code, rec.Header())
	}
}

func TestThePublishedCallbackKeyAndThePayoutKinds(t *testing.T) {
	pay, err := coinpay.NewPayGate(coinpay.DefaultPayGateAPI, http.DefaultClient)
	if err != nil || pay.Keys["v1"] == nil || pay.Keys["v1"].N.BitLen() != 2048 {
		t.Fatalf("embedded key: %v %v", err, pay.Keys)
	}
	for ticker, want := range map[string]string{
		"btc": "btc", "xmr": "xmr", "eth": "evm", "trx": "tron", "erc20/usdt": "evm", "base/usdc": "evm", "avax-c/usdc": "evm",
		"trc20/usdt": "tron", "sol/usdc": "sol", "sol/sol": "sol", "ton/usdt": "ton",
		"arc/usdc": "", "btc/usdt": "", "erc20": "", "sol": "", "ada": "",
	} {
		if got := coinpay.Family(ticker); got != want {
			t.Errorf("Family(%q) = %q, want %q", ticker, got, want)
		}
	}
	if coinpay.ValidatePayouts(map[string]string{"evm": "0xours", "sol": "ours"}) != nil {
		t.Error("good payouts refused")
	}
	for name, payouts := range map[string]map[string]string{"none": {}, "typo": {"bitcoin": "bc1q"}, "blank": {"btc": " "}} {
		if coinpay.ValidatePayouts(payouts) == nil {
			t.Errorf("%s payouts accepted", name)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
