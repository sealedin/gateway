// Package coinpay sells keys for coins other than USDC on Solana. It runs outside the enclave, as the operator: a forwarder
// with no merchant account gives each order a fresh address and sends what arrives there on to our own address in the same
// coin, its signed callback is the only proof of payment, and the key is issued through the operator's own route, so nothing
// measured changes. Whoever runs it can read the keys it hands out, as with any hand-issued key.
package coinpay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/sealedin/gateway/internal/httpjson"
)

const (
	coinsRoute    = "/pay/coins"
	ordersRoute   = "/pay/orders"
	callbackRoute = "/pay/callback"

	aliasPrefix  = "coin-"
	maxBodyBytes = 1 << 10
	coinsTTL     = 10 * time.Minute
	centsPerUSD  = 100
	centEpsilon  = 1e-6 // a payment of exactly the quoted amount must not lose a cent to floating point
	callbackOK   = "ok" // the body that tells the forwarder to stop repeating a callback

	// Each order makes the forwarder derive an address, so anyone could have it derive them without end.
	ordersPerSecond = 1
	ordersBurst     = 20
	retryAfter      = "5"
)

// Forwarder is the payment side: PayGate today, and any forwarder of the same model behind it.
type Forwarder interface {
	Coins(ctx context.Context) ([]Coin, error)
	Quote(ctx context.Context, ticker string, usd float64) (amount string, rate float64, err error)
	Address(ctx context.Context, ticker, payout, callback string) (string, error)
	Verify(callbackURL string, r *http.Request) error
}

// KeyIssuer is the gateway's operator key issuance.
type KeyIssuer interface {
	Exists(ctx context.Context, alias string) (bool, error)
	Issue(ctx context.Context, alias string, budgetUSD float64, rpm int) (string, error)
}

// Config is what the service sells and where the coins go.
type Config struct {
	PublicURL string            // this service's own origin, which the forwarder calls back
	SiteURL   string            // the origin whose pages may call the service from a browser
	Payouts   map[string]string // our address by Family; a coin with no address here is not offered
	MinUSD    float64           // the smallest purchase
	MaxUSD    float64           // the largest credit one payment can buy
	RPMLimit  int               // the rate limit of a bought key
	QuoteTTL  time.Duration     // how long an order's price holds; a later payment is priced when it arrives
}

// Service holds the routes' state.
type Service struct {
	cfg     Config
	pay     Forwarder
	keys    KeyIssuer
	store   *Store
	logger  *slog.Logger
	limiter *rate.Limiter
	Now     func() time.Time

	issueMu sync.Mutex // one payment is credited at a time, so an order is paid once

	coinsMu sync.Mutex
	coins   []Coin
	coinsAt time.Time
}

// New wires the routes.
func New(cfg Config, pay Forwarder, keys KeyIssuer, store *Store, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, pay: pay, keys: keys, store: store, logger: logger, Now: time.Now,
		limiter: rate.NewLimiter(ordersPerSecond, ordersBurst)}
}

// Register mounts the routes on mux. The browser routes answer the site's origin only; the callback is the forwarder's.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+coinsRoute, s.browser(s.listCoins))
	mux.HandleFunc("POST "+ordersRoute, s.browser(s.create))
	mux.HandleFunc("GET "+ordersRoute+"/{id}", s.browser(s.status))
	mux.HandleFunc("OPTIONS /pay/", s.browser(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	mux.HandleFunc("GET "+callbackRoute, s.callback)
}

func (s *Service) callbackURL() string { return s.cfg.PublicURL + callbackRoute }

// browser lets the site's pages read the reply and keeps it out of every cache: a reply can carry a key.
func (s *Service) browser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Access-Control-Allow-Origin", s.cfg.SiteURL)
		header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		header.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		header.Set("Vary", "Origin")
		header.Set("Cache-Control", "no-store")
		next(w, r)
	}
}

// offered is the forwarder's list cut to the coins we hold a payout address for, read at most once per coinsTTL.
func (s *Service) offered(ctx context.Context) ([]Coin, error) {
	s.coinsMu.Lock()
	defer s.coinsMu.Unlock()
	if s.coins != nil && s.Now().Sub(s.coinsAt) < coinsTTL {
		return s.coins, nil
	}
	all, err := s.pay.Coins(ctx)
	if err != nil {
		if s.coins != nil {
			return s.coins, nil // a stale list sells; an empty one does not
		}
		return nil, err
	}
	offered := make([]Coin, 0, len(all))
	for _, coin := range all {
		if s.cfg.Payouts[Family(coin.Ticker)] != "" {
			offered = append(offered, coin)
		}
	}
	s.coins, s.coinsAt = offered, s.Now()
	return offered, nil
}

// minimum is the smallest payment the forwarder forwards in an offered coin.
func (s *Service) minimum(ctx context.Context, ticker string) (float64, bool) {
	coins, err := s.offered(ctx)
	if err != nil {
		return 0, false
	}
	for _, coin := range coins {
		if coin.Ticker == ticker {
			return coin.Minimum, true
		}
	}
	return 0, false
}

func (s *Service) listCoins(w http.ResponseWriter, r *http.Request) {
	coins, err := s.offered(r.Context())
	if err != nil {
		s.unavailable(w, "coins", err)
		return
	}
	httpjson.Write(w, http.StatusOK, map[string]any{"coins": coins, "min_usd": s.cfg.MinUSD, "max_usd": s.cfg.MaxUSD})
}

type createRequest struct {
	Ticker string   `json:"ticker"`
	USD    *float64 `json:"usd"`
}

// create opens an order: a price, an address and the secret that will read the key.
func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := httpjson.DecodeStrict(r, maxBodyBytes, &req); err != nil {
		httpjson.Error(w, httpjson.DecodeStatus(err), err.Error())
		return
	}
	payout := s.cfg.Payouts[Family(req.Ticker)]
	switch {
	case !tickerPattern.MatchString(req.Ticker) || payout == "":
		httpjson.Error(w, http.StatusBadRequest, "this coin is not offered; see "+coinsRoute)
		return
	case req.USD == nil || !(*req.USD >= s.cfg.MinUSD) || *req.USD > s.cfg.MaxUSD:
		httpjson.Error(w, http.StatusBadRequest, "usd must be between "+formatUSD(s.cfg.MinUSD)+" and "+formatUSD(s.cfg.MaxUSD))
		return
	case !s.limiter.Allow():
		w.Header().Set("Retry-After", retryAfter)
		httpjson.Error(w, http.StatusTooManyRequests, "too many orders, retry shortly")
		return
	}
	usd := math.Round(*req.USD*centsPerUSD) / centsPerUSD
	amount, quoteRate, err := s.pay.Quote(r.Context(), req.Ticker, usd)
	if err != nil {
		s.unavailable(w, "quote", err)
		return
	}
	if least, known := s.minimum(r.Context(), req.Ticker); !known {
		httpjson.Error(w, http.StatusBadRequest, "this coin is not offered; see "+coinsRoute)
		return
	} else if coins, parseErr := strconv.ParseFloat(amount, 64); parseErr != nil || coins < least {
		// The forwarder keeps a payment under its minimum for the coin: such an order could be paid and never become a key.
		httpjson.Error(w, http.StatusBadRequest, "the forwarder takes no less than "+strconv.FormatFloat(least, 'f', -1, 64)+
			" of this coin, about "+formatUSD(math.Ceil(least/quoteRate*centsPerUSD)/centsPerUSD)+" USD; buy more or pick another coin")
		return
	}
	id, claim := strings.ToLower(rand.Text()), rand.Text()
	address, err := s.pay.Address(r.Context(), req.Ticker, payout, s.callbackURL()+"?"+url.Values{"order": {id}}.Encode())
	if err != nil {
		s.unavailable(w, "address", err)
		return
	}
	order := Order{ID: id, Ticker: req.Ticker, USD: usd, Amount: amount, Rate: quoteRate, Address: address,
		ClaimHash: hashClaim(claim), Created: s.Now().UTC()}
	if err = s.store.Put(order); err != nil {
		s.unavailable(w, "order", err) // an order that would not survive a restart must not be paid
		return
	}
	reply := s.view(order)
	reply["claim"] = claim
	httpjson.Write(w, http.StatusCreated, reply)
}

// status shows an order to the holder of its claim secret, with the key once it is paid.
func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	claim, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	order, ok := s.store.Get(r.PathValue("id"))
	if !ok || claim == "" || subtle.ConstantTimeCompare([]byte(hashClaim(claim)), []byte(order.ClaimHash)) != 1 {
		w.WriteHeader(http.StatusNotFound) // the same answer for no order and a wrong secret
		return
	}
	httpjson.Write(w, http.StatusOK, s.view(order))
}

// view is what the buyer may know of an order.
func (s *Service) view(order Order) map[string]any {
	view := map[string]any{
		"order":      order.ID,
		"ticker":     order.Ticker,
		"usd":        order.USD,
		"amount":     order.Amount,
		"address":    order.Address,
		"expires_at": order.Created.Add(s.cfg.QuoteTTL),
		"status":     "pending",
	}
	if order.Paid() {
		view["status"] = "paid"
		view["credited_usd"] = order.CreditedUSD
		view["txid"] = order.TxID
		view["key"] = order.Key // empty when the key was never issued or is no longer kept
	}
	return view
}

// callback is the forwarder reporting a payment. A reply other than ok makes it call again, so only what a retry can mend
// answers otherwise.
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	if err := s.pay.Verify(s.callbackURL(), r); err != nil {
		s.logger.Warn("coinpay: callback refused", "err", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	query := r.URL.Query()
	txid, paidCoin := query.Get("txid_in"), query.Get("value_coin")
	order, ok := s.store.Get(query.Get("order"))
	paid, err := strconv.ParseFloat(paidCoin, 64)
	switch {
	case query.Get("pending") == "1":
		writeOK(w) // an unconfirmed payment, which we never ask to hear of
		return
	case !ok:
		s.logger.Error("coinpay: payment to an order we do not hold, credit it by hand", "order", query.Get("order"), "txid", txid)
		writeOK(w)
		return
	case query.Get("coin") != strings.ReplaceAll(order.Ticker, "/", "_") || query.Get("address_in") != order.Address ||
		txid == "" || err != nil || !(paid > 0):
		s.logger.Error("coinpay: callback does not match its order", "order", order.ID, "txid", txid)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.credit(w, r, order.ID, txid, paidCoin, paid)
}

// credit turns one payment into the order's key, once.
func (s *Service) credit(w http.ResponseWriter, r *http.Request, id, txid, paidCoin string, paid float64) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	order, _ := s.store.Get(id)
	if order.Paid() {
		if order.TxID != txid {
			s.logger.Error("coinpay: a second payment to a paid order, credit it by hand", "order", id, "txid", txid, "coin", paidCoin)
		}
		writeOK(w)
		return
	}
	now := s.Now().UTC()
	coinPerUSD := order.Rate
	if now.Sub(order.Created) > s.cfg.QuoteTTL { // the quote lapsed: the payment is worth what it is worth now
		var err error
		if _, coinPerUSD, err = s.pay.Quote(r.Context(), order.Ticker, order.USD); err != nil {
			s.retryLater(w, "late quote", id, err)
			return
		}
	}
	credited := math.Min(math.Floor(paid/coinPerUSD*centsPerUSD+centEpsilon)/centsPerUSD, s.cfg.MaxUSD)
	order.TxID, order.PaidCoin, order.PaidAt, order.CreditedUSD, order.Alias = txid, paidCoin, now, credited, aliasPrefix+id
	taken, err := s.keys.Exists(r.Context(), order.Alias)
	switch {
	case err != nil:
		s.retryLater(w, "lookup", id, err)
		return
	case taken:
		s.logger.Error("coinpay: the key of this order was issued and lost, issue another by hand", "order", id, "txid", txid)
	case credited <= 0:
		s.logger.Error("coinpay: a payment too small to credit", "order", id, "txid", txid, "coin", paidCoin)
	default:
		if order.Key, err = s.keys.Issue(r.Context(), order.Alias, credited, s.cfg.RPMLimit); err != nil {
			s.retryLater(w, "issue", id, err)
			return
		}
	}
	if err = s.store.Put(order); err != nil {
		s.logger.Error("coinpay: paid but not recorded, the key is lost at the next restart", "order", id, "txid", txid, "err", err)
	}
	s.logger.Info("coinpay: paid", "order", id, "ticker", order.Ticker, "coin", paidCoin, "credited_usd", credited, "txid", txid)
	writeOK(w)
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(callbackOK))
}

func (s *Service) retryLater(w http.ResponseWriter, step, id string, err error) {
	s.logger.Error("coinpay: payment not credited yet", "step", step, "order", id, "err", err)
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (s *Service) unavailable(w http.ResponseWriter, step string, err error) {
	s.logger.Error("coinpay: request failed", "step", step, "err", err)
	httpjson.Error(w, http.StatusBadGateway, "payments are unavailable, retry shortly")
}

func hashClaim(claim string) string {
	digest := sha256.Sum256([]byte(claim))
	return hex.EncodeToString(digest[:])
}

func formatUSD(usd float64) string { return strconv.FormatFloat(usd, 'f', -1, 64) }

// ValidatePayouts refuses a payout file naming a kind of address no coin pays out to: a typo there would silently drop
// that coin from sale.
func ValidatePayouts(payouts map[string]string) error {
	known := map[string]bool{"btc": true, "bch": true, "ltc": true, "doge": true, "zec": true, "xmr": true, "xrp": true,
		familyEVM: true, familyTron: true, "sol": true, "ton": true}
	if len(payouts) == 0 {
		return errors.New("payouts: no address given")
	}
	for family, address := range payouts {
		if !known[family] || strings.TrimSpace(address) == "" || strings.TrimSpace(address) != address {
			return errors.New("payouts: unknown kind or empty address under " + strconv.Quote(family))
		}
	}
	return nil
}
