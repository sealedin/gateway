package coinpay

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // the forwarder's published callback key
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	// DefaultPayGateAPI is the forwarder's shared endpoint.
	DefaultPayGateAPI = "https://api.paygate.to"

	signatureHeader = "X-Paygate-Signature"
	keyIDHeader     = "X-Paygate-Key-Id"
	firstKeyID      = "v1"

	maxReplyBytes = 1 << 20 // the coin list is about 40 KB
)

// The key every PayGate callback is signed with, as published at https://paygate.to/docs/paygate_callback_public.pem on
// 2026-11-24. A new key id is refused until its key is added here.
//
//go:embed paygate_callback_v1.pem
var payGateKeyV1 []byte

// tickerPattern bounds what goes into a request path: a coin, or a network and a token.
var tickerPattern = regexp.MustCompile(`^[a-z0-9-]{1,16}(/[a-z0-9.-]{1,16})?$`)

var errBadSignature = errors.New("paygate: callback signature does not verify")

// Coin is one way to pay.
type Coin struct {
	Ticker  string  `json:"ticker"`  // btc, or network/token as in trc20/usdt
	Name    string  `json:"name"`    // as the forwarder names it
	Minimum float64 `json:"minimum"` // a smaller payment is never forwarded
}

// PayGate is the client of PayGate.to, a forwarder with no merchant account: it gives a fresh address per order, sends
// whatever arrives there on to our own address and calls back with a signature.
type PayGate struct {
	APIBase string
	HTTP    *http.Client
	Keys    map[string]*rsa.PublicKey // callback keys by id
}

// NewPayGate is the client holding the published callback key.
func NewPayGate(apiBase string, client *http.Client) (*PayGate, error) {
	block, _ := pem.Decode(payGateKeyV1)
	if block == nil {
		return nil, errors.New("paygate: the embedded callback key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("paygate: embedded callback key: %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("paygate: the embedded callback key is not RSA")
	}
	return &PayGate{APIBase: apiBase, HTTP: client, Keys: map[string]*rsa.PublicKey{firstKeyID: key}}, nil
}

// coinInfo is one entry of the forwarder's coin list.
type coinInfo struct {
	Coin    string `json:"coin"`
	Ticker  string `json:"ticker"`
	Minimum string `json:"minimum_transaction_coin"`
}

// Coins lists everything the forwarder takes, sorted by ticker. Entries it reports in a shape we do not know are skipped.
func (p *PayGate) Coins(ctx context.Context) ([]Coin, error) {
	var list map[string]json.RawMessage
	if err := p.get(ctx, "/crypto/info.php", "coins", &list); err != nil {
		return nil, err
	}
	coins := make([]Coin, 0, len(list))
	for name, raw := range list {
		var native coinInfo
		if json.Unmarshal(raw, &native) == nil && native.Ticker != "" {
			coins = appendCoin(coins, name, native)
			continue
		}
		var tokens map[string]coinInfo
		if json.Unmarshal(raw, &tokens) != nil {
			continue
		}
		for token, info := range tokens {
			coins = appendCoin(coins, name+"/"+token, info)
		}
	}
	sort.Slice(coins, func(i, j int) bool { return coins[i].Ticker < coins[j].Ticker })
	return coins, nil
}

func appendCoin(coins []Coin, ticker string, info coinInfo) []Coin {
	minimum, err := strconv.ParseFloat(info.Minimum, 64)
	if err != nil || minimum < 0 || !tickerPattern.MatchString(ticker) {
		return coins
	}
	return append(coins, Coin{Ticker: ticker, Name: info.Coin, Minimum: minimum})
}

// Quote prices usd in the coin: the amount to show the buyer and the rate, in coin per USD, it was priced at.
func (p *PayGate) Quote(ctx context.Context, ticker string, usd float64) (string, float64, error) {
	var reply struct {
		Status string `json:"status"`
		Amount string `json:"value_coin"`
		Rate   string `json:"exchange_rate"`
	}
	query := url.Values{"from": {"usd"}, "value": {strconv.FormatFloat(usd, 'f', 2, 64)}}
	if err := p.get(ctx, "/crypto/"+ticker+"/convert.php?"+query.Encode(), "quote", &reply); err != nil {
		return "", 0, err
	}
	amount, amountErr := strconv.ParseFloat(reply.Amount, 64)
	rate, rateErr := strconv.ParseFloat(reply.Rate, 64)
	if reply.Status != "success" || amountErr != nil || rateErr != nil || !(amount > 0) || !(rate > 0) {
		return "", 0, errors.New("paygate: quote: no price for this coin")
	}
	return reply.Amount, rate, nil
}

// Address asks for the address a buyer pays: whatever arrives there is forwarded to payout, and callback is then requested
// with the payment appended to its query. One callback URL always gets the same address.
func (p *PayGate) Address(ctx context.Context, ticker, payout, callback string) (string, error) {
	var reply struct {
		AddressIn string `json:"address_in"`
		Callback  string `json:"callback_url"`
	}
	query := url.Values{"address": {payout}, "callback": {callback}}
	if err := p.get(ctx, "/crypto/"+ticker+"/wallet.php?"+query.Encode(), "address", &reply); err != nil {
		return "", err
	}
	if reply.AddressIn == "" || reply.Callback != callback {
		return "", errors.New("paygate: address: reply names no address for this callback")
	}
	return reply.AddressIn, nil
}

// Verify checks that a callback is the forwarder's: an RSA signature (SHA-256, PKCS#1 v1.5) over the registered callback
// URL and the query string exactly as it arrived.
func (p *PayGate) Verify(callbackURL string, r *http.Request) error {
	id := r.Header.Get(keyIDHeader)
	if id == "" {
		id = firstKeyID
	}
	key, known := p.Keys[id]
	signature, err := base64.StdEncoding.DecodeString(r.Header.Get(signatureHeader))
	if !known || err != nil {
		return errBadSignature
	}
	digest := sha256.Sum256([]byte(callbackURL + "?" + r.URL.RawQuery))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return errBadSignature
	}
	return nil
}

// get never puts a URL in an error: it carries our payout address and the order's callback.
func (p *PayGate) get(ctx context.Context, path, name string, reply any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.APIBase+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("paygate: %s: %w", name, err)
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			err = urlErr.Err
		}
		return fmt.Errorf("paygate: %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("paygate: %s: status %d", name, resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxReplyBytes)).Decode(reply); err != nil {
		return fmt.Errorf("paygate: %s: invalid reply", name)
	}
	return nil
}

// Family is the kind of address a ticker pays out to, which is the name the payout file gives that address under: one EVM
// address serves every EVM network. Empty for a network we have not mapped, which is then not offered: a payout address of
// the wrong kind would lose the payment.
func Family(ticker string) string {
	network, _, token := strings.Cut(ticker, "/")
	switch network {
	case "btc", "bch", "ltc", "doge", "zec", "xmr", "xrp":
		if !token {
			return network
		}
	case "eth":
		if !token {
			return familyEVM
		}
	case "trx":
		if !token {
			return familyTron
		}
	case "erc20", "bep20", "arbitrum", "avax-c", "base", "bera", "linea", "monad", "optimism", "polygon":
		if token {
			return familyEVM
		}
	case "trc20":
		if token {
			return familyTron
		}
	case "sol", "ton":
		if token {
			return network
		}
	}
	return ""
}

const (
	familyEVM  = "evm"
	familyTron = "tron"
)
