// Command x402-smoke is the operator's client for trying a purchase on devnet: it checks the 402 against the signed catalog,
// answers it with a wallet file, then recovers the key; scripts/x402-devnet-smoke.sh drives it. It is no part of any
// measured image.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402client"
)

const (
	requestTimeout = 2 * time.Minute // a settlement holds the reply open while it confirms
	memoBytes      = 16              // the spec's random nonce
	maxReplyBytes  = 1 << 20

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("x402-smoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("url", "", "gateway base URL")
	walletPath := flags.String("wallet", "", "paying wallet: a Solana CLI keypair file (JSON array of 64 bytes)")
	catalogURL := flags.String("catalog-url", "", "identity base URL whose signed catalog the challenge must match")
	amount := flags.String("amount-usd", "20", "amount to pay")
	solanaPayRPC := flags.String("solana-pay-rpc", "", "also pay by a Solana Pay transfer, sent through this RPC URL, and claim it")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *baseURL == "" || *catalogURL == "" || *walletPath == "" {
		_, _ = fmt.Fprintln(stderr, "x402-smoke: -url, -catalog-url and -wallet are required")
		return exitUsage
	}
	wallet, err := loadWallet(*walletPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "x402-smoke:", err)
		return exitUsage
	}
	c := &client{baseURL: strings.TrimRight(*baseURL, "/"), catalogURL: strings.TrimRight(*catalogURL, "/"), wallet: wallet,
		http: &http.Client{Timeout: requestTimeout}, out: stdout}
	if err = c.flow(ctx, *amount); err != nil {
		_, _ = fmt.Fprintln(stderr, "x402-smoke: FAIL:", err)
		return exitError
	}
	_, _ = fmt.Fprintln(stdout, "OK: challenge, settlement, duplicate refusal and recovery all behaved")
	if *solanaPayRPC != "" {
		if err = c.claimFlow(ctx, *solanaPayRPC, *amount); err != nil {
			_, _ = fmt.Fprintln(stderr, "x402-smoke: FAIL:", err)
			return exitError
		}
		_, _ = fmt.Fprintln(stdout, "OK: a spec-shaped transfer was found, claimed, and claimed again to the same key")
	}
	return exitOK
}

func loadWallet(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's own -wallet path
	if err != nil {
		return nil, fmt.Errorf("wallet: %w", err)
	}
	var key []byte
	var ints []int
	if err = json.Unmarshal(raw, &ints); err != nil {
		return nil, fmt.Errorf("wallet: %w", err)
	}
	for _, v := range ints {
		key = append(key, byte(v)) //nolint:gosec // a keypair file holds bytes
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("wallet: %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	return key, nil
}

type client struct {
	baseURL    string
	catalogURL string
	wallet     ed25519.PrivateKey
	http       *http.Client
	out        io.Writer
}

type response struct {
	status int
	header http.Header
	body   map[string]any
}

func (c *client) post(ctx context.Context, path, body string, headers map[string]string) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(body))
	if err != nil {
		return response{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return response{}, err
	}
	var decoded map[string]any
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &decoded); err != nil {
			return response{}, fmt.Errorf("%s: reply: %w", path, err)
		}
	}
	return response{status: resp.StatusCode, header: resp.Header, body: decoded}, nil
}

func (c *client) flow(ctx context.Context, amountUSD string) error {
	body := `{"amount_usd":` + amountUSD + `}`
	first, err := c.post(ctx, "/v1/keys/buy", body, nil)
	if err != nil {
		return err
	}
	if first.status != http.StatusPaymentRequired {
		return fmt.Errorf("want a 402 challenge, got %d", first.status)
	}
	accepted, err := readChallenge(first.header.Get(x402.HeaderRequired))
	if err != nil {
		return err
	}
	if err = c.checkCatalog(ctx, accepted); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.out, "challenge: %s base units to %s, fees by %s\n", accepted.Amount, accepted.PayTo, accepted.Extra.FeePayer)
	raw, err := c.buildPayment(accepted)
	if err != nil {
		return err
	}
	payload := x402.Payload{X402Version: x402.Version, Accepted: accepted}
	payload.Payload.Transaction = base64.StdEncoding.EncodeToString(raw)
	header, err := x402.EncodeHeader(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{x402.HeaderSignature: header}

	settled, err := c.post(ctx, "/v1/keys/buy", body, headers)
	if err != nil {
		return err
	}
	if settled.status != http.StatusOK {
		return fmt.Errorf("want the key, got %d: %v", settled.status, settled.body)
	}
	transaction, ok := settled.body["transaction"].(string)
	if !ok || settled.body["key"] == nil {
		return fmt.Errorf("reply lacks a key or a transaction: %d", settled.status)
	}
	_, _ = fmt.Fprintf(c.out, "settled: %s, alias %v, budget %v USD\n", transaction, settled.body["alias"], settled.body["max_budget_usd"])

	duplicate, err := c.post(ctx, "/v1/keys/buy", body, headers)
	if err != nil {
		return err
	}
	if duplicate.status != http.StatusConflict {
		return fmt.Errorf("a repeated purchase must get 409, got %d", duplicate.status)
	}
	return c.recoverKey(ctx, transaction, settled.body["key"])
}

// checkCatalog is what a careful client does before paying: the challenge's terms must be the ones the enclave signed.
// catalogTerms is what the signed catalog says a purchase pays.
type catalogTerms struct {
	PayTo    string   `json:"pay_to"`
	Networks []string `json:"networks"`
	Asset    string   `json:"asset"`
	FeePayer string   `json:"fee_payer"`
}

func (c *client) readCatalog(ctx context.Context) (catalogTerms, error) {
	var catalog catalogTerms
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.catalogURL+"/v1/catalog", nil)
	if err != nil {
		return catalog, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return catalog, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxReplyBytes)).Decode(&catalog); err != nil {
		return catalog, fmt.Errorf("catalog: %w", err)
	}
	return catalog, nil
}

func (c *client) checkCatalog(ctx context.Context, accepted x402.Requirements) error {
	catalog, err := c.readCatalog(ctx)
	if err != nil {
		return err
	}
	if catalog.PayTo != accepted.PayTo || catalog.Asset != accepted.Asset || catalog.FeePayer != accepted.Extra.FeePayer ||
		!slices.Contains(catalog.Networks, accepted.Network) {
		return fmt.Errorf("the challenge differs from the signed catalog: %+v against %+v", accepted, catalog)
	}
	return nil
}

func readChallenge(header string) (x402.Requirements, error) {
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return x402.Requirements{}, fmt.Errorf("challenge: %w", err)
	}
	var required x402.Required
	if err = json.Unmarshal(raw, &required); err != nil {
		return x402.Requirements{}, fmt.Errorf("challenge: %w", err)
	}
	if len(required.Accepts) != 1 {
		return x402.Requirements{}, errors.New("challenge: want one accepted payment")
	}
	return required.Accepts[0], nil
}

func (c *client) buildPayment(accepted x402.Requirements) ([]byte, error) {
	feePayer, err := solana.PublicKeyFromBase58(accepted.Extra.FeePayer)
	if err != nil {
		return nil, fmt.Errorf("fee payer: %w", err)
	}
	treasury, err := solana.PublicKeyFromBase58(accepted.PayTo)
	if err != nil {
		return nil, fmt.Errorf("treasury: %w", err)
	}
	mint, err := solana.PublicKeyFromBase58(accepted.Asset)
	if err != nil {
		return nil, fmt.Errorf("asset: %w", err)
	}
	blockhash, err := solana.HashFromBase58(accepted.Extra.RecentBlockhash)
	if err != nil {
		return nil, fmt.Errorf("the challenge carries no usable blockhash hint: %w", err)
	}
	var amount uint64
	if _, err = fmt.Sscan(accepted.Amount, &amount); err != nil {
		return nil, fmt.Errorf("amount: %w", err)
	}
	nonce := make([]byte, memoBytes)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	msg, err := x402client.Payment{Payer: c.wallet, FeePayer: feePayer, Treasury: treasury, Mint: mint, Amount: amount,
		Blockhash: blockhash, Memo: hex.EncodeToString(nonce)}.Message()
	if err != nil {
		return nil, err
	}
	return x402client.Sign(msg, c.wallet)
}

// recoverKey proves the wallet path: the same key comes back.
func (c *client) recoverKey(ctx context.Context, transaction string, key any) error {
	id, err := solana.SignatureFromBase58(transaction)
	if err != nil {
		return fmt.Errorf("transaction: %w", err)
	}
	now := time.Now().Unix()
	proof := solana.SignatureFromBytes(ed25519.Sign(c.wallet, x402.RecoverMessage(id, now)))
	payer := solana.PublicKeyFromBytes(c.wallet[ed25519.SeedSize:])
	body := fmt.Sprintf(`{"transaction":%q,"payer":%q,"timestamp":%d,"signature":%q}`, transaction, payer, now, proof)
	got, err := c.post(ctx, "/v1/keys/recover", body, nil)
	if err != nil {
		return err
	}
	if got.status != http.StatusOK || got.body["key"] != key {
		return fmt.Errorf("recovery must return the same key, got status %d", got.status)
	}
	_, _ = fmt.Fprintf(c.out, "recovered: alias %v\n", got.body["alias"])
	return nil
}
