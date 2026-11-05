package sales_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402client"
	"github.com/sealedin/gateway/internal/x402/x402test"
)

const (
	claimPath  = "/v1/keys/claim"
	amount5USD = 5_000_000
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// buyer is a browser's code and the reference it opens, with its own wallet so transactions differ.
type buyer struct {
	code      string
	reference solana.PublicKey
	nonce     byte
}

func newBuyer(t *testing.T, seed byte) *buyer {
	t.Helper()
	raw := make([]byte, x402.ClaimCodeBytes)
	raw[0] = seed
	code := base58.Encode(raw)
	reference, err := x402.ParseClaimCode(code)
	require.NoError(t, err)
	return &buyer{code: code, reference: reference}
}

func (b *buyer) transfer(t *testing.T, s *shop, amount uint64, plain bool) []byte {
	t.Helper()
	b.nonce++
	raw, err := x402client.SolanaPayTransfer{Payer: s.world.Payer, Treasury: s.world.Treasury, Mint: s.world.Policy.Mint, Amount: amount,
		Reference: b.reference, Blockhash: solana.Hash{b.nonce}, Plain: plain}.Build()
	require.NoError(t, err)
	return raw
}

func idOfTx(t *testing.T, raw []byte) string {
	t.Helper()
	tx, err := solana.TransactionFromBytes(raw)
	require.NoError(t, err)
	return tx.Signatures[0].String()
}

func (s *shop) pay(t *testing.T, b *buyer, amount uint64) solana.Signature {
	t.Helper()
	return s.chain.LandUnder(t, b.transfer(t, s, amount, false), b.reference, "")
}

func (s *shop) claim(t *testing.T, b *buyer, headers map[string]string) reply {
	t.Helper()
	body, err := json.Marshal(map[string]string{"code": b.code})
	require.NoError(t, err)
	s.after(4 * time.Second) // past the negative cache
	return s.post(t, claimPath, string(body), headers)
}

func TestClaimIsPendingUntilPaid(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 1)
	got := s.claim(t, b, nil)
	require.Equal(t, http.StatusAccepted, got.status)
	require.NotEmpty(t, got.headers.Get("Retry-After"))

	s.pay(t, b, amount25USD)
	got = s.claim(t, b, nil)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.Regexp(t, "^sk-", got.body["key"])
	require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12)
	require.NotEmpty(t, got.body["transaction"])
	require.Equal(t, "no-store", got.headers.Get("Cache-Control"))
}

// A repeated claim is the same key and the same budget, so a claim needs no wallet and no recovery route.
func TestClaimRepeatsWithoutCreditingAgain(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 2)
	s.pay(t, b, amount25USD)
	first := s.claim(t, b, nil)
	for range 3 {
		got := s.claim(t, b, nil)
		require.Equal(t, http.StatusOK, got.status, "%v", got.body)
		require.Equal(t, first.body["key"], got.body["key"])
		require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12)
	}
}

// A QR scanned twice: both payments land on the one key, each exactly once.
func TestSecondPaymentUnderAReferenceCreditsTheSameKeyOnce(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 3)
	s.pay(t, b, amount25USD)
	first := s.claim(t, b, nil)
	require.Equal(t, http.StatusOK, first.status)
	s.pay(t, b, amount25USD)
	for range 2 {
		got := s.claim(t, b, nil)
		require.Equal(t, first.body["key"], got.body["key"])
		require.InEpsilon(t, 50.0, got.body["max_budget_usd"], 1e-12)
	}
}

func TestClaimBelowTheMinimumIssuesNothingAndSaysSo(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 4)
	id := s.pay(t, b, amount5USD)
	got := s.claim(t, b, nil)
	require.Equal(t, http.StatusConflict, got.status)
	require.Equal(t, "below_minimum", got.body["reason"])
	require.Contains(t, got.body["error"], "minimum")
	require.Equal(t, id.String(), got.body["transaction"])
	require.Empty(t, s.fake.Generated())
}

func TestClaimAboveTheMaximumCreditsWhatWasPaid(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 5)
	s.pay(t, b, 750_000_000)
	got := s.claim(t, b, nil)
	require.Equal(t, http.StatusOK, got.status)
	require.InEpsilon(t, 750.0, got.body["max_budget_usd"], 1e-12)
}

func TestClaimWithABearerTopsUpAndReturnsNoKey(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	key, _, _ := s.firstKey(t)
	b := newBuyer(t, 6)
	s.pay(t, b, amount25USD)
	headers := map[string]string{"Authorization": "Bearer " + key}
	for range 2 {
		got := s.claim(t, b, headers)
		require.Equal(t, http.StatusOK, got.status, "%v", got.body)
		require.NotContains(t, got.body, "key")
		require.InEpsilon(t, 50.0, got.body["max_budget_usd"], 1e-12)
	}
	// The first claim decided where the money went: without the bearer it is not credited again, and no key comes back.
	got := s.claim(t, b, nil)
	require.Equal(t, http.StatusConflict, got.status)
	require.Equal(t, "credited_elsewhere", got.body["reason"])
	require.NotContains(t, got.body, "key")
}

// The other way round: a key's claim decided, so a bearer does not take the money and is told.
func TestClaimWithABearerAfterTheKeyWasClaimed(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	key, _, _ := s.firstKey(t)
	b := newBuyer(t, 16)
	s.pay(t, b, amount25USD)
	require.Equal(t, http.StatusOK, s.claim(t, b, nil).status)
	got := s.claim(t, b, map[string]string{"Authorization": "Bearer " + key})
	require.Equal(t, http.StatusConflict, got.status)
	require.Equal(t, "credited_elsewhere", got.body["reason"])
	info, err := s.gw.LookupKey(t.Context(), key)
	require.NoError(t, err)
	require.InEpsilon(t, 25.0, info.MaxBudgetUSD, 1e-12)
}

func TestClaimRefusesABadBearerBeforeAnyRPC(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	got := s.claim(t, newBuyer(t, 7), map[string]string{"Authorization": "Bearer sk-nope"})
	require.Equal(t, http.StatusUnauthorized, got.status)
	require.Zero(t, s.chain.Calls("getSignaturesForAddress"))
}

func TestClaimRefusesABadCode(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	for _, body := range []string{`{"code":"0OIl"}`, `{"code":""}`, `{"code":1}`, `{}x`} {
		got := s.post(t, claimPath, body, nil)
		require.Equal(t, http.StatusBadRequest, got.status, body)
		require.Equal(t, "bad_code", got.body["reason"])
	}
}

// The code opens the key, so nothing that leaves here may carry it.
func TestClaimNeverRepeatsTheCode(t *testing.T) {
	t.Parallel()
	var logs lockedBuffer
	s := newLoggedShop(t, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	b := newBuyer(t, 8)
	s.pay(t, b, amount5USD)
	got := s.claim(t, b, nil)
	require.NotContains(t, logs.String(), b.code)
	raw, err := json.Marshal(got.body)
	require.NoError(t, err)
	require.NotContains(t, string(raw), b.code)
}

// Under the minimum and failed or unrelated transactions under one reference do not stop a good one.
func TestClaimFindsThePaymentAmongNoise(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 9)
	s.chain.LandUnder(t, b.transfer(t, s, amount25USD, false), b.reference, `{"InstructionError":[0,"x"]}`)
	s.pay(t, b, amount5USD)
	raw, err := x402client.SolanaPayTransfer{Payer: s.world.Payer, Treasury: x402test.Public(x402test.NewKey(t)), Mint: s.world.Policy.Mint,
		Amount: amount25USD, Reference: b.reference, Blockhash: solana.Hash{77}}.Build()
	require.NoError(t, err)
	s.chain.LandUnder(t, raw, b.reference, "")
	s.chain.LandUnder(t, b.transfer(t, s, amount25USD, true), b.reference, "")
	got := s.claim(t, b, nil)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12, "only the good one")
}

// The reference is public once paid: a transaction a host will not return, tagged with it, must not hold up the payment.
func TestClaimCreditsPastATransactionThatDoesNotRead(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 17)
	s.pay(t, b, amount25USD)
	s.chain.RefuseTransaction(s.pay(t, b, amount5USD).String())
	got := s.claim(t, b, nil)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12)
}

// Polling on a dust payment must not bury the alerts that need a person.
func TestClaimAlertsOnceForAPaymentUnderTheMinimum(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	s := newLoggedShop(t, nil, slog.New(slog.NewTextHandler(&lockedWriter{w: &logs}, nil)))
	b := newBuyer(t, 18)
	s.pay(t, b, amount5USD)
	require.Equal(t, http.StatusConflict, s.claim(t, b, nil).status)
	require.Equal(t, http.StatusConflict, s.claim(t, b, nil).status)
	require.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("operator must reconcile")))
}

// A lying primary cannot confirm alone, and cannot show another transaction under a real id.
func TestClaimNeedsBothHosts(t *testing.T) {
	t.Parallel()
	s := newShop(t, &x402test.Chain{ConfirmerBlind: true})
	b := newBuyer(t, 10)
	s.pay(t, b, amount25USD)
	got := s.claim(t, b, nil)
	require.Equal(t, http.StatusAccepted, got.status)
	require.Empty(t, s.fake.Generated())
}

// One lying host shows a well signed transaction paying 500 USD under a real id that paid 5: it is not read.
func TestClaimReadsNoSubstitutedTransaction(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 11)
	s.pay(t, b, amount5USD)
	s.chain.Substitute = b.transfer(t, s, 500_000_000, false)
	got := s.claim(t, b, nil)
	require.NotEqual(t, http.StatusOK, got.status)
	require.Empty(t, s.fake.Generated())
}

// A transaction naming two references reads under each on its own.
func TestClaimReadsATransactionUnderEachReference(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	first, second := newBuyer(t, 14), newBuyer(t, 15)
	raw := first.transfer(t, s, amount25USD, false)
	s.chain.LandUnder(t, raw, first.reference, "")
	s.chain.ListOnly(second.reference, idOfTx(t, raw))
	require.Equal(t, http.StatusOK, s.claim(t, first, nil).status)
	require.Equal(t, http.StatusAccepted, s.claim(t, second, nil).status)
}

func TestClaimPollsAreBounded(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	b := newBuyer(t, 12)
	body, err := json.Marshal(map[string]string{"code": b.code})
	require.NoError(t, err)
	for range 5 {
		require.Equal(t, http.StatusAccepted, s.post(t, claimPath, string(body), nil).status)
	}
	require.Equal(t, 1, s.chain.Calls("getSignaturesForAddress"), "a reference with nothing under it is asked for once")
	s.settler.ClaimLimiter.SetBurst(0)
	got := s.claim(t, newBuyer(t, 13), nil)
	require.Equal(t, http.StatusTooManyRequests, got.status)
	require.NotEmpty(t, got.headers.Get("Retry-After"))
	require.Zero(t, s.settler.Meter.Spent(), "nothing on this path costs SOL")
}
