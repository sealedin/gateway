package sales_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/sales"
	"github.com/sealedin/gateway/internal/solanarpc"
	"github.com/sealedin/gateway/internal/testsupport"
	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402test"
)

const (
	masterKey   = "sk-master"
	amount25USD = 25_000_000
	buyPath     = "/v1/keys/buy"
	recoverPath = "/v1/keys/recover"
	body25      = `{"amount_usd":25}`
)

type shop struct {
	srv     *httptest.Server
	chain   *x402test.Chain
	fake    *testsupport.FakeGateway
	world   *x402test.World
	settler *x402.Settler
	gw      *usage.Gateway
	offset  atomic.Int64 // how far the settler's clock runs ahead, in seconds
}

func newShop(t *testing.T, chain *x402test.Chain) *shop {
	t.Helper()
	return newLoggedShop(t, chain, slog.New(slog.DiscardHandler))
}

func newLoggedShop(t *testing.T, chain *x402test.Chain, logger *slog.Logger) *shop {
	t.Helper()
	if chain == nil {
		chain = &x402test.Chain{}
	}
	if chain.BlockTime == 0 {
		chain.BlockTime = time.Now().Unix()
	}
	world := x402test.NewWorld(t)
	primary, confirmer := chain.Clients(t)
	terms := x402.Terms{Network: "solana:test", Treasury: world.Treasury, Mint: world.Policy.Mint}
	settler, err := x402.NewSettler(terms, world.FeePayer, world.Keys, primary, confirmer, logger)
	require.NoError(t, err)
	settler.Poll = time.Millisecond
	settler.Wait = 200 * time.Millisecond
	fake := &testsupport.FakeGateway{MasterKey: masterKey}
	gw := fake.Client(t)
	mux := http.NewServeMux()
	sales.New(gw, gateway.CatalogModels(), settler, logger).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shop{srv: srv, chain: chain, fake: fake, world: world, settler: settler, gw: gw}
	settler.Now = func() time.Time { return time.Now().Add(time.Duration(s.offset.Load()) * time.Second) }
	return s
}

// after moves the clock and signs from the moved time on.
func (s *shop) after(d time.Duration) { s.offset.Add(int64(d / time.Second)) }

func (s *shop) now() time.Time { return s.settler.Now() }

type reply struct {
	status  int
	body    map[string]any
	headers http.Header
}

func (s *shop) post(t *testing.T, path, body string, headers map[string]string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var decoded map[string]any
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &decoded), "body: %s", raw)
	}
	return reply{status: resp.StatusCode, body: decoded, headers: resp.Header}
}

// challenge is the requirements of a fresh 402 for 25 USD.
func (s *shop) challenge(t *testing.T) x402.Requirements {
	t.Helper()
	got := s.post(t, buyPath, body25, nil)
	require.Equal(t, http.StatusPaymentRequired, got.status)
	var required x402.Required
	decodeHeader(t, got.headers.Get(x402.HeaderRequired), &required)
	require.Len(t, required.Accepts, 1)
	return required.Accepts[0]
}

func decodeHeader(t *testing.T, header string, into any) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, into))
}

// paymentHeader wraps a transaction the way a client does: the accepted terms plus the base64 transaction.
func paymentHeader(t *testing.T, accepted x402.Requirements, raw []byte) map[string]string {
	t.Helper()
	payload := x402.Payload{X402Version: 2, Accepted: accepted}
	payload.Payload.Transaction = base64.StdEncoding.EncodeToString(raw)
	header, err := x402.EncodeHeader(payload)
	require.NoError(t, err)
	return map[string]string{x402.HeaderSignature: header}
}

// buy pays 25 USD with a fresh transaction, optionally topping up a key.
func (s *shop) buy(t *testing.T, bearer string) (reply, []byte) {
	t.Helper()
	raw := s.world.ClientTx(t, amount25USD, nil)
	headers := paymentHeader(t, s.challenge(t), raw)
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	return s.post(t, buyPath, body25, headers), raw
}

func settlementOf(t *testing.T, got reply) x402.Settlement {
	t.Helper()
	var settled x402.Settlement
	decodeHeader(t, got.headers.Get(x402.HeaderResponse), &settled)
	return settled
}

func TestBuyAnswersTheChallengeWithoutPayment(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	got := s.post(t, buyPath, `{"amount_usd":25.5}`, nil)
	require.Equal(t, http.StatusPaymentRequired, got.status)
	require.Equal(t, "no-store", got.headers.Get("Cache-Control"), "a 402 stays out of shared caches")
	var required x402.Required
	decodeHeader(t, got.headers.Get(x402.HeaderRequired), &required)
	require.Equal(t, 2, required.X402Version)
	accepted := required.Accepts[0]
	require.Equal(t, "exact", accepted.Scheme)
	require.Equal(t, "25500000", accepted.Amount)
	require.Equal(t, s.world.Treasury.String(), accepted.PayTo)
	require.Equal(t, s.world.Policy.Mint.String(), accepted.Asset)
	require.Equal(t, s.world.FeePayer.String(), accepted.Extra.FeePayer)
	require.NotEmpty(t, accepted.Extra.RecentBlockhash)
	require.Equal(t, x402.MaxTimeoutSeconds, accepted.MaxTimeoutSeconds)
	require.Empty(t, s.fake.Generated())
}

func TestBuyValidatesTheAmount(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	tests := []struct {
		body string
		want int
	}{
		{`{"amount_usd":20}`, http.StatusPaymentRequired},
		{`{"amount_usd":500}`, http.StatusPaymentRequired},
		{`{"amount_usd":20.000001}`, http.StatusPaymentRequired},
		{`{"amount_usd":19.999999}`, http.StatusBadRequest},
		{`{"amount_usd":500.000001}`, http.StatusBadRequest},
		{`{"amount_usd":20.1234567}`, http.StatusBadRequest},
		{`{"amount_usd":0}`, http.StatusBadRequest},
		{`{"amount_usd":-25}`, http.StatusBadRequest},
		{`{"amount_usd":"25"}`, http.StatusBadRequest},
		{`{"amount_usd":2.5e1}`, http.StatusBadRequest},
		{`{"amount_usd":null}`, http.StatusBadRequest},
		{`{}`, http.StatusBadRequest},
		{`{"amount_usd":25,"max_budget_usd":1000}`, http.StatusBadRequest},
		{`{"amount_usd":25}{"amount_usd":25}`, http.StatusBadRequest},
		{`not json`, http.StatusBadRequest},
		{``, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.body, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, s.post(t, buyPath, tc.body, nil).status)
		})
	}
}

func TestBuyIssuesAKeyAfterConfirmation(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	got, _ := s.buy(t, "")
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)

	require.Len(t, s.chain.Sent(), 1)
	tx, err := solana.TransactionFromBytes(s.chain.Sent()[0])
	require.NoError(t, err)
	id := tx.Signatures[0].String()
	settled := settlementOf(t, got)
	require.True(t, settled.Success)
	require.Equal(t, id, settled.Transaction)
	require.Equal(t, "solana:test", settled.Network)
	require.Equal(t, x402test.Public(s.world.Payer).String(), settled.Payer)

	require.NotEmpty(t, got.body["key"])
	require.Regexp(t, `^x402-[0-9a-f]{32}$`, got.body["alias"])
	require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12)
	require.InEpsilon(t, 60.0, got.body["rpm_limit"], 1e-12)
	require.Equal(t, id, got.body["transaction"])
	require.Equal(t, "no-store", got.headers.Get("Cache-Control"))
	calls := s.fake.Generated()
	require.Len(t, calls, 1)
	require.Equal(t, gateway.CatalogModels(), calls[0].Models)
	require.InEpsilon(t, 25.0, calls[0].MaxBudget, 1e-12)
	require.Nil(t, calls[0].BudgetDuration, "prepaid credits never reset")
}

// Never a key before confirmation: every settlement failure leaves the gateway untouched.
func TestBuyIssuesNothingWithoutConfirmation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		chain  *x402test.Chain
		status int
		reason string
	}{
		{"simulation fails", &x402test.Chain{SimulationFailure: `"BlockhashNotFound"`}, http.StatusPaymentRequired, x402.ReasonSimulationFailed},
		{"client lacks funds", &x402test.Chain{SimulationFailure: `{"InstructionError":[2,{"Custom":1}]}`},
			http.StatusPaymentRequired, x402.ReasonInsufficientFunds},
		{"lands failed", &x402test.Chain{FailOnChain: "Boom"}, http.StatusPaymentRequired, x402.ReasonTransactionFailed},
		{"never lands", &x402test.Chain{Dropped: true}, http.StatusPaymentRequired, x402.ReasonPending},
		{"primary already claims the transaction", &x402test.Chain{Dropped: true, PrimaryLies: true}, http.StatusConflict, x402.ReasonDuplicate},
		{"a primary lying after the send", &x402test.Chain{Dropped: true, PrimaryLiesAfter: true},
			http.StatusPaymentRequired, x402.ReasonPending},
		{"independent host blind", &x402test.Chain{ConfirmerBlind: true}, http.StatusPaymentRequired, x402.ReasonPending},
		{"fee payer unfunded", &x402test.Chain{SimulationFailure: `"AccountNotFound"`}, http.StatusServiceUnavailable, ""},
		{"send refused", &x402test.Chain{SendRefused: true}, http.StatusServiceUnavailable, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newShop(t, tc.chain)
			got, _ := s.buy(t, "")
			require.Equal(t, tc.status, got.status, "%v", got.body)
			require.Empty(t, s.fake.Generated(), "no key without a confirmed payment")
			require.NotContains(t, got.body, "key")
			if tc.reason != "" {
				settled := settlementOf(t, got)
				require.False(t, settled.Success)
				require.Equal(t, tc.reason, settled.ErrorReason)
			}
			if tc.reason == x402.ReasonPending {
				require.NotEmpty(t, settlementOf(t, got).Transaction, "the spec requires the hash on settlement_pending")
				require.Empty(t, got.headers.Get(x402.HeaderRequired), "a transaction that may still land must not invite a second payment")
			}
		})
	}
}

// A rate-limited second host leaves every purchase pending, so a pending reply logs at error level: that is the alert.
func TestBuyAlertsOnPendingReplies(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	s := newLoggedShop(t, &x402test.Chain{ConfirmerBlind: true}, slog.New(slog.NewTextHandler(&lockedWriter{w: &logs}, nil)))
	got, _ := s.buy(t, "")
	require.Equal(t, http.StatusPaymentRequired, got.status)
	require.Contains(t, logs.String(), "level=ERROR msg=\"x402: payment refused\"")
}

func TestBuyRefusesPaymentsThatDoNotMatchTheRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(s *shop, accepted *x402.Requirements) []byte
		reason string
	}{
		{"smaller amount than requested", func(s *shop, _ *x402.Requirements) []byte {
			return s.world.ClientTx(t, amount25USD-1, nil)
		}, x402.ReasonAmountMismatch},
		{"larger amount than requested", func(s *shop, _ *x402.Requirements) []byte {
			return s.world.ClientTx(t, amount25USD+1, nil)
		}, x402.ReasonAmountMismatch},
		{"accepted terms differ", func(s *shop, accepted *x402.Requirements) []byte {
			accepted.PayTo = solana.PublicKey{1}.String()
			return s.world.ClientTx(t, amount25USD, nil)
		}, x402.ReasonRequirements},
		{"policy violation", func(s *shop, _ *x402.Requirements) []byte {
			return s.world.ClientTx(t, amount25USD, func(m *solana.Message) { m.Instructions = m.Instructions[:3] })
		}, x402.ReasonMemo},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newShop(t, nil)
			accepted := s.challenge(t)
			raw := tc.mutate(s, &accepted)
			got := s.post(t, buyPath, body25, paymentHeader(t, accepted, raw))
			require.Equal(t, http.StatusPaymentRequired, got.status)
			require.Equal(t, tc.reason, settlementOf(t, got).ErrorReason)
			require.Empty(t, s.chain.Simulated(), "static failures cost no RPC call")
		})
	}
}

func TestBuyRefusesAMalformedPaymentHeader(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	got := s.post(t, buyPath, body25, map[string]string{x402.HeaderSignature: "!!"})
	require.Equal(t, http.StatusBadRequest, got.status)
	require.Empty(t, s.chain.Simulated())
}

// A second request carrying settled bytes gets 409 and no key, including from someone else's connection with their own bearer.
func TestBuyRefusesASettledTransaction(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	first, raw := s.buy(t, "")
	require.Equal(t, http.StatusOK, first.status)
	replay := paymentHeader(t, s.challenge(t), raw)

	got := s.post(t, buyPath, body25, replay)
	require.Equal(t, http.StatusConflict, got.status)
	require.Equal(t, x402.ReasonDuplicate, settlementOf(t, got).ErrorReason)
	require.NotContains(t, got.body, "key")

	key, ok := first.body["key"].(string)
	require.True(t, ok)
	replay["Authorization"] = "Bearer " + key
	got = s.post(t, buyPath, body25, replay)
	require.Equal(t, http.StatusConflict, got.status, "public bytes never buy a top-up either")
	require.Len(t, s.fake.Generated(), 1)
	require.Len(t, s.chain.Sent(), 1)
}

// After a crash the in-process memory is gone: the chain alone still refuses the bytes.
func TestBuyRefusesATransactionTheChainKnows(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	raw := s.world.ClientTx(t, amount25USD, nil)
	pay, err := s.world.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	s.chain.Land(t, s.world.FeePayer.CoSign(pay))

	got := s.post(t, buyPath, body25, paymentHeader(t, s.challenge(t), raw))
	require.Equal(t, http.StatusConflict, got.status)
	require.Empty(t, s.fake.Generated())
	require.Empty(t, s.chain.Sent())
}

// A key under the transaction's alias refuses the bytes even if the chain's view lags.
func TestBuyRefusesATransactionWithAKey(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	raw := s.world.ClientTx(t, amount25USD, nil)
	pay, err := s.world.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	_, err = s.gw.Issue(t.Context(), sales.AliasFor(pay.Digest()), usage.KeyLimits{MaxBudgetUSD: 25, RPMLimit: 60,
		Key: s.settler.VirtualKey(pay.Digest())})
	require.NoError(t, err)
	got := s.post(t, buyPath, body25, paymentHeader(t, s.challenge(t), raw))
	require.Equal(t, http.StatusConflict, got.status)
	require.Empty(t, s.chain.Sent())
}

// A row under the alias with another token proves nothing: the bytes fail closed with no id disclosed, and nothing is sent.
func TestBuyFailsClosedOnAForeignRowUnderTheAlias(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	raw := s.world.ClientTx(t, amount25USD, nil)
	pay, err := s.world.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	_, err = s.gw.Issue(t.Context(), sales.AliasFor(pay.Digest()), usage.KeyLimits{Key: "sk-foreign"})
	require.NoError(t, err)
	got := s.post(t, buyPath, body25, paymentHeader(t, s.challenge(t), raw))
	require.Equal(t, http.StatusServiceUnavailable, got.status)
	require.NotContains(t, got.body, "transaction")
	require.Empty(t, got.headers.Get(x402.HeaderResponse))
	require.Empty(t, s.chain.Simulated())
}

// Concurrent submissions of one transaction: one settlement, one key.
func TestBuyClaimsAnInFlightTransaction(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	chain := &x402test.Chain{OnSend: func() { <-release }}
	s := newShop(t, chain)
	t.Cleanup(sync.OnceFunc(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}))
	raw := s.world.ClientTx(t, amount25USD, nil)
	headers := paymentHeader(t, s.challenge(t), raw)
	first := make(chan reply, 1)
	go func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.srv.URL+buyPath, strings.NewReader(body25))
		if err != nil {
			first <- reply{}
			return
		}
		req.Header.Set(x402.HeaderSignature, headers[x402.HeaderSignature])
		resp, err := s.srv.Client().Do(req)
		if err != nil {
			first <- reply{}
			return
		}
		_ = resp.Body.Close()
		first <- reply{status: resp.StatusCode}
	}()
	require.Eventually(t, func() bool { return s.chain.Calls(solanarpc.MethodSend) == 1 }, 2*time.Second, time.Millisecond)
	got := s.post(t, buyPath, body25, headers)
	require.Equal(t, http.StatusConflict, got.status)
	close(release)
	require.Equal(t, http.StatusOK, (<-first).status)
	require.Len(t, s.fake.Generated(), 1)
}

// While a transaction is only being checked, a colliding request learns nothing: its id is the sponsor's signature, which
// would let a client broadcast past simulation and past the fee meter.
func TestBuyNeverRevealsTheSignatureBeforeSimulationPassed(t *testing.T) {
	t.Parallel()
	release, entered := make(chan struct{}), make(chan struct{})
	once := sync.OnceFunc(func() { close(release) })
	chain := &x402test.Chain{OnSimulate: func() {
		close(entered)
		<-release
	}, SimulationFailure: `"BlockhashNotFound"`}
	s := newShop(t, chain)
	t.Cleanup(once)
	raw := s.world.ClientTx(t, amount25USD, nil)
	headers := paymentHeader(t, s.challenge(t), raw)
	first := make(chan int, 1)
	go func() {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.srv.URL+buyPath, strings.NewReader(body25))
		if err != nil {
			first <- 0
			return
		}
		req.Header.Set(x402.HeaderSignature, headers[x402.HeaderSignature])
		resp, err := s.srv.Client().Do(req)
		if err != nil {
			first <- 0
			return
		}
		_ = resp.Body.Close()
		first <- resp.StatusCode
	}()
	<-entered
	got := s.post(t, buyPath, body25, headers)
	require.Equal(t, http.StatusConflict, got.status)
	require.Empty(t, settlementOf(t, got).Transaction)
	require.NotContains(t, got.body, "transaction")
	once()
	require.Equal(t, http.StatusPaymentRequired, <-first)
	require.Empty(t, chain.Sent())
}

// A failed simulation leaves the transaction retryable: nothing was committed.
func TestBuyReleasesTheClaimWhenNothingWasSent(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{SimulationFailure: `"BlockhashNotFound"`}
	s := newShop(t, chain)
	raw := s.world.ClientTx(t, amount25USD, nil)
	headers := paymentHeader(t, s.challenge(t), raw)
	require.Equal(t, http.StatusPaymentRequired, s.post(t, buyPath, body25, headers).status)
	require.Equal(t, http.StatusPaymentRequired, s.post(t, buyPath, body25, headers).status, "still a payment failure, not a duplicate")
}

// Once bytes have left the process they stay claimed, so a retry cannot settle them twice.
func TestBuyKeepsTheClaimOnceSent(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{Dropped: true}
	s := newShop(t, chain)
	raw := s.world.ClientTx(t, amount25USD, nil)
	headers := paymentHeader(t, s.challenge(t), raw)
	require.Equal(t, http.StatusPaymentRequired, s.post(t, buyPath, body25, headers).status)
	require.Equal(t, http.StatusConflict, s.post(t, buyPath, body25, headers).status)
	require.Len(t, chain.Sent(), 1)
}

func TestBuyLimitsSettlementAttempts(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	s.settler.Limiter.SetBurst(0)
	got := s.post(t, buyPath, body25, paymentHeader(t, s.challenge(t), s.world.ClientTx(t, amount25USD, nil)))
	require.Equal(t, http.StatusTooManyRequests, got.status)
	require.Empty(t, s.chain.Simulated())
}

func TestBuyAnswers503AtTheFeeCeiling(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	s.settler.Meter.Ceiling = 1
	got := s.post(t, buyPath, body25, paymentHeader(t, s.challenge(t), s.world.ClientTx(t, amount25USD, nil)))
	require.Equal(t, http.StatusServiceUnavailable, got.status)
	require.Empty(t, s.chain.Sent())
}

// LiteLLM down at the last step: the money moved, so the reply says so and points at recovery.
func TestBuySettledButGatewayDownPointsAtRecovery(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	s.fake.SetFail("/key/generate", true)
	got, _ := s.buy(t, "")
	require.Equal(t, http.StatusBadGateway, got.status)
	require.True(t, settlementOf(t, got).Success, "the payment did settle")
	require.NotEmpty(t, got.body["transaction"])
	require.Contains(t, got.body["error"], recoverPath)
	require.NotContains(t, got.body, "key")
}

func TestTopUpAddsToTheKeysBudget(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	first, _ := s.buy(t, "")
	key, ok := first.body["key"].(string)
	require.True(t, ok)

	got, _ := s.buy(t, key)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.NotContains(t, got.body, "key", "the caller already holds it; no key material travels back")
	require.Equal(t, first.body["alias"], got.body["alias"])
	require.InEpsilon(t, 50.0, got.body["max_budget_usd"], 1e-12)
	require.True(t, settlementOf(t, got).Success)
	info, err := s.gw.LookupKey(t.Context(), key)
	require.NoError(t, err)
	require.InEpsilon(t, 50.0, info.MaxBudgetUSD, 1e-12)
}

func TestTopUpRefusesABadKeyBeforeAnyPayment(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	headers := paymentHeader(t, s.challenge(t), s.world.ClientTx(t, amount25USD, nil))
	for name, authorization := range map[string]string{
		"unknown key":  "Bearer sk-nobody",
		"empty bearer": "Bearer ",
		"other scheme": "Basic abc",
	} {
		headers["Authorization"] = authorization
		require.Equal(t, http.StatusUnauthorized, s.post(t, buyPath, body25, headers).status, name)
		challenge := s.post(t, buyPath, body25, map[string]string{"Authorization": authorization})
		require.Equal(t, http.StatusUnauthorized, challenge.status, name)
	}
	require.Empty(t, s.chain.Sent())
}

func TestTopUpRefusesABlockedKey(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	issued, err := s.gw.Issue(t.Context(), "alice", usage.KeyLimits{MaxBudgetUSD: 5, RPMLimit: 60})
	require.NoError(t, err)
	s.fake.Block(issued.Key)
	got := s.post(t, buyPath, body25, map[string]string{"Authorization": "Bearer " + issued.Key})
	require.Equal(t, http.StatusUnauthorized, got.status)
}

func TestTopUpBearerLookupFailuresAreNotAuthFailures(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	s.fake.SetFail("/key/info", true)
	got := s.post(t, buyPath, body25, map[string]string{"Authorization": "Bearer sk-any"})
	require.Equal(t, http.StatusBadGateway, got.status)
}

// landedPayment lands a paid transaction with no key, and returns it with its id.
func (s *shop) landedPayment(t *testing.T) (solana.Signature, x402.Payment) {
	t.Helper()
	pay, err := s.world.Policy.VerifyUnsigned(s.world.ClientTx(t, amount25USD, nil))
	require.NoError(t, err)
	s.chain.Land(t, s.world.FeePayer.CoSign(pay))
	return s.world.FeePayer.TransactionID(pay), pay
}

// recoverBody is a valid recovery request signed by the given wallet.
func recoverBody(t *testing.T, wallet ed25519.PrivateKey, id solana.Signature, at time.Time) string {
	t.Helper()
	sig := ed25519.Sign(wallet, x402.RecoverMessage(id, at.Unix()))
	encoded, err := json.Marshal(map[string]any{
		"transaction": id.String(),
		"payer":       x402test.Public(wallet).String(),
		"timestamp":   at.Unix(),
		"signature":   solana.SignatureFromBytes(sig).String(),
	})
	require.NoError(t, err)
	return string(encoded)
}

// landed puts a paid transaction on chain with no key issued, the crash between settlement and issuance.
func (s *shop) landed(t *testing.T) solana.Signature {
	t.Helper()
	raw := s.world.ClientTx(t, amount25USD, nil)
	pay, err := s.world.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	s.chain.Land(t, s.world.FeePayer.CoSign(pay))
	return s.world.FeePayer.TransactionID(pay)
}

func TestRecoverPinsTheSignedMessage(t *testing.T) {
	t.Parallel()
	var id solana.Signature
	id[0], id[63] = 0xaa, 0xbb
	want := append([]byte("sealedin-key-recover-v1\x00"), id[:]...)
	want = binary.BigEndian.AppendUint64(want, 1800000000)
	require.Equal(t, want, x402.RecoverMessage(id, 1800000000))
}

func TestRecoverIssuesAfterACrash(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	id := s.landed(t)
	got := s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, time.Now()), nil)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.NotEmpty(t, got.body["key"])
	require.Regexp(t, `^x402-[0-9a-f]{32}$`, got.body["alias"])
	require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12)
	require.Equal(t, id.String(), got.body["transaction"])
	require.Equal(t, gateway.CatalogModels(), s.fake.Generated()[0].Models)
	require.Equal(t, "no-store", got.headers.Get("Cache-Control"))
}

// firstKey buys a key and returns it with its transaction.
func (s *shop) firstKey(t *testing.T) (string, solana.Signature, reply) {
	t.Helper()
	first, _ := s.buy(t, "")
	require.Equal(t, http.StatusOK, first.status, "%v", first.body)
	key, ok := first.body["key"].(string)
	require.True(t, ok)
	tx, err := solana.TransactionFromBytes(s.chain.Sent()[0])
	require.NoError(t, err)
	return key, tx.Signatures[0], first
}

func (s *shop) recoverNow(t *testing.T, id solana.Signature) reply {
	t.Helper()
	s.after(time.Second) // each proof is a fresh one
	return s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, s.now()), nil)
}

// Recovery hands back the same key, whatever was spent or topped up meanwhile: nothing about it can forgive spend.
func TestRecoverReturnsTheSameKey(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	key, id, first := s.firstKey(t)
	_, _ = s.buy(t, key)
	got := s.recoverNow(t, id)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.Equal(t, key, got.body["key"])
	require.Equal(t, first.body["alias"], got.body["alias"])
	require.InEpsilon(t, 50.0, got.body["max_budget_usd"], 1e-12, "top-ups included")
	require.Equal(t, http.StatusOK, s.recoverNow(t, id).status, "and again")
	info, err := s.gw.LookupKey(t.Context(), key)
	require.NoError(t, err)
	require.False(t, info.Blocked, "recovery does not disturb a working key")
}

// A row that is not this payment's derived key was not issued here: it is not handed back, and nothing is issued.
func TestRecoverFailsClosedWhenTheKeyOnRecordIsNotDerived(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	raw := s.world.ClientTx(t, amount25USD, nil)
	pay, err := s.world.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	s.chain.Land(t, s.world.FeePayer.CoSign(pay))
	_, err = s.gw.Issue(t.Context(), sales.AliasFor(pay.Digest()), usage.KeyLimits{Key: "sk-somebody-elses", MaxBudgetUSD: 1})
	require.NoError(t, err)
	got := s.recoverNow(t, s.world.FeePayer.TransactionID(pay))
	require.Equal(t, http.StatusConflict, got.status)
	require.NotContains(t, got.body, "key")
	require.Len(t, s.fake.Generated(), 1)
}

// formerPayment lands a payment by this shop's wallet whose fee payer is not this shop's, as after a change of the env key.
func (s *shop) formerPayment(t *testing.T) (x402.Payment, solana.Signature) {
	t.Helper()
	other := x402test.NewWorld(t)
	other.Payer = s.world.Payer
	other.Treasury = s.world.Treasury
	policy, err := x402.NewPolicy(other.FeePayer.Public(), s.world.Treasury, s.world.Policy.Mint)
	require.NoError(t, err)
	other.Policy = policy
	pay, err := other.Policy.VerifyUnsigned(other.ClientTx(t, amount25USD, nil))
	require.NoError(t, err)
	s.chain.Land(t, other.FeePayer.CoSign(pay))
	return pay, other.FeePayer.TransactionID(pay)
}

// With no key on record, a former fee payer's transaction gets a clear refusal, never a budget: anyone can pay a fee, so
// nothing would show this enclave ever handled it. This is what a crash just before a rotation strands.
func TestRecoverOfAFormerFeePayerIssuesNothing(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	_, id := s.formerPayment(t)
	got := s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, s.now()), nil)
	require.Equal(t, http.StatusConflict, got.status)
	require.Contains(t, got.body["error"], "former fee payer")
	require.Empty(t, s.fake.Generated())
}

// A key sold before a change of fee payer stays recoverable, since the secret behind it did not change: the same key, the same
// row, and no second budget however often it is asked for.
func TestRecoverSurvivesAChangeOfFeePayer(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	pay, id := s.formerPayment(t)
	key := s.settler.VirtualKey(pay.Digest())
	_, err := s.gw.Issue(t.Context(), sales.AliasFor(pay.Digest()), usage.KeyLimits{MaxBudgetUSD: 25, RPMLimit: 60, Key: key})
	require.NoError(t, err)
	before := len(s.fake.Generated())
	for range 2 {
		got := s.recoverNow(t, id)
		require.Equal(t, http.StatusOK, got.status, "%v", got.body)
		require.Equal(t, key, got.body["key"])
		require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12)
	}
	require.Len(t, s.fake.Generated(), before)
}

// A row that is not this secret's derivation, as after a change of the KMS path, is not handed back, and no budget is issued.
func TestRecoverOfAFormerFeePayerFailsClosedOnAnotherSecret(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	pay, id := s.formerPayment(t)
	limits := usage.KeyLimits{MaxBudgetUSD: 25, RPMLimit: 60, Key: "sk-another-secret"}
	_, err := s.gw.Issue(t.Context(), sales.AliasFor(pay.Digest()), limits)
	require.NoError(t, err)
	before := len(s.fake.Generated())
	got := s.recoverNow(t, id)
	require.Equal(t, http.StatusConflict, got.status)
	require.NotContains(t, got.body, "key")
	require.Len(t, s.fake.Generated(), before)
}

// A top-up marked before a change of fee payer finishes once.
func TestRecoverFinishesAFormerFeePayersTopUpOnce(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	key, _, _ := s.firstKey(t)
	target, err := s.gw.LookupKey(t.Context(), key)
	require.NoError(t, err)
	pay, id := s.formerPayment(t)
	marker := usage.KeyLimits{RPMLimit: 1, Blocked: true, Key: s.settler.VirtualKey(pay.Digest()),
		Metadata: map[string]any{"x402_kind": "top-up", "x402_target": target.Token}}
	_, err = s.gw.Issue(t.Context(), sales.AliasFor(pay.Digest()), marker)
	require.NoError(t, err)
	for range 2 {
		got := s.recoverNow(t, id)
		require.Equal(t, http.StatusOK, got.status, "%v", got.body)
		require.NotContains(t, got.body, "key")
	}
	info, err := s.gw.LookupKey(t.Context(), key)
	require.NoError(t, err)
	require.InEpsilon(t, target.MaxBudgetUSD+25, info.MaxBudgetUSD, 1e-12)
}

// A row under another alias after the issuance is someone else's: no key goes back, whatever the upsert said.
func TestIssueRefusesARowUnderAnotherAlias(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	id, pay := s.landedPayment(t)
	_, err := s.gw.Issue(t.Context(), "another-alias", usage.KeyLimits{Key: s.settler.VirtualKey(pay.Digest())})
	require.NoError(t, err)
	got := s.recoverNow(t, id)
	require.Equal(t, http.StatusBadGateway, got.status, "%v", got.body)
	require.NotContains(t, got.body, "key")
}

// A marker committed just after the alias check wins the upsert: the blocked row gets no key out, and the next recovery
// finds the marker and credits the top-up it stands for, once.
func TestLateMarkerWinsOverARecoveryIssuance(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	target, _, _ := s.firstKey(t)
	id, pay := s.landedPayment(t)
	_, err := s.gw.Issue(t.Context(), sales.AliasFor(pay.Digest()), usage.KeyLimits{Key: s.settler.VirtualKey(pay.Digest()), Blocked: true,
		Metadata: map[string]any{"x402_kind": "top-up", "x402_target": usage.TokenHash(target)}})
	require.NoError(t, err)
	s.fake.RaceNextIssue()
	got := s.recoverNow(t, id)
	require.Equal(t, http.StatusBadGateway, got.status, "%v", got.body)
	require.NotContains(t, got.body, "key")
	got = s.recoverNow(t, id)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.NotContains(t, got.body, "key")
	info, err := s.gw.LookupKey(t.Context(), target)
	require.NoError(t, err)
	require.InEpsilon(t, 50.0, info.MaxBudgetUSD, 1e-12)
}

// The other order: a usable key committed just after the alias check keeps the row, so the top-up does not credit its target
// as well, or one payment would pay twice.
func TestTopUpDoesNotCreditWhenAKeyWonTheUpsert(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	target, _, _ := s.firstKey(t)
	raw := s.world.ClientTx(t, amount25USD, nil)
	pay, err := s.world.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	headers := paymentHeader(t, s.challenge(t), raw)
	headers["Authorization"] = "Bearer " + target
	s.chain.SetOnSend(func() {
		s.fake.RaceNextIssue()
		limits := usage.KeyLimits{Key: s.settler.VirtualKey(pay.Digest()), MaxBudgetUSD: 25}
		_, issueErr := s.gw.Issue(context.Background(), sales.AliasFor(pay.Digest()), limits)
		if issueErr == nil {
			s.fake.RaceNextIssue()
		}
	})
	got := s.post(t, buyPath, body25, headers)
	require.Equal(t, http.StatusBadGateway, got.status, "%v", got.body)
	info, err := s.gw.LookupKey(t.Context(), target)
	require.NoError(t, err)
	require.InEpsilon(t, 25.0, info.MaxBudgetUSD, 1e-12, "the target is not credited too")
}

// A reply lost after the row landed: the retry through recovery finds the row and hands back that key, one row, one budget.
func TestLostIssueReplyLeavesOneBudget(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	s.fake.LoseNextMintReply()
	got, _ := s.buy(t, "")
	require.Equal(t, http.StatusBadGateway, got.status, "%v", got.body)
	require.True(t, settlementOf(t, got).Success)
	tx, err := solana.TransactionFromBytes(s.chain.Sent()[0])
	require.NoError(t, err)
	got = s.recoverNow(t, tx.Signatures[0])
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.NotEmpty(t, got.body["key"])
	require.InEpsilon(t, 25.0, got.body["max_budget_usd"], 1e-12)
	require.Len(t, s.fake.Generated(), 1)
}

// A token hash is a handle anyone with the admin view holds; only the key itself may top up.
func TestTopUpRefusesAHashAsBearer(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	key, _, _ := s.firstKey(t)
	got := s.post(t, buyPath, body25, map[string]string{"Authorization": "Bearer " + usage.TokenHash(key)})
	require.Equal(t, http.StatusUnauthorized, got.status)
}

// An operator's revocation is a block under the live alias: a proof must not turn it into a fresh key.
func TestRecoverKeepsARevokedKeyRevoked(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	key, id, _ := s.firstKey(t)
	s.fake.Block(key)
	got := s.recoverNow(t, id)
	require.Equal(t, http.StatusConflict, got.status)
	require.NotContains(t, got.body, "key")
	require.Len(t, s.fake.Generated(), 1)
}

// A missing key on an old payment is not a crash: a lost database or a deleted key must not reissue the whole history.
func TestRecoverIssuesOnlyWithinTheWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		blockTime func() int64
		want      int
	}{
		{"recent", func() int64 { return time.Now().Add(-time.Hour).Unix() }, http.StatusOK},
		{"just inside", func() int64 { return time.Now().Add(-6 * 24 * time.Hour).Unix() }, http.StatusOK},
		{"old", func() int64 { return time.Now().Add(-8 * 24 * time.Hour).Unix() }, http.StatusConflict},
		{"too far back to be real", func() int64 { return 1 }, http.StatusConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newShop(t, &x402test.Chain{BlockTime: tc.blockTime()})
			id := s.landed(t)
			got := s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, s.now()), nil)
			require.Equal(t, tc.want, got.status, "%v", got.body)
		})
	}
}

// A node that reports no block time cannot show the payment is recent.
func TestRecoverIssuesNothingWithoutABlockTime(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	s := newShop(t, chain)
	chain.BlockTime = 0
	id := s.landed(t)
	require.Equal(t, http.StatusConflict, s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, s.now()), nil).status)
	require.Empty(t, s.fake.Generated())
}

// Every gateway failure on the recovery path says the payment stands and names the way back, never a key and never a 200.
func TestRecoverGatewayFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		path  string
		setup func(t *testing.T, s *shop) solana.Signature
	}{
		{"lookup fails", "/key/list", func(t *testing.T, s *shop) solana.Signature {
			t.Helper()
			return s.landed(t)
		}},
		{"issue fails", "/key/generate", func(t *testing.T, s *shop) solana.Signature {
			t.Helper()
			return s.landed(t)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newShop(t, nil)
			id := tc.setup(t, s)
			s.fake.SetFail(tc.path, true)
			got := s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, s.now()), nil)
			require.Equal(t, http.StatusBadGateway, got.status, "%v", got.body)
			require.NotContains(t, got.body, "key")
			require.True(t, settlementOf(t, got).Success)
		})
	}
}

func TestRecoverRefuses(t *testing.T) {
	t.Parallel()
	stranger := x402test.NewKey(t)
	now := time.Now()
	tests := []struct {
		name   string
		body   func(s *shop, id solana.Signature) string
		status int
	}{
		{"not the payer", func(_ *shop, id solana.Signature) string { return recoverBody(t, stranger, id, now) }, http.StatusUnauthorized},
		{"stale timestamp", func(s *shop, id solana.Signature) string {
			return recoverBody(t, s.world.Payer, id, now.Add(-10*time.Minute))
		}, http.StatusBadRequest},
		{"future timestamp", func(s *shop, id solana.Signature) string {
			return recoverBody(t, s.world.Payer, id, now.Add(10*time.Minute))
		}, http.StatusBadRequest},
		{"unknown transaction", func(s *shop, _ solana.Signature) string {
			return recoverBody(t, s.world.Payer, solana.Signature{1}, now)
		}, http.StatusNotFound},
		{"signature over another transaction", func(s *shop, id solana.Signature) string {
			sig := ed25519.Sign(s.world.Payer, x402.RecoverMessage(solana.Signature{1}, now.Unix()))
			return fmt.Sprintf(`{"transaction":%q,"payer":%q,"timestamp":%d,"signature":%q}`, id, x402test.Public(s.world.Payer),
				now.Unix(), solana.SignatureFromBytes(sig))
		}, http.StatusUnauthorized},
		{"bad transaction encoding", func(*shop, solana.Signature) string {
			return fmt.Sprintf(`{"transaction":"!!","payer":"!!","timestamp":%d,"signature":"!!"}`, now.Unix())
		}, http.StatusBadRequest},
		{"unknown field", func(*shop, solana.Signature) string { return `{"transaction":"a","extra":1}` }, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newShop(t, nil)
			id := s.landed(t)
			got := s.post(t, recoverPath, tc.body(s, id), nil)
			require.Equal(t, tc.status, got.status, "%v", got.body)
			require.NotContains(t, got.body, "key")
			require.Empty(t, s.fake.Generated())
		})
	}
}

// A signed recovery message works once, even though the key it returns is always the same.
func TestRecoverRefusesAReplayedProof(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	id := s.landed(t)
	body := recoverBody(t, s.world.Payer, id, time.Now())
	require.Equal(t, http.StatusOK, s.post(t, recoverPath, body, nil).status)
	got := s.post(t, recoverPath, body, nil)
	require.Equal(t, http.StatusConflict, got.status)
	require.NotContains(t, got.body, "key")
}

func TestRecoverMapsChainFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		chain  *x402test.Chain
		status int
	}{
		{"a lone primary is not enough", &x402test.Chain{ConfirmerBlind: true}, http.StatusConflict},
		{"a failed transaction paid nothing", &x402test.Chain{FailOnChain: "Boom"}, http.StatusConflict},
		{"the second host is down", &x402test.Chain{ConfirmerDown: true}, http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newShop(t, tc.chain)
			id := s.landed(t)
			got := s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, time.Now()), nil)
			require.Equal(t, tc.status, got.status)
			require.Empty(t, s.fake.Generated())
		})
	}
}

func TestRecoverAnswers429PastItsBucket(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	id := s.landed(t)
	s.settler.RecoverLimiter.SetBurst(0)
	require.Equal(t, http.StatusTooManyRequests, s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, time.Now()), nil).status)
}

// While a buy holds a transaction, a recovery of it is told to come back, and its proof stays good.
func TestRecoverAnswers409WhileTheTransactionIsHeld(t *testing.T) {
	t.Parallel()
	release, sending := make(chan struct{}), make(chan struct{})
	once := sync.OnceFunc(func() { close(release) })
	chain := &x402test.Chain{OnSend: func() {
		close(sending)
		<-release
	}}
	s := newShop(t, chain)
	t.Cleanup(once)
	raw := s.world.ClientTx(t, amount25USD, nil)
	pay, err := s.world.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	id := s.world.FeePayer.TransactionID(pay)
	headers := paymentHeader(t, s.challenge(t), raw)
	first := make(chan int, 1)
	go func() {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPost, s.srv.URL+buyPath, strings.NewReader(body25))
		if reqErr != nil {
			first <- 0
			return
		}
		req.Header.Set(x402.HeaderSignature, headers[x402.HeaderSignature])
		resp, doErr := s.srv.Client().Do(req)
		if doErr != nil {
			first <- 0
			return
		}
		_ = resp.Body.Close()
		first <- resp.StatusCode
	}()
	<-sending
	chain.Land(t, s.world.FeePayer.CoSign(pay))
	got := s.post(t, recoverPath, recoverBody(t, s.world.Payer, id, s.now()), nil)
	require.Equal(t, http.StatusConflict, got.status)
	require.NotContains(t, got.body, "key")
	once()
	require.Equal(t, http.StatusOK, <-first)
}

// A settlement whose credit check cannot reach the gateway fails closed, before any simulation.
func TestBuyFailsClosedWhenTheAliasLookupFails(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	s.fake.SetFail("/key/list", true)
	got := s.post(t, buyPath, body25, paymentHeader(t, s.challenge(t), s.world.ClientTx(t, amount25USD, nil)))
	require.Equal(t, http.StatusServiceUnavailable, got.status)
	require.Empty(t, s.chain.Simulated())
}

// A well-formed header carrying undecodable transaction bytes is malformed, not a failed payment.
func TestBuyAnswers400ForATransactionItCannotDecode(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	got := s.post(t, buyPath, body25, paymentHeader(t, s.challenge(t), []byte{1, 2, 3}))
	require.Equal(t, http.StatusBadRequest, got.status)
	require.Empty(t, got.headers.Get(x402.HeaderRequired))
}

func TestTopUpMarkerFailureIsSettledNotCredited(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	key, _, _ := s.firstKey(t)
	s.fake.SetFail("/key/generate", true)
	got, _ := s.buy(t, key)
	require.Equal(t, http.StatusBadGateway, got.status)
	require.True(t, settlementOf(t, got).Success)
}

// A top-up that crashed after settling: the marker is durable, so recovery credits it exactly once and never mints a key.
func TestRecoverCompletesATopUpOnce(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	first, _ := s.buy(t, "")
	key, ok := first.body["key"].(string)
	require.True(t, ok)
	s.fake.SetFail("/key/update", true)
	got, _ := s.buy(t, key)
	require.Equal(t, http.StatusBadGateway, got.status)
	require.True(t, settlementOf(t, got).Success)
	s.fake.SetFail("/key/update", false)
	sent := s.chain.Sent()
	tx, err := solana.TransactionFromBytes(sent[len(sent)-1])
	require.NoError(t, err)
	generated := len(s.fake.Generated())

	got = s.post(t, recoverPath, recoverBody(t, s.world.Payer, tx.Signatures[0], time.Now()), nil)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	require.NotContains(t, got.body, "key", "the payer of a top-up never receives the key it topped up")
	require.NotContains(t, got.body, "max_budget_usd", "nor the holder's budget")
	require.InEpsilon(t, 25.0, got.body["credited_usd"], 1e-12)

	got = s.post(t, recoverPath, recoverBody(t, s.world.Payer, tx.Signatures[0], time.Now().Add(time.Second)), nil)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	info, err := s.gw.LookupKey(t.Context(), key)
	require.NoError(t, err)
	require.InEpsilon(t, 50.0, info.MaxBudgetUSD, 1e-12, "the second recovery credits nothing")
	require.Len(t, s.fake.Generated(), generated, "no key was minted")
}

// A top-up that completed but whose reply was lost: recovery must not double-credit.
func TestRecoverDoesNotDoubleCreditAFinishedTopUp(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	first, _ := s.buy(t, "")
	key, ok := first.body["key"].(string)
	require.True(t, ok)
	got, _ := s.buy(t, key)
	require.Equal(t, http.StatusOK, got.status)
	sent := s.chain.Sent()
	tx, err := solana.TransactionFromBytes(sent[len(sent)-1])
	require.NoError(t, err)
	got = s.post(t, recoverPath, recoverBody(t, s.world.Payer, tx.Signatures[0], time.Now()), nil)
	require.Equal(t, http.StatusOK, got.status, "%v", got.body)
	info, err := s.gw.LookupKey(t.Context(), key)
	require.NoError(t, err)
	require.InEpsilon(t, 50.0, info.MaxBudgetUSD, 1e-12)
}

// A top-up whose target key has gone cannot prove it was or was not credited, so it fails closed.
func TestRecoverFailsClosedWhenTheTopUpTargetIsGone(t *testing.T) {
	t.Parallel()
	s := newShop(t, nil)
	first, _ := s.buy(t, "")
	key, ok := first.body["key"].(string)
	require.True(t, ok)
	got, _ := s.buy(t, key)
	require.Equal(t, http.StatusOK, got.status)
	sent := s.chain.Sent()
	tx, err := solana.TransactionFromBytes(sent[len(sent)-1])
	require.NoError(t, err)
	s.fake.Delete(key)
	got = s.post(t, recoverPath, recoverBody(t, s.world.Payer, tx.Signatures[0], time.Now()), nil)
	require.Equal(t, http.StatusConflict, got.status)
}

// Keys never reach a log line: not on any flow, and not when the gateway fails mid-flow.
func TestSalesNeverLogKeys(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	s := newLoggedShop(t, nil, slog.New(slog.NewTextHandler(&lockedWriter{w: &logs}, nil)))
	key, id, _ := s.firstKey(t)

	_, _ = s.buy(t, key)
	require.Equal(t, http.StatusOK, s.recoverNow(t, id).status)
	s.fake.SetFail("/key/info", true)
	require.Equal(t, http.StatusBadGateway, s.post(t, buyPath, body25, map[string]string{"Authorization": "Bearer " + key}).status)
	s.fake.SetFail("/key/info", false)
	for _, path := range []string{"/key/generate", "/key/update", "/key/list"} {
		s.fake.SetFail(path, true)
		_, _ = s.buy(t, key)
		_ = s.recoverNow(t, s.landed(t))
		s.fake.SetFail(path, false)
	}

	text := logs.String()
	require.NotContains(t, text, key)
	require.NotContains(t, text, "sk-")
	require.Contains(t, text, "x402: issued")
	require.Contains(t, text, "x402: topped up")
	require.Contains(t, text, "x402: key recovered")
	require.Contains(t, text, "x402: settled but not credited")
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
