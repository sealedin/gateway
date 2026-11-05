package x402_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/solanarpc"
	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402test"
)

func newSettler(t *testing.T, chain *x402test.Chain) (*x402.Settler, *x402test.World) {
	t.Helper()
	w := x402test.NewWorld(t)
	primary, confirmer := chain.Clients(t)
	terms := x402.Terms{Network: "solana:test", Treasury: w.Treasury, Mint: w.Policy.Mint}
	settler, err := x402.NewSettler(terms, w.FeePayer, w.Keys, primary, confirmer, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	settler.Poll = time.Millisecond
	settler.Wait = 200 * time.Millisecond
	return settler, w
}

func noCredit(context.Context, string) (bool, error) { return false, nil }

// payment is a compliant payment as the wire carries it, with the id it would get.
func payment(t *testing.T, settler *x402.Settler, w *x402test.World) (x402.Payload, []byte, solana.Signature) {
	t.Helper()
	raw := w.ClientTx(t, amount, nil)
	pay, err := w.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	payload := x402.Payload{X402Version: x402.Version, Accepted: settler.Challenge(t.Context(), x402.Resource{}, amount, "").Accepts[0]}
	return payload, raw, w.FeePayer.TransactionID(pay)
}

func TestSettleSettles(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	settler, w := newSettler(t, chain)
	payload, raw, id := payment(t, settler, w)

	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err)
	settled.Release()

	require.Equal(t, id, settled.ID)
	require.Equal(t, [][]byte{raw}, chain.Simulated(), "simulation sees the client's bytes, no sponsor signature yet")
	sent := chain.Sent()
	require.Len(t, sent, 1)
	tx, err := solana.TransactionFromBytes(sent[0])
	require.NoError(t, err)
	require.Equal(t, id, tx.Signatures[0])
	require.True(t, bytes.Equal(raw[65:], sent[0][65:]), "only the sponsor's signature changes")
	require.Equal(t, settled.FeeLamports, settler.Meter.Spent())
}

// The status of each way a payment can fail, the fee booked, and whether the id may be told.
func TestSettleFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		chain     *x402test.Chain
		reason    string
		left      bool
		wantSpent bool
	}{
		{"simulation fails", &x402test.Chain{SimulationFailure: `"BlockhashNotFound"`}, x402.ReasonSimulationFailed, false, false},
		{"client lacks funds", &x402test.Chain{SimulationFailure: `{"InstructionError":[2,{"Custom":1}]}`},
			x402.ReasonInsufficientFunds, false, false},
		{"another instruction's custom error is no lack of funds", &x402test.Chain{SimulationFailure: `{"InstructionError":[3,{"Custom":1}]}`},
			x402.ReasonSimulationFailed, false, false},
		{"lands failed", &x402test.Chain{FailOnChain: "InstructionError"}, x402.ReasonTransactionFailed, true, true},
		{"never lands", &x402test.Chain{Dropped: true}, x402.ReasonPending, true, true},
		{"send outcome unknown and never lands", &x402test.Chain{SendTransportFail: true, Dropped: true}, x402.ReasonPending, true, true},
		{"independent host does not confirm", &x402test.Chain{ConfirmerBlind: true}, x402.ReasonPending, true, true},
		{"independent host is down", &x402test.Chain{ConfirmerDown: true}, x402.ReasonPending, true, true},
		{"independent host reports a failure", &x402test.Chain{ConfirmerFailure: "Boom"}, x402.ReasonTransactionFailed, true, true},
		{"a lying primary alone confirms nothing", &x402test.Chain{Dropped: true, PrimaryLiesAfter: true}, x402.ReasonPending, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			settler, w := newSettler(t, tc.chain)
			payload, raw, id := payment(t, settler, w)
			_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
			require.Equal(t, tc.reason, x402.Reason(err), "err: %v", err)
			rejection, ok := errors.AsType[*x402.RejectionError](err)
			require.True(t, ok)
			if tc.left {
				require.Equal(t, id.String(), rejection.Transaction, "the bytes left, so the id is public")
			} else {
				require.Empty(t, rejection.Transaction, "the id is the sponsor's signature and nothing left")
				require.Empty(t, tc.chain.Sent())
			}
			if tc.wantSpent {
				require.Positive(t, settler.Meter.Spent(), "a transaction that left is paid for")
			} else {
				require.Zero(t, settler.Meter.Spent())
			}
		})
	}
}

// An ambiguous send is watched: if it lands the payment stands, and its fee stays booked either way.
func TestSettleWatchesASendOfUnknownOutcome(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{SendTransportFail: true}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err)
	settled.Release()
	require.Equal(t, settled.FeeLamports, settler.Meter.Spent())
	_, err = settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Equal(t, x402.ReasonDuplicate, x402.Reason(err))
}

// A status that stays processed for a while is no confirmation yet, and no failure either.
func TestSettleWaitsThroughProcessed(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{Processed: 3}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	// Reads before the send find nothing, so all three processed reads land on the watch.
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err)
	settled.Release()
	require.GreaterOrEqual(t, chain.Calls(solanarpc.MethodSignatureStatuses), 5)
}

// The critical regression: a request that collides with one in flight never learns the sponsor's signature, or it could
// paste it in and broadcast, past simulation and past the fee meter.
func TestSettleNeverDisclosesTheSignatureOfAnInFlightTransaction(t *testing.T) {
	t.Parallel()
	release, entered := make(chan struct{}), make(chan struct{})
	chain := &x402test.Chain{OnSimulate: func() {
		close(entered)
		<-release
	}}
	settler, w := newSettler(t, chain)
	payload, raw, id := payment(t, settler, w)
	done := make(chan error, 1)
	go func() {
		settled, err := settler.Settle(context.Background(), payload, raw, amount, noCredit)
		if err == nil {
			settled.Release()
		}
		done <- err
	}()
	<-entered
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	close(release)
	require.Equal(t, x402.ReasonDuplicate, x402.Reason(err))
	rejection, ok := errors.AsType[*x402.RejectionError](err)
	require.True(t, ok)
	require.Empty(t, rejection.Transaction)
	require.NotContains(t, err.Error(), id.String())
	require.NoError(t, <-done)
}

// A host handed the bytes and the id could broadcast past simulation, so a failing simulation must never see a status call.
func TestSettleKeepsTheSignatureFromTheHostUntilSimulationPasses(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{SimulationFailure: `"BlockhashNotFound"`}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Equal(t, x402.ReasonSimulationFailed, x402.Reason(err))
	require.Zero(t, chain.Calls(solanarpc.MethodSignatureStatuses))
}

func TestSettleRefusedSendRefundsAndReleases(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{SendRefused: true}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Error(t, err)
	require.Empty(t, x402.Reason(err), "a refused send is the node's failure, not the payment's")
	require.Zero(t, settler.Meter.Spent())
	_, err = settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Empty(t, x402.Reason(err), "still the node's failure, not a duplicate: the bytes never left")
}

func TestSettleNamesAnUnfundedFeePayer(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{`"InsufficientFundsForFee"`, `"AccountNotFound"`} {
		settler, w := newSettler(t, &x402test.Chain{SimulationFailure: failure})
		payload, raw, _ := payment(t, settler, w)
		_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
		require.ErrorIs(t, err, x402.ErrFeePayerUnfunded)
	}
}

func TestSettleStopsAtTheFeeCeiling(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	settler.Meter.Ceiling = 1
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.ErrorIs(t, err, x402.ErrFeeCeiling)
	require.Empty(t, chain.Sent(), "nothing is sent past the ceiling")
	settler.Meter.Ceiling = x402.DailyFeeCeilingLamports
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err, "the ceiling sent nothing, so the bytes stay retryable")
	settled.Release()
}

// Before sending, a canceled request stops the settlement: nothing was committed yet.
func TestSettleStopsWhenTheRequestDiesBeforeSending(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := settler.Settle(ctx, payload, raw, amount, noCredit)
	require.Error(t, err)
	require.Empty(t, chain.Sent())
}

// A client hanging up as the transaction goes out must not abandon it: it is sent and seen through.
func TestSettleOutlivesTheRequestOnceSending(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	chain := &x402test.Chain{OnSend: cancel}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	settled, err := settler.Settle(ctx, payload, raw, amount, noCredit)
	require.NoError(t, err)
	settled.Release()
	require.Len(t, chain.Sent(), 1)
}

// A payer whose transaction landed failed cost the fee payer a fee; a second try from that wallet is refused up front.
func TestSettleBarsAPayerWhoseTransactionFailed(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{FailOnChain: "Boom"}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Equal(t, x402.ReasonTransactionFailed, x402.Reason(err))
	spent := settler.Meter.Spent()
	_, err = settler.Settle(t.Context(), payload, w.ClientTx(t, amount, nil), amount, noCredit)
	require.Equal(t, x402.ReasonPayerBarred, x402.Reason(err))
	require.Equal(t, spent, settler.Meter.Spent())
	require.Len(t, chain.Sent(), 1)
}

// The source is metered too: another wallet delegated on the same token account does not get a second free failure.
func TestSettleBarsTheSourceAccountToo(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{FailOnChain: "Boom"}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	pay, err := w.Policy.VerifyUnsigned(raw)
	require.NoError(t, err)
	_, err = settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Equal(t, x402.ReasonTransactionFailed, x402.Reason(err))
	w.Payer = x402test.NewKey(t)
	delegate := w.ClientTx(t, amount, func(m *solana.Message) {
		m.AccountKeys[m.Instructions[2].Accounts[0]] = pay.Source
	})
	_, err = settler.Settle(t.Context(), payload, delegate, amount, noCredit)
	require.Equal(t, x402.ReasonPayerBarred, x402.Reason(err))
}

func TestSettleRefusesWhatTheCallerOrTheChainAlreadyKnows(t *testing.T) {
	t.Parallel()
	t.Run("the caller holds a credit", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		payload, raw, id := payment(t, settler, w)
		pay, err := w.Policy.VerifyUnsigned(raw)
		require.NoError(t, err)
		credited := func(_ context.Context, got string) (bool, error) { return got == pay.Digest(), nil }
		_, err = settler.Settle(t.Context(), payload, raw, amount, credited)
		require.Equal(t, x402.ReasonDuplicate, x402.Reason(err))
		rejection, ok := errors.AsType[*x402.RejectionError](err)
		require.True(t, ok)
		require.Equal(t, id.String(), rejection.Transaction, "a credit on record means the transaction is public")
		require.Empty(t, chain.Simulated())
	})
	t.Run("the credit check fails closed", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		payload, raw, _ := payment(t, settler, w)
		boom := errors.New("gateway down")
		_, err := settler.Settle(t.Context(), payload, raw, amount, func(context.Context, string) (bool, error) {
			return false, boom
		})
		require.ErrorIs(t, err, boom)
		require.Empty(t, chain.Simulated())
	})
	t.Run("the chain knows it", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		payload, raw, id := payment(t, settler, w)
		pay, err := w.Policy.VerifyUnsigned(raw)
		require.NoError(t, err)
		chain.Land(t, w.FeePayer.CoSign(pay))
		_, err = settler.Settle(t.Context(), payload, raw, amount, noCredit)
		require.Equal(t, x402.ReasonDuplicate, x402.Reason(err))
		rejection, ok := errors.AsType[*x402.RejectionError](err)
		require.True(t, ok)
		require.Equal(t, id.String(), rejection.Transaction, "already public")
		require.Empty(t, chain.Sent())
	})
	t.Run("the status check fails closed", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{StatusDown: true}
		settler, w := newSettler(t, chain)
		payload, raw, _ := payment(t, settler, w)
		_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
		require.Error(t, err)
		require.Empty(t, x402.Reason(err))
		require.Empty(t, chain.Sent())
	})
}

func TestDailyCeilingResetsAtMidnightUTC(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 4, 23, 59, 0, 0, time.UTC)
	meter := &x402.FeeMeter{Ceiling: 100, FailureCeiling: 100, Now: func() time.Time { return now }}
	day, ok := meter.Reserve(100, false)
	require.True(t, ok)
	_, ok = meter.Reserve(1, false)
	require.False(t, ok)
	meter.Refund(40, day)
	_, ok = meter.Reserve(40, false)
	require.True(t, ok)
	now = now.Add(2 * time.Minute)
	_, ok = meter.Reserve(100, false)
	require.True(t, ok)
	require.Equal(t, uint64(100), meter.Spent())
	meter.Refund(100, day)
	meter.Resolved(100, day)
	require.Equal(t, uint64(100), meter.Spent(), "yesterday's refund does not erase today's bookings")
	require.Equal(t, uint64(100), meter.Unresolved(), "nor does yesterday's resolution")
}

// Fees that bought nothing stop at the failure ceiling; confirmed ones free it, and known buyers go on to the full ceiling.
func TestFailureCeilingKeepsTheBudgetForSuccesses(t *testing.T) {
	t.Parallel()
	meter := &x402.FeeMeter{Ceiling: 100, FailureCeiling: 20, Now: time.Now}
	day, ok := meter.Reserve(20, false)
	require.True(t, ok)
	_, ok = meter.Reserve(1, false)
	require.False(t, ok, "griefing stops here, with 80 of the budget left")
	_, ok = meter.Reserve(30, true)
	require.True(t, ok, "a payer with a settled purchase behind it still buys")
	meter.Resolved(20, day)
	meter.Resolved(30, day)
	_, ok = meter.Reserve(20, false)
	require.True(t, ok, "a confirmed payment frees what it reserved")
	_, ok = meter.Reserve(60, true)
	require.False(t, ok, "nobody passes the ceiling")
}

// One unresolved transaction at a time per wallet and per source, each on its own, proven or not.
func TestSettleHoldsOneUnresolvedTransactionPerWalletAndSource(t *testing.T) {
	t.Parallel()
	otherSource := x402test.Public(x402test.NewKey(t))
	tests := []struct {
		name   string
		second func(w *x402test.World, source solana.PublicKey) []byte
	}{
		{"the same wallet from another source", func(w *x402test.World, _ solana.PublicKey) []byte {
			return w.ClientTx(t, amount, func(m *solana.Message) { m.AccountKeys[m.Instructions[2].Accounts[0]] = otherSource })
		}},
		{"another wallet on the same source", func(w *x402test.World, source solana.PublicKey) []byte {
			w.Payer = x402test.NewKey(t)
			return w.ClientTx(t, amount, func(m *solana.Message) { m.AccountKeys[m.Instructions[2].Accounts[0]] = source })
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			settler, w := newSettler(t, &x402test.Chain{Dropped: true})
			settler.ReconcileAfter = time.Hour
			payload, raw, _ := payment(t, settler, w)
			pay, err := w.Policy.VerifyUnsigned(raw)
			require.NoError(t, err)
			_, err = settler.Settle(t.Context(), payload, raw, amount, noCredit)
			require.Equal(t, x402.ReasonPending, x402.Reason(err))
			spent := settler.Meter.Spent()
			_, err = settler.Settle(t.Context(), payload, tc.second(w, pay.Source), amount, noCredit)
			require.Equal(t, x402.ReasonPayerUnresolved, x402.Reason(err))
			require.Equal(t, spent, settler.Meter.Spent(), "nothing more is booked")
		})
	}
}

// A pending transaction is looked at again, and what the chain then says decides the books. Each case reads the meter before
// anything else books a fee.
func TestReconcileSettlesTheBooks(t *testing.T) {
	t.Parallel()
	const after = 300 * time.Millisecond
	settle := func(t *testing.T, chain *x402test.Chain) (*x402.Settler, *x402test.World, x402.Payload, x402.Payment, uint64) {
		t.Helper()
		settler, w := newSettler(t, chain)
		settler.ReconcileAfter = after
		payload, raw, _ := payment(t, settler, w)
		pay, err := w.Policy.VerifyUnsigned(raw)
		require.NoError(t, err)
		_, err = settler.Settle(t.Context(), payload, raw, amount, noCredit)
		require.Equal(t, x402.ReasonPending, x402.Reason(err))
		require.Positive(t, settler.Meter.Spent())
		return settler, w, payload, pay, settler.Meter.Spent()
	}
	// reSettles requires the wallet free: a second payment goes all the way through, or is at least not held as unresolved.
	walletFree := func(t *testing.T, settler *x402.Settler, w *x402test.World, payload x402.Payload) {
		t.Helper()
		_, err := settler.Settle(t.Context(), payload, w.ClientTx(t, amount, nil), amount, noCredit)
		require.NotEqual(t, x402.ReasonPayerUnresolved, x402.Reason(err), "err: %v", err)
	}
	t.Run("dropped on both hosts gets its fee back and frees the wallet", func(t *testing.T) {
		t.Parallel()
		settler, w, payload, _, _ := settle(t, &x402test.Chain{Dropped: true})
		require.Eventually(t, func() bool { return settler.Meter.Spent() == 0 }, 5*time.Second, time.Millisecond)
		require.Zero(t, settler.Meter.Unresolved())
		walletFree(t, settler, w, payload)
	})
	for name, chain := range map[string]*x402test.Chain{
		"the primary alone knowing nothing keeps the fee": {Dropped: true, ConfirmerClaims: true},
		"a second host that cannot answer keeps the fee":  {Dropped: true, ConfirmerDown: true},
		"still only processed keeps the fee":              {ConfirmerBlind: true, Processed: 1 << 30},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			settler, w, payload, _, spent := settle(t, chain)
			time.Sleep(3 * after)
			require.Equal(t, spent, settler.Meter.Spent())
			require.Equal(t, spent, settler.Meter.Unresolved(), "still not known to have bought anything")
			walletFree(t, settler, w, payload)
		})
	}
	t.Run("landed late resolves: the fee stays spent, the fifth is free", func(t *testing.T) {
		t.Parallel()
		settler, w, payload, _, spent := settle(t, &x402test.Chain{ConfirmerBlind: true})
		require.Eventually(t, func() bool { return settler.Meter.Unresolved() == 0 }, 5*time.Second, time.Millisecond)
		require.Equal(t, spent, settler.Meter.Spent(), "that fee was paid")
		walletFree(t, settler, w, payload)
	})
	t.Run("landed failed bars the wallet and the source and keeps the fee", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{ConfirmerBlind: true, Dropped: true}
		settler, w, payload, pay, spent := settle(t, chain)
		chain.SetFailOnChain("Boom")
		chain.Land(t, w.FeePayer.CoSign(pay))
		next := w.ClientTx(t, amount, nil)
		require.Eventually(t, func() bool {
			_, err := settler.Settle(t.Context(), payload, next, amount, noCredit)
			return x402.Reason(err) == x402.ReasonPayerBarred
		}, 5*time.Second, 5*time.Millisecond)
		require.Equal(t, spent, settler.Meter.Spent())
		anotherSource := x402test.Public(x402test.NewKey(t))
		moved := w.ClientTx(t, amount, func(m *solana.Message) { m.AccountKeys[m.Instructions[2].Accounts[0]] = anotherSource })
		_, err := settler.Settle(t.Context(), payload, moved, amount, noCredit)
		require.Equal(t, x402.ReasonPayerBarred, x402.Reason(err), "the wallet is barred on another source")
		w.Payer = x402test.NewKey(t)
		delegate := w.ClientTx(t, amount, func(m *solana.Message) { m.AccountKeys[m.Instructions[2].Accounts[0]] = pay.Source })
		_, err = settler.Settle(t.Context(), payload, delegate, amount, noCredit)
		require.Equal(t, x402.ReasonPayerBarred, x402.Reason(err), "the source is barred under another wallet")
		_, err = settler.Settle(t.Context(), payload, w.ClientTx(t, amount, nil), amount, noCredit)
		require.NotEqual(t, x402.ReasonPayerBarred, x402.Reason(err), "an unrelated wallet and source are not")
	})
	t.Run("a primary that cannot answer keeps the fee and frees the wallet", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{Dropped: true}
		settler, w, payload, _, spent := settle(t, chain)
		chain.SetStatusDown(true)
		time.Sleep(3 * after)
		chain.SetStatusDown(false)
		require.Equal(t, spent, settler.Meter.Spent())
		walletFree(t, settler, w, payload)
	})
}

// A failed status check undoes the reservation: the fee is not booked and the wallet is free.
func TestSettleUndoesTheReservationWhenTheStatusCheckFails(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{StatusDown: true}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Error(t, err)
	require.Zero(t, settler.Meter.Spent())
	chain.SetStatusDown(false)
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err, "the same bytes settle once the host is back")
	settled.Release()
}

// The signature reaches a host only once the fee is booked: past the ceiling no status call carries it.
func TestSettleBooksTheFeeBeforeTheSignatureReachesAHost(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	settler, w := newSettler(t, chain)
	settler.Meter.Ceiling = 1
	payload, raw, _ := payment(t, settler, w)
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.ErrorIs(t, err, x402.ErrFeeCeiling)
	require.Zero(t, chain.Calls(solanarpc.MethodSignatureStatuses))
}

// An error object that may follow a forward is not a refusal: the transaction is watched and its fee stays booked.
func TestSettleWatchesAfterAnIndefiniteErrorObject(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{SendAmbiguousError: true}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err)
	settled.Release()
	require.Positive(t, settler.Meter.Spent())
}

// Known answer, computed independently with RFC 5869 over HMAC-SHA256: the derivation is a wire contract, so any change must
// fail here before it strands every key sold.
func TestVirtualKeyKnownAnswer(t *testing.T) {
	t.Parallel()
	var secret [x402.SecretBytes]byte
	copy(secret[:], bytes.Repeat([]byte{7}, x402.SecretBytes))
	require.Equal(t, "sk-43b1f0459fa4ea044b372be972b672d5d7eedc7e5b8bdbe9acb5c6b3dbce5c9a", x402.NewVirtualKeys(secret).ForPayment("00ff"))
}

// A griefer's unresolved fees stop new buyers at the sub-ceiling; a wallet that bought already is not stopped with them.
func TestSettleHoldsNewPayersToTheFailureCeiling(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err)
	settled.Release()
	settler.Meter.FailureCeiling = 0

	second := w.ClientTx(t, amount, nil)
	settled, err = settler.Settle(t.Context(), payload, second, amount, noCredit)
	require.NoError(t, err, "proven payers pass")
	settled.Release()

	w.Payer = x402test.NewKey(t)
	_, err = settler.Settle(t.Context(), payload, w.ClientTx(t, amount, nil), amount, noCredit)
	require.ErrorIs(t, err, x402.ErrFeeCeiling)
}

// The derived ceiling is exactly 500 worst-case settlements: pinned, not a knob.
func TestFeeConstants(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint64(2_010_000), uint64(x402.MaxFeeLamports))
	require.Equal(t, uint64(1_005_000_000), uint64(x402.DailyFeeCeilingLamports))
	require.Equal(t, uint64(201_000_000), uint64(x402.DailyFailureCeilingLamports))
}

func TestClaimsExpire(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	claims := &x402.Claims{TTL: time.Minute, Now: func() time.Time { return now }}
	require.True(t, claims.Claim("a"))
	require.False(t, claims.Claim("a"))
	require.True(t, claims.Held("a"))
	claims.Release("a")
	require.False(t, claims.Held("a"))
	require.True(t, claims.Claim("a"))
	now = now.Add(2 * time.Minute)
	require.False(t, claims.Held("a"))
	require.True(t, claims.Claim("a"))
}

func recoverRequest(t *testing.T, w *x402test.World, id solana.Signature, at time.Time) x402.RecoverRequest {
	t.Helper()
	proof := solana.SignatureFromBytes(signRecover(w, id, at))
	return x402.RecoverRequest{Transaction: id.String(), Payer: x402test.Public(w.Payer).String(), Timestamp: at.Unix(),
		Signature: proof.String()}
}

func signRecover(w *x402test.World, id solana.Signature, at time.Time) []byte {
	return x402test.Sign(w.Payer, x402.RecoverMessage(id, at.Unix()))
}

func landed(t *testing.T, chain *x402test.Chain, w *x402test.World) solana.Signature {
	t.Helper()
	pay, err := w.Policy.VerifyUnsigned(w.ClientTx(t, amount, nil))
	require.NoError(t, err)
	chain.Land(t, w.FeePayer.CoSign(pay))
	return w.FeePayer.TransactionID(pay)
}

func TestRecover(t *testing.T) {
	t.Parallel()
	t.Run("landed", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		id := landed(t, chain, w)
		settled, err := settler.Recover(t.Context(), recoverRequest(t, w, id, time.Now()))
		require.NoError(t, err)
		defer settled.Release()
		require.Equal(t, x402test.Public(w.Payer), settled.Payer)
		require.Equal(t, uint64(amount), settled.Amount)
		require.True(t, settled.LandedAt.IsZero(), "this chain reports no block time")
	})
	t.Run("carries the block time", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{BlockTime: 1800000000}
		settler, w := newSettler(t, chain)
		settled, err := settler.Recover(t.Context(), recoverRequest(t, w, landed(t, chain, w), time.Now()))
		require.NoError(t, err)
		defer settled.Release()
		require.Equal(t, time.Unix(1800000000, 0), settled.LandedAt)
	})
	t.Run("the primary is down", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{StatusDown: true}
		settler, w := newSettler(t, chain)
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, landed(t, chain, w), time.Now()))
		require.Error(t, err)
		require.Empty(t, x402.Reason(err))
	})
	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		settler, w := newSettler(t, &x402test.Chain{})
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, solana.Signature{1}, time.Now()))
		require.ErrorIs(t, err, x402.ErrNotOnChain)
	})
	t.Run("landed failed", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{FailOnChain: "Boom"}
		settler, w := newSettler(t, chain)
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, landed(t, chain, w), time.Now()))
		require.Equal(t, x402.ReasonTransactionFailed, x402.Reason(err))
	})
	t.Run("independent host silent", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{ConfirmerBlind: true}
		settler, w := newSettler(t, chain)
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, landed(t, chain, w), time.Now()))
		require.Equal(t, x402.ReasonPending, x402.Reason(err))
	})
	t.Run("independent host reports failure", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{ConfirmerFailure: "Boom"}
		settler, w := newSettler(t, chain)
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, landed(t, chain, w), time.Now()))
		require.Equal(t, x402.ReasonPending, x402.Reason(err))
	})
	t.Run("independent host down", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{ConfirmerDown: true}
		settler, w := newSettler(t, chain)
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, landed(t, chain, w), time.Now()))
		require.Error(t, err)
		require.Empty(t, x402.Reason(err))
	})
	t.Run("not signed by this sponsor", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		forged := w.ClientTx(t, amount, nil)
		forged[1] = 7 // a signature slot no sponsor key produced
		chain.Land(t, forged)
		tx, err := solana.TransactionFromBytes(forged)
		require.NoError(t, err)
		_, err = settler.Recover(t.Context(), recoverRequest(t, w, tx.Signatures[0], time.Now()))
		require.Equal(t, x402.ReasonSponsorSignature, x402.Reason(err))
	})
	t.Run("the host answers with another of this sponsor's transactions", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		id := landed(t, chain, w)
		pay, err := w.Policy.VerifyUnsigned(w.ClientTx(t, amount, nil))
		require.NoError(t, err)
		chain.Substitute = w.FeePayer.CoSign(pay)
		_, err = settler.Recover(t.Context(), recoverRequest(t, w, id, time.Now()))
		require.Equal(t, x402.ReasonSponsorSignature, x402.Reason(err))
	})
	t.Run("another wallet proves it", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		id := landed(t, chain, w)
		w.Payer = x402test.NewKey(t) // self-consistent proof by someone who is not the transaction's payer
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, id, time.Now()))
		require.ErrorIs(t, err, x402.ErrProofInvalid)
	})
	t.Run("a bad proof costs no RPC call and no bucket token", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		id := landed(t, chain, w)
		settler.RecoverLimiter.SetBurst(0)
		req := recoverRequest(t, w, id, time.Now())
		req.Timestamp++
		_, err := settler.Recover(t.Context(), req)
		require.ErrorIs(t, err, x402.ErrProofInvalid)
		require.Zero(t, chain.Calls(solanarpc.MethodTransaction))
	})
	t.Run("a good proof past the bucket", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		id := landed(t, chain, w)
		settler.RecoverLimiter.SetBurst(0)
		_, err := settler.Recover(t.Context(), recoverRequest(t, w, id, time.Now()))
		require.ErrorIs(t, err, x402.ErrRateLimited)
		require.Zero(t, chain.Calls(solanarpc.MethodTransaction))
	})
	t.Run("a proof works once, and only while nothing else holds the transaction", func(t *testing.T) {
		t.Parallel()
		chain := &x402test.Chain{}
		settler, w := newSettler(t, chain)
		id := landed(t, chain, w)
		req := recoverRequest(t, w, id, time.Now())
		settled, err := settler.Recover(t.Context(), req)
		require.NoError(t, err)
		_, err = settler.Recover(t.Context(), recoverRequest(t, w, id, time.Now().Add(time.Second)))
		require.ErrorIs(t, err, x402.ErrBusy, "the claim is held until Release, and the busy proof stays usable")
		settled.Release()
		_, err = settler.Recover(t.Context(), req)
		require.ErrorIs(t, err, x402.ErrProofSpent)
	})
}

func TestRecoverRefusesMalformedRequests(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	settler, w := newSettler(t, chain)
	id := landed(t, chain, w)
	good := recoverRequest(t, w, id, time.Now())
	for name, mutate := range map[string]func(*x402.RecoverRequest){
		"transaction": func(r *x402.RecoverRequest) { r.Transaction = "!!" },
		"payer":       func(r *x402.RecoverRequest) { r.Payer = "!!" },
		"signature":   func(r *x402.RecoverRequest) { r.Signature = "!!" },
		"stale":       func(r *x402.RecoverRequest) { r.Timestamp -= 600 },
		"future":      func(r *x402.RecoverRequest) { r.Timestamp += 600 },
	} {
		req := good
		mutate(&req)
		_, err := settler.Recover(t.Context(), req)
		require.ErrorIs(t, err, x402.ErrBadRecovery, name)
	}
	require.Zero(t, chain.Calls(solanarpc.MethodTransaction))
}

func TestChallengeCarriesTheTermsAndTheHint(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	settler, w := newSettler(t, chain)
	required := settler.Challenge(t.Context(), x402.Resource{URL: "https://x/v1/keys/buy"}, amount, "pay")
	header, err := x402.EncodeHeader(required)
	require.NoError(t, err)
	body, err := base64.StdEncoding.DecodeString(header)
	require.NoError(t, err)
	want := `{"x402Version":2,"error":"pay","resource":{"url":"https://x/v1/keys/buy"},"accepts":[{"scheme":"exact",
		"network":"solana:test","amount":"25000000","asset":"` + w.Policy.Mint.String() + `","payTo":"` + w.Treasury.String() + `",
		"maxTimeoutSeconds":60,"extra":{"feePayer":"` + w.FeePayer.String() + `","recentBlockhash":"` + solana.Hash{9}.String() + `",
		"lastValidBlockHeight":"500"}}]}`
	require.JSONEq(t, want, string(body))

	settler.Challenge(t.Context(), x402.Resource{}, amount, "")
	require.Equal(t, 1, chain.Calls(solanarpc.MethodLatestBlockhash), "402s share one blockhash call")
}

// A host that cannot answer costs a 402 only its hint, and only one call per TTL.
func TestChallengeWithoutAHint(t *testing.T) {
	t.Parallel()
	settler, w := newSettler(t, &x402test.Chain{})
	down := &solanarpc.Client{URL: "http://127.0.0.1:1", HTTP: http.DefaultClient}
	settler2, err := x402.NewSettler(settler.Terms, w.FeePayer, w.Keys, down, down, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	for range 2 {
		required := settler2.Challenge(t.Context(), x402.Resource{}, amount, "")
		require.Empty(t, required.Accepts[0].Extra.RecentBlockhash)
		require.Equal(t, w.FeePayer.String(), required.Accepts[0].Extra.FeePayer)
	}
}

func TestSettleChecksTheAcceptedTermsButNotTheHints(t *testing.T) {
	t.Parallel()
	settler, w := newSettler(t, &x402test.Chain{})
	raw := w.ClientTx(t, amount, nil)
	good := settler.Challenge(t.Context(), x402.Resource{}, amount, "").Accepts[0]
	stale := good
	stale.Extra.RecentBlockhash = "older"
	settled, err := settler.Settle(t.Context(), x402.Payload{Accepted: stale}, raw, amount, noCredit)
	require.NoError(t, err)
	settled.Release()
	for name, mutate := range map[string]func(*x402.Requirements){
		"scheme":    func(r *x402.Requirements) { r.Scheme = "upto" },
		"network":   func(r *x402.Requirements) { r.Network = "solana:other" },
		"amount":    func(r *x402.Requirements) { r.Amount = "1" },
		"asset":     func(r *x402.Requirements) { r.Asset = "other" },
		"payTo":     func(r *x402.Requirements) { r.PayTo = "other" },
		"fee payer": func(r *x402.Requirements) { r.Extra.FeePayer = "other" },
	} {
		bad := good
		mutate(&bad)
		_, err = settler.Settle(t.Context(), x402.Payload{Accepted: bad}, w.ClientTx(t, amount, nil), amount, noCredit)
		require.Equal(t, x402.ReasonRequirements, x402.Reason(err), name)
	}
}

func TestDecodePayload(t *testing.T) {
	t.Parallel()
	encode := func(v any) string {
		body, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.StdEncoding.EncodeToString(body)
	}
	good := map[string]any{"x402Version": 2, "payload": map[string]any{"transaction": "AQI="}}
	_, raw, err := x402.DecodePayload(encode(good))
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, raw)

	for name, header := range map[string]string{
		"not base64":  "!!",
		"not json":    base64.StdEncoding.EncodeToString([]byte("nope")),
		"old version": encode(map[string]any{"x402Version": 1, "payload": map[string]any{"transaction": "AQI="}}),
		"bad tx":      encode(map[string]any{"x402Version": 2, "payload": map[string]any{"transaction": "!!"}}),
		"too large":   string(bytes.Repeat([]byte("A"), 9000)),
	} {
		_, _, err = x402.DecodePayload(header)
		require.Error(t, err, name)
	}
}

func TestSimulateTransportFailureSendsNothing(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{SimulateDown: true}
	settler, w := newSettler(t, chain)
	payload, raw, _ := payment(t, settler, w)
	_, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.Error(t, err)
	require.Empty(t, x402.Reason(err))
	require.Empty(t, chain.Sent())
	chain.SetSimulateDown(false)
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err, "the claim was released: nothing left the process")
	settled.Release()
}

func TestSettleLogsAReportedSignatureMismatch(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	chain := &x402test.Chain{WrongSendReply: true}
	w := x402test.NewWorld(t)
	primary, confirmer := chain.Clients(t)
	terms := x402.Terms{Network: "solana:test", Treasury: w.Treasury, Mint: w.Policy.Mint}
	settler, err := x402.NewSettler(terms, w.FeePayer, w.Keys, primary, confirmer, slog.New(slog.NewTextHandler(&logs, nil)))
	require.NoError(t, err)
	settler.Poll = time.Millisecond
	payload, raw, id := payment(t, settler, w)
	settled, err := settler.Settle(t.Context(), payload, raw, amount, noCredit)
	require.NoError(t, err, "the id watched is always our own")
	settled.Release()
	require.Equal(t, id, settled.ID)
	require.Contains(t, logs.String(), "another signature")
}

func TestParseTermsRefuses(t *testing.T) {
	t.Parallel()
	good := randomAddress(t)
	for name, tc := range map[string][3]string{
		"no network":   {"", good, good},
		"bad treasury": {"n", "TREASURY-PLACEHOLDER-NOT-AN-ADDRESS", good},
		"bad mint":     {"n", good, "!!"},
	} {
		_, err := x402.ParseTerms(tc[0], tc[1], tc[2])
		require.Error(t, err, name)
	}
	terms, err := x402.ParseTerms("n", good, good)
	require.NoError(t, err)
	require.Equal(t, "n", terms.Network)
}

func randomAddress(t *testing.T) string {
	t.Helper()
	return x402test.Public(x402test.NewKey(t)).String()
}
