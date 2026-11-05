package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/sales"
	"github.com/sealedin/gateway/internal/testsupport"
	"github.com/sealedin/gateway/internal/x402"
	"github.com/sealedin/gateway/internal/x402/x402test"
)

func writeWallet(t *testing.T, key []byte) string {
	t.Helper()
	ints := make([]int, len(key))
	for i, b := range key {
		ints[i] = int(b)
	}
	raw, err := json.Marshal(ints)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "wallet.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// The operator's tool runs its whole flow end to end against the real handlers and a fake chain and gateway.
func TestSmokeFlowAgainstTheHandlers(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	world := x402test.NewWorld(t)
	primary, confirmer := chain.Clients(t)
	logger := slog.New(slog.DiscardHandler)
	settler, err := x402.NewSettler(x402.Terms{Network: "solana:test", Treasury: world.Treasury, Mint: world.Policy.Mint},
		world.FeePayer, world.Keys, primary, confirmer, logger)
	require.NoError(t, err)
	settler.Poll = time.Millisecond
	fake := &testsupport.FakeGateway{MasterKey: "sk-master"}
	mux := http.NewServeMux()
	sales.New(fake.Client(t), gateway.CatalogModels(), settler, logger).Register(mux)
	catalog := testCatalog(world.Treasury.String(), world.Policy.Mint.String(), world.FeePayer.String())
	mux.HandleFunc("GET /v1/catalog", func(w http.ResponseWriter, _ *http.Request) { httpjson.Write(w, http.StatusOK, catalog) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"-url", srv.URL, "-catalog-url", srv.URL, "-wallet", writeWallet(t, world.Payer)}, &stdout, &stderr)
	require.Equal(t, exitOK, code, "stderr: %s", stderr.String())
	require.Contains(t, stdout.String(), "OK:")
	require.Len(t, chain.Sent(), 1)
	require.NotContains(t, stdout.String(), "sk-", "no key on the terminal")
}

// The Solana Pay half, with a local signer in the wallet's place: sent through the node, found, claimed and claimed again.
func TestSmokeClaimFlowAgainstTheHandlers(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	world := x402test.NewWorld(t)
	primary, confirmer := chain.Clients(t)
	logger := slog.New(slog.DiscardHandler)
	settler, err := x402.NewSettler(x402.Terms{Network: "solana:test", Treasury: world.Treasury, Mint: world.Policy.Mint},
		world.FeePayer, world.Keys, primary, confirmer, logger)
	require.NoError(t, err)
	settler.Poll = time.Millisecond
	fake := &testsupport.FakeGateway{MasterKey: "sk-master"}
	mux := http.NewServeMux()
	sales.New(fake.Client(t), gateway.CatalogModels(), settler, logger).Register(mux)
	catalog := testCatalog(world.Treasury.String(), world.Policy.Mint.String(), world.FeePayer.String())
	mux.HandleFunc("GET /v1/catalog", func(w http.ResponseWriter, _ *http.Request) { httpjson.Write(w, http.StatusOK, catalog) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var stdout, stderr bytes.Buffer
	args := []string{"-url", srv.URL, "-catalog-url", srv.URL, "-wallet", writeWallet(t, world.Payer), "-solana-pay-rpc", primary.URL}
	code := run(t.Context(), args, &stdout, &stderr)
	require.Equal(t, exitOK, code, "stderr: %s", stderr.String())
	require.Contains(t, stdout.String(), "claimed again")
	require.NotContains(t, stdout.String(), "sk-", "no key on the terminal")
}

func testCatalog(payTo, asset, feePayer string) map[string]any {
	return map[string]any{"pay_to": payTo, "networks": []string{"solana:test"}, "asset": asset, "fee_payer": feePayer}
}

// A challenge that differs from what the enclave signed is refused before any money moves.
func TestSmokeRefusesAChallengeOffTheCatalog(t *testing.T) {
	t.Parallel()
	chain := &x402test.Chain{}
	world := x402test.NewWorld(t)
	primary, confirmer := chain.Clients(t)
	logger := slog.New(slog.DiscardHandler)
	settler, err := x402.NewSettler(x402.Terms{Network: "solana:test", Treasury: world.Treasury, Mint: world.Policy.Mint},
		world.FeePayer, world.Keys, primary, confirmer, logger)
	require.NoError(t, err)
	mux := http.NewServeMux()
	sales.New((&testsupport.FakeGateway{MasterKey: "sk-master"}).Client(t), gateway.CatalogModels(), settler, logger).Register(mux)
	catalog := testCatalog("another-treasury", world.Policy.Mint.String(), world.FeePayer.String())
	mux.HandleFunc("GET /v1/catalog", func(w http.ResponseWriter, _ *http.Request) { httpjson.Write(w, http.StatusOK, catalog) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	var stderr bytes.Buffer
	code := run(t.Context(), []string{"-url", srv.URL, "-catalog-url", srv.URL, "-wallet", writeWallet(t, world.Payer)}, io.Discard, &stderr)
	require.Equal(t, exitError, code)
	require.Contains(t, stderr.String(), "signed catalog")
	require.Empty(t, chain.Sent())
}

func TestRunUsage(t *testing.T) {
	t.Parallel()
	short := writeWallet(t, []byte{1, 2})
	for name, args := range map[string][]string{
		"bad flag":     {"-nope"},
		"no url":       {"-catalog-url", "http://x", "-wallet", "x"},
		"no catalog":   {"-url", "http://x", "-wallet", "x"},
		"no wallet":    {"-url", "http://x", "-catalog-url", "http://x"},
		"absent file":  {"-url", "http://x", "-catalog-url", "http://x", "-wallet", filepath.Join(t.TempDir(), "absent")},
		"short wallet": {"-url", "http://x", "-catalog-url", "http://x", "-wallet", short},
	} {
		require.Equal(t, exitUsage, run(context.Background(), args, io.Discard, io.Discard), name)
	}
}

func TestRunFailsWithoutAChallenge(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	t.Cleanup(srv.Close)
	wallet := writeWallet(t, x402test.NewKey(t))
	var stderr bytes.Buffer
	require.Equal(t, exitError, run(t.Context(), []string{"-url", srv.URL, "-catalog-url", srv.URL, "-wallet", wallet}, io.Discard, &stderr))
	require.Contains(t, stderr.String(), strconv.Itoa(http.StatusNotFound))
}
