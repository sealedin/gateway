package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/mr-tron/base58"
	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/x402"
)

const devTreasury = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"

func setDevPayment(t *testing.T) {
	t.Helper()
	t.Setenv(gateway.DevFeePayerSeedEnv, strings.Repeat("07", gateway.FeePayerSeedBytes))
	t.Setenv(devVirtualKeySecretEnv, strings.Repeat("0b", x402.SecretBytes))
	t.Setenv("SEALEDIN_DEV_PAYMENT_NETWORK", "solana:test")
	t.Setenv("SEALEDIN_DEV_TREASURY", devTreasury)
	t.Setenv("SEALEDIN_DEV_PAYMENT_ASSET", gateway.PaymentAsset)
}

func TestRunRejectsBadFlag(t *testing.T) {
	t.Parallel()
	require.Equal(t, exitUsage, run(context.Background(), []string{"-nope"}, io.Discard))
}

// A settlement holds its reply open while it confirms; the constants derive from its budget, and the host must wait them out.
func TestTimeoutsOutlastASettlement(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	var compose struct {
		Services map[string]struct {
			StopGracePeriod string `yaml:"stop_grace_period"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &compose))
	grace, err := time.ParseDuration(compose.Services["sales"].StopGracePeriod)
	require.NoError(t, err)
	require.Greater(t, grace, shutdownBudget, "the host must wait out the server's shutdown budget")
}

func TestLoadSecretsDevBranch(t *testing.T) {
	t.Run("no seed sells nothing", func(t *testing.T) {
		t.Setenv(gateway.DevFeePayerSeedEnv, "")
		_, err := loadSecrets(t.Context(), "", "", time.Millisecond)
		require.ErrorContains(t, err, gateway.DevFeePayerSeedEnv)
	})
	t.Run("a bad seed is a startup error", func(t *testing.T) {
		t.Setenv(gateway.DevFeePayerSeedEnv, "zz")
		_, err := loadSecrets(t.Context(), "", "", time.Millisecond)
		require.ErrorContains(t, err, "hex bytes")
	})
	t.Run("the dev terms apply", func(t *testing.T) {
		setDevPayment(t)
		t.Setenv(devMasterKeyEnv, "sk-dev")
		got, err := loadSecrets(t.Context(), "", "", time.Millisecond)
		require.NoError(t, err)
		require.Equal(t, "sk-dev", got.masterKey)
		require.Equal(t, devTreasury, got.terms.Treasury)
	})
}

// published lays out what the measured branch reads, with a throwaway key in the sealed env's place.
func published(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	t.Setenv(feePayerKeyEnv, base58.Encode(key))
	dir := t.TempDir()
	secretFile, keyFile := filepath.Join(dir, "secret"), filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(secretFile, []byte(strings.Repeat("0a", x402.SecretBytes)+"\n"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("sk-published\n"), 0o600))
	return key, secretFile, keyFile
}

// The measured branch reads the sealed env's key, the identity's files and the measured terms, whatever the dev settings say.
func TestReadPublishedIgnoresTheDevSettings(t *testing.T) {
	setDevPayment(t)
	key, secretFile, keyFile := published(t)
	got, err := readPublished(t.Context(), secretFile, keyFile, time.Second)
	require.NoError(t, err)
	require.Equal(t, key, got.key)
	require.Equal(t, strings.Repeat("0a", x402.SecretBytes), hex.EncodeToString(got.virtualKeySecret[:]))
	require.Equal(t, "sk-published", got.masterKey)
	require.Equal(t, gateway.MeasuredTerms(), got.terms)
	require.Empty(t, os.Getenv(feePayerKeyEnv), "the key leaves the environment once read")
}

// Attested, a missing or malformed key stops the service, and the error does not carry it.
func TestReadPublishedRefusesABadFeePayerKey(t *testing.T) {
	_, secretFile, keyFile := published(t)
	for _, bad := range []string{"", "zz", strings.Repeat("07", gateway.FeePayerSeedBytes)} {
		t.Setenv(feePayerKeyEnv, bad)
		_, err := readPublished(t.Context(), secretFile, keyFile, time.Millisecond)
		require.ErrorContains(t, err, feePayerKeyEnv)
		if bad != "" {
			require.NotContains(t, err.Error(), bad)
		}
	}
}

// The operators hold the fee payer key, so it must decide no customer's key: with the same secret a different fee payer key
// derives the same keys, with a different secret the same key derives others, and the key itself as the secret derives none.
func TestVirtualKeysDoNotDependOnTheFeePayerKey(t *testing.T) {
	const digest = "00ff"
	_, secretFile, keyFile := published(t)
	first, err := readPublished(t.Context(), secretFile, keyFile, time.Second)
	require.NoError(t, err)
	want := x402.NewVirtualKeys(first.virtualKeySecret).ForPayment(digest)

	published(t)
	require.NoError(t, os.WriteFile(secretFile, []byte(strings.Repeat("0a", x402.SecretBytes)+"\n"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("sk-published\n"), 0o600))
	second, err := readPublished(t.Context(), secretFile, keyFile, time.Second)
	require.NoError(t, err)
	require.NotEqual(t, first.key, second.key)
	require.Equal(t, want, x402.NewVirtualKeys(second.virtualKeySecret).ForPayment(digest), "another fee payer key, the same keys")

	var fromSeed [x402.SecretBytes]byte
	copy(fromSeed[:], first.key.Seed())
	require.NotEqual(t, want, x402.NewVirtualKeys(fromSeed).ForPayment(digest), "the env value is not the derivation input")
}

func TestPublishAddress(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "address")
	require.NoError(t, publishAddress(path, key))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, base58.Encode(key[ed25519.SeedSize:])+"\n", string(got), "the public half, and nothing else")
	require.NoError(t, publishAddress("", key), "the dev branch publishes nothing")
}

func TestReadWhenPresent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	t.Run("waits for the file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "late")
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = os.WriteFile(path, []byte("value\n"), 0o600)
		}()
		got, err := readWhenPresent(t.Context(), path, 5*time.Second)
		require.NoError(t, err)
		require.Equal(t, "value", got)
	})
	t.Run("gives up", func(t *testing.T) {
		t.Parallel()
		_, err := readWhenPresent(t.Context(), filepath.Join(dir, "never"), 10*time.Millisecond)
		require.ErrorContains(t, err, "never appeared")
	})
	t.Run("a directory is no secret", func(t *testing.T) {
		t.Parallel()
		_, err := readWhenPresent(t.Context(), dir, time.Second)
		require.Error(t, err)
	})
}

func TestWire(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	terms := gateway.Terms{Network: "solana:test", Treasury: gateway.TreasuryPlaceholder, Asset: gateway.PaymentAsset}
	_, err = wire(secrets{key: key, terms: terms}, "http://g", "http://r", logger)
	require.ErrorContains(t, err, "treasury", "the placeholder is no address")
	terms.Treasury = devTreasury
	handler, err := wire(secrets{key: key, terms: terms}, "http://g", "http://r", logger)
	require.NoError(t, err)
	require.NotNil(t, handler)
}

func TestRunServesAndStops(t *testing.T) {
	setDevPayment(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", addr, "-gateway", "http://127.0.0.1:1", "-rpcproxy", "http://127.0.0.1:1"}, io.Discard)
	}()
	require.Eventually(t, func() bool {
		req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/v1/keys/buy", strings.NewReader("nope"))
		if reqErr != nil {
			return false
		}
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusBadRequest
	}, 5*time.Second, 20*time.Millisecond)
	cancel()
	select {
	case code := <-done:
		require.Equal(t, exitOK, code)
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit")
	}
}
