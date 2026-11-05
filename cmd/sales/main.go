// Command sales sells virtual keys over x402: it parses clients' transactions and holds the fee payer key, so the identity
// holding the quote-bound key links neither the Solana library nor this code.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/sales"
	"github.com/sealedin/gateway/internal/solanarpc"
	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
)

const (
	defaultListen     = ":8476"
	defaultGatewayURL = "http://gateway:4000"
	defaultRPCProxy   = "http://rpcproxy:8475"
	devMasterKeyEnv   = "SEALEDIN_LITELLM_MASTER_KEY"
	// devVirtualKeySecretEnv is the unattested branch's stand-in for what the identity derives.
	devVirtualKeySecretEnv = "SEALEDIN_DEV_VIRTUAL_KEY_SECRET" //nolint:gosec // the variable's name, not a credential
	// feePayerKeyEnv is the operators' key in the sealed env, in wallet form. This file is the only reader, see check-isolation.sh.
	feePayerKeyEnv  = "SEALEDIN_FEE_PAYER_KEY"
	addressFileMode = 0o444
	gatewayTimeout  = 8 * time.Second
	headerTimeout   = 5 * time.Second
	readTimeout     = 10 * time.Second
	writeTimeout    = readTimeout + gatewayTimeout + x402.HandlerBudget // body, top-up lookup, then the settlement it holds open
	idleTimeout     = 60 * time.Second
	shutdownBudget  = writeTimeout // a settlement in flight finishes; the compose's stop_grace_period sits above this
	secretWaitPoll  = 200 * time.Millisecond
	secretsWait     = 2 * time.Minute // the identity publishes at its start, which the compose orders first

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("sales", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", defaultListen, "listen address on the compose network, reached only by the edge")
	gatewayURL := flags.String("gateway", defaultGatewayURL, "LiteLLM base URL")
	rpcProxy := flags.String("rpcproxy", defaultRPCProxy, "the measured Solana RPC proxy")
	secretFile := flags.String("virtual-key-secret-file", "", "secret behind sold keys, from the identity; empty means the dev branch")
	addressFile := flags.String("fee-payer-address-file", "", "file to publish the fee payer's address to, for the identity's signed catalog")
	masterKeyFile := flags.String("master-key-file", "", "LiteLLM master key the attested identity publishes")
	wait := flags.Duration("secrets-wait", secretsWait, "how long to wait for the identity's files")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	cfg, err := loadSecrets(ctx, *secretFile, *masterKeyFile, *wait)
	if err != nil {
		logger.Error("sales wiring failed", "err", err)
		return exitUsage
	}
	handler, err := wire(cfg, *gatewayURL, *rpcProxy, logger)
	if err != nil {
		logger.Error("sales wiring failed", "err", err)
		return exitUsage
	}
	if err = publishAddress(*addressFile, cfg.key); err != nil {
		logger.Error("sales wiring failed", "err", err)
		return exitUsage
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: headerTimeout, ReadTimeout: readTimeout,
		WriteTimeout: writeTimeout, IdleTimeout: idleTimeout}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("sales listening", "addr", *listen)
	select {
	case err = <-serveErr:
		logger.Error("server failed", "err", err)
		return exitError
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		if err = server.Shutdown(shutdownCtx); err != nil { //nolint:contextcheck // the parent context is already done
			logger.Error("shutdown failed", "err", err)
			return exitError
		}
		return exitOK
	}
}

// secrets is what this service runs on: the operators' fee payer key from the sealed env, and from the identity the secret
// behind sold keys, which no operator holds, with the terms that go with them.
type secrets struct {
	key              ed25519.PrivateKey
	virtualKeySecret [x402.SecretBytes]byte
	masterKey        string
	terms            gateway.Terms
}

// loadSecrets takes the measured inputs when the measured compose names the identity's files, never reading the dev settings
// then; with no files named it is the unattested branch, and with no dev seed there is nothing to sell.
func loadSecrets(ctx context.Context, secretFile, masterKeyFile string, wait time.Duration) (secrets, error) {
	if secretFile == "" {
		return devSecrets()
	}
	if !gateway.TreasuryConfigured() {
		return secrets{}, errors.New("the measured treasury is still the placeholder")
	}
	return readPublished(ctx, secretFile, masterKeyFile, wait)
}

func devSecrets() (secrets, error) {
	devSeed := os.Getenv(gateway.DevFeePayerSeedEnv)
	if devSeed == "" {
		return secrets{}, errors.New("no -virtual-key-secret-file and no " + gateway.DevFeePayerSeedEnv)
	}
	seed, err := gateway.DecodeFeePayerSeed(devSeed)
	if err != nil {
		return secrets{}, err
	}
	secret, err := decodeSecret(os.Getenv(devVirtualKeySecretEnv))
	if err != nil {
		return secrets{}, fmt.Errorf("%s: %w", devVirtualKeySecretEnv, err)
	}
	return secrets{key: ed25519.NewKeyFromSeed(seed[:]), virtualKeySecret: secret, masterKey: os.Getenv(devMasterKeyEnv),
		terms: gateway.DevTerms()}, nil
}

// readPublished is the measured branch: the sealed env's key, the identity's two files and the measured terms, whatever the
// dev settings say. The key leaves the environment at once, so nothing this process starts inherits it.
func readPublished(ctx context.Context, secretFile, masterKeyFile string, wait time.Duration) (secrets, error) {
	key, err := x402.ParseFeePayerKey(os.Getenv(feePayerKeyEnv))
	if err != nil {
		return secrets{}, fmt.Errorf("%s: %w", feePayerKeyEnv, err)
	}
	if err = os.Unsetenv(feePayerKeyEnv); err != nil {
		return secrets{}, err
	}
	secretText, err := readWhenPresent(ctx, secretFile, wait)
	if err != nil {
		return secrets{}, err
	}
	secret, err := decodeSecret(secretText)
	if err != nil {
		return secrets{}, err
	}
	masterKey, err := readWhenPresent(ctx, masterKeyFile, wait)
	if err != nil {
		return secrets{}, err
	}
	return secrets{key: key, virtualKeySecret: secret, masterKey: masterKey, terms: gateway.MeasuredTerms()}, nil
}

func decodeSecret(text string) ([x402.SecretBytes]byte, error) {
	var secret [x402.SecretBytes]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != x402.SecretBytes {
		return secret, fmt.Errorf("virtual key secret must be %d hex bytes", x402.SecretBytes)
	}
	copy(secret[:], raw)
	return secret, nil
}

// publishAddress tells the identity the fee payer's public address, renamed into place so it never reads a partial one.
func publishAddress(path string, key ed25519.PrivateKey) error {
	if path == "" {
		return nil
	}
	tmp := path + ".tmp"
	address := x402.NewFeePayer(key).String() + "\n"
	if err := os.WriteFile(tmp, []byte(address), addressFileMode); err != nil {
		return fmt.Errorf("fee payer address: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("fee payer address: %w", err)
	}
	return nil
}

// readWhenPresent waits for a file the identity renames into place, so it is never partial.
func readWhenPresent(ctx context.Context, path string, wait time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	ticker := time.NewTicker(secretWaitPoll)
	defer ticker.Stop()
	for {
		raw, err := os.ReadFile(path) //nolint:gosec // a path fixed in the measured compose
		if err == nil {
			return strings.TrimSpace(string(raw)), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("secret file: %w", err)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("secret file %s never appeared: %w", path, ctx.Err())
		case <-ticker.C:
		}
	}
}

func wire(cfg secrets, gatewayURL, rpcProxy string, logger *slog.Logger) (http.Handler, error) {
	terms, err := x402.ParseTerms(cfg.terms.Network, cfg.terms.Treasury, cfg.terms.Asset)
	if err != nil {
		return nil, err
	}
	payer := x402.NewFeePayer(cfg.key)
	rpc := &http.Client{Timeout: solanarpc.ClientTimeout}
	settler, err := x402.NewSettler(terms, payer, x402.NewVirtualKeys(cfg.virtualKeySecret),
		&solanarpc.Client{URL: rpcProxy + solanarpc.PrimaryRoute, HTTP: rpc},
		&solanarpc.Client{URL: rpcProxy + solanarpc.ConfirmationRoute, HTTP: rpc}, logger)
	if err != nil {
		return nil, err
	}
	admin := &usage.Gateway{BaseURL: gatewayURL, MasterKey: cfg.masterKey, HTTP: &http.Client{Timeout: gatewayTimeout}}
	mux := http.NewServeMux()
	sales.New(admin, gateway.CatalogModels(), settler, logger).Register(mux)
	logger.Info("x402 purchases on", "fee_payer", payer.String(), "pay_to", terms.Treasury.String(), "network", terms.Network)
	return mux, nil
}
