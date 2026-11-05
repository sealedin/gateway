// Command identity is the identity service: an ephemeral enclave key quoted over GET /v1/quote?block_id=<hex>.
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

	"github.com/mr-tron/base58"

	"github.com/sealedin/gateway/internal/enclave"
	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/keys"
	"github.com/sealedin/gateway/internal/usage"
)

const (
	defaultListenAddr  = ":8471"
	defaultPrivateAddr = ":8473" // reached only by the in-TD edge, never published
	defaultEdgeAddr    = "edge:443"
	defaultGatewayURL  = "http://gateway:4000" // LiteLLM's admin API on the compose network, never published
	// gatewayTimeout must stay below writeTimeout so a slow LiteLLM yields a 502, not a torn reply; the scripts'
	// --max-time 15 sits above both.
	gatewayTimeout = 8 * time.Second
	// defaultMasterKeyFile is where the attested identity hands the derived master key to the gateway: a tmpfs volume
	// of the measured compose, so the gateway needs no agent socket of its own.
	defaultMasterKeyFile = "/run/sealedin/litellm-master-key"
	// defaultVirtualKeySecretFile hands the derived secret behind sold keys to the sales service: a tmpfs volume of its own,
	// which LiteLLM does not mount, unlike the master key's.
	defaultVirtualKeySecretFile = "/run/sealedin-virtualkey/virtual-key-secret" //nolint:gosec // a path, not a credential
	// defaultFeePayerAddressFile is where the sales service, alone holding the fee payer key, publishes its public address.
	defaultFeePayerAddressFile = "/run/sealedin-feepayer-address/fee-payer-address"
	// virtualKeyPath is the guest agent derivation path of that secret. A new version strands every key sold under this one.
	virtualKeyPath    = "sealedin/virtual-key/v1"
	virtualKeyPurpose = "x402 virtual key derivation"
	masterKeyFileMode = 0o400
	operatorKeyEnv    = "SEALEDIN_OPERATOR_API_KEY"
	devMasterKeyEnv   = "SEALEDIN_LITELLM_MASTER_KEY"
	edgeCertTTL       = time.Minute
	headerTimeout     = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 5 * time.Second

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("identity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddr := flags.String("listen", defaultListenAddr, "identity service listen address")
	privateAddr := flags.String("private-listen", defaultPrivateAddr,
		"private listen address serving GET /v1/catalog and the operator's /v1/keys, reachable only by the in-TD edge")
	edgeAddr := flags.String("edge", defaultEdgeAddr, "edge TLS address whose certificate the enclave key endorses")
	edgeSNI := flags.String("edge-sni", "", "SNI server name for the edge handshake (empty sends none)")
	gatewayURL := flags.String("gateway", defaultGatewayURL, "LiteLLM base URL the key issuance calls with the in-CVM master key")
	masterKeyFile := flags.String("master-key-file", defaultMasterKeyFile,
		"file the attested identity writes the derived LiteLLM master key to for the gateway (shared tmpfs volume)")
	virtualKeySecretFile := flags.String("virtual-key-secret-file", defaultVirtualKeySecretFile,
		"file the attested identity writes the secret behind sold keys to for the sales service (shared tmpfs volume)")
	feePayerAddressFile := flags.String("fee-payer-address-file", defaultFeePayerAddressFile,
		"file the sales service publishes the fee payer's public address to, for the signed catalog (shared tmpfs volume)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(stderr, nil))

	identity, err := enclave.NewIdentity()
	if err != nil {
		logger.Error("identity init failed", "err", err)
		return exitError
	}
	logger.Info("identity ready", "pubkey", identity.PublicKeyHex(), "attested", identity.Attested())
	issuer, err := keyIssuer(ctx, *gatewayURL, *masterKeyFile, enclave.DeriveKey, logger)
	if err != nil {
		logger.Error("key issuance init failed", "err", err)
		return exitError
	}

	terms, feePayer, err := setUpPurchases(ctx, *virtualKeySecretFile, *feePayerAddressFile, enclave.DeriveKey, logger)
	if err != nil {
		logger.Error("x402 init failed", "err", err)
		return exitError
	}

	publicMux := enclave.NewMux(identity, enclave.Cached(enclave.EdgeCert(*edgeAddr, *edgeSNI), edgeCertTTL))
	// The catalog and key issuance live on their own listener so the plaintext surface stays /v1/quote and /v1/tls.
	servers := []*http.Server{
		newServer(*listenAddr, publicMux),
		newServer(*privateAddr, privateMux(identity, gateway.CatalogFor(terms), issuer, feePayer)),
	}

	serveErr := make(chan error, len(servers))
	addrs := make([]string, 0, len(servers))
	for _, server := range servers {
		addrs = append(addrs, server.Addr)
		go func() { serveErr <- server.ListenAndServe() }()
	}
	logger.Info("identity service listening", "addrs", addrs)

	select {
	case serveResult := <-serveErr:
		// Nothing closes these servers but shutdownAll, so any first result is a failure; never run half a topology.
		logger.Error("server failed", "err", serveResult)
		shutdownAll(logger, servers) //nolint:contextcheck // shutdown runs on its own fresh-context budget
		return exitError
	case <-ctx.Done():
		if !shutdownAll(logger, servers) { //nolint:contextcheck // the parent context is already done
			return exitError
		}
		return exitOK
	}
}

func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// keySource is enclave.DeriveKey's shape, injected so the three startup branches are testable without an agent.
type keySource func(ctx context.Context, path, purpose string) ([enclave.KeySize]byte, error)

// keyIssuer wires key issuance: attested, the master key is derived in the CVM, handed to the gateway through
// masterKeyFile and the operator bearer is required; on the unattested branch both come from the environment and may
// be empty (issuance then fails at the gateway).
func keyIssuer(ctx context.Context, gatewayURL, masterKeyFile string, derive keySource, logger *slog.Logger,
) (*keys.Service, error) {
	operator := os.Getenv(operatorKeyEnv)
	var master string
	raw, err := derive(ctx, usage.MasterKeyPath, usage.MasterKeyPurpose)
	switch {
	case errors.Is(err, enclave.ErrNotAttested):
		master = os.Getenv(devMasterKeyEnv)
		if master == "" || operator == "" {
			logger.Warn("key issuance unconfigured: set " + devMasterKeyEnv + " and " + operatorKeyEnv + " for dev")
		}
	case err != nil:
		return nil, err
	case operator == "":
		return nil, errors.New(operatorKeyEnv + " must be set in attested mode")
	default:
		master = usage.FormatMasterKey(raw)
		if publishErr := publishSecret(masterKeyFile, master); publishErr != nil {
			return nil, publishErr
		}
	}
	client := &usage.Gateway{BaseURL: gatewayURL, MasterKey: master, HTTP: &http.Client{Timeout: gatewayTimeout}}
	return &keys.Service{Gateway: client, Operator: operator, Models: gateway.CatalogModels(), Logger: logger}, nil
}

// publishSecret writes a derived secret read-only for its owner and renames it into place, so its reader never sees a
// partial file; a previous boot's copy on the same volume is replaced.
func publishSecret(path, secret string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(secret+"\n"), masterKeyFileMode); err != nil {
		return fmt.Errorf("secret file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("secret file: %w", err)
	}
	return nil
}

// setUpPurchases prepares what the sales service needs from here. Attested, it derives the secret behind sold keys, hands it
// over its tmpfs volume, and a placeholder treasury is fatal; unattested, purchases are off without the dev seed. It returns
// the terms and where the signed catalog reads the fee payer's address from, empty while purchases are off.
func setUpPurchases(
	ctx context.Context, secretFile, addressFile string, derive keySource, logger *slog.Logger,
) (gateway.Terms, func() string, error) {
	secret, err := derive(ctx, virtualKeyPath, virtualKeyPurpose)
	switch {
	case errors.Is(err, enclave.ErrNotAttested):
		devSeed := os.Getenv(gateway.DevFeePayerSeedEnv)
		if devSeed == "" {
			logger.Info("x402 purchases off: unattested and no " + gateway.DevFeePayerSeedEnv)
			return gateway.MeasuredTerms(), func() string { return "" }, nil
		}
		seed, seedErr := gateway.DecodeFeePayerSeed(devSeed)
		if seedErr != nil {
			return gateway.Terms{}, nil, fmt.Errorf("%s: %w", gateway.DevFeePayerSeedEnv, seedErr)
		}
		address := feePayerAddress(seed)
		return gateway.DevTerms(), func() string { return address }, nil
	case err != nil:
		return gateway.Terms{}, nil, err
	case !gateway.TreasuryConfigured():
		return gateway.Terms{}, nil, errors.New("the measured treasury is still the placeholder")
	}
	if err = publishSecret(secretFile, hex.EncodeToString(secret[:])); err != nil {
		return gateway.Terms{}, nil, err
	}
	logger.Info("x402 virtual key secret published")
	return gateway.MeasuredTerms(), func() string { return readFeePayerAddress(addressFile) }, nil
}

// readFeePayerAddress reads what the sales service published; anything but an address leaves the catalog saying purchases are off.
func readFeePayerAddress(path string) string {
	raw, err := os.ReadFile(path) //nolint:gosec // a path fixed in the measured compose
	if err != nil {
		return ""
	}
	address := strings.TrimSpace(string(raw))
	if decoded, decodeErr := base58.Decode(address); decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
		return ""
	}
	return address
}

// feePayerAddress is the Solana form of the dev seed's public key.
func feePayerAddress(seed [enclave.KeySize]byte) string {
	return base58.Encode(ed25519.NewKeyFromSeed(seed[:])[ed25519.SeedSize:])
}

// privateMux is the edge-only surface: the signed catalog and key issuance today, every future non-bootstrap route.
func privateMux(id *enclave.Identity, catalog gateway.Catalog, issuer *keys.Service, feePayer func() string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/catalog", enclave.CatalogHandler(id, catalog, feePayer))
	issuer.Register(mux)
	return mux
}

func shutdownAll(logger *slog.Logger, servers []*http.Server) bool {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	ok := true
	for _, server := range servers {
		if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Error("shutdown failed", "addr", server.Addr, "err", shutdownErr)
			ok = false
		}
	}
	return ok
}
