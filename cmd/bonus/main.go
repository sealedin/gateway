// Command bonus gives a one-time credit to X accounts that follow ours. It is the operator's tool and runs outside the enclave:
// it holds the operator token and has the gateway issue keys through the operator's route, so no measured image knows of it.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sealedin/gateway/internal/bonus"
	"github.com/sealedin/gateway/internal/operator"
)

const (
	operatorEnv     = "SEALEDIN_OPERATOR_API_KEY"
	clientIDEnv     = "SEALEDIN_X_CLIENT_ID"
	clientSecretEnv = "SEALEDIN_X_CLIENT_SECRET" //nolint:gosec // the variable's name, not a credential

	defaultListen  = ":8480"
	defaultAccount = "sealedinai"
	defaultSite    = "https://sealedin.ai"
	defaultBudget  = 10
	defaultRPM     = 20
	defaultMaxKeys = 100
	defaultMinAge  = 30 * 24 * time.Hour

	callTimeout    = 10 * time.Second
	headerTimeout  = 5 * time.Second
	readTimeout    = 10 * time.Second
	writeTimeout   = 5 * callTimeout // three calls to X and two to the gateway
	idleTimeout    = 60 * time.Second
	shutdownBudget = writeTimeout

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("bonus", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", defaultListen, "listen address, behind a TLS reverse proxy")
	publicURL := flags.String("public-url", "", "this service's own https origin, as registered with X for the callback")
	gatewayURL := flags.String("gateway", "", "the gateway's https origin, whose /v1/keys issues the keys")
	ledgerFile := flags.String("ledger-file", "bonus-ledger", "file recording the aliases given a bonus")
	cfg := bonus.Config{}
	flags.StringVar(&cfg.SiteURL, "site", defaultSite, "the site whose bonus page shows the outcome")
	flags.StringVar(&cfg.Account, "account", defaultAccount, "the X account to follow")
	flags.Float64Var(&cfg.BudgetUSD, "budget", defaultBudget, "USD one bonus key may spend")
	flags.IntVar(&cfg.RPMLimit, "rpm", defaultRPM, "requests a minute one bonus key may make")
	flags.IntVar(&cfg.MaxKeys, "max-keys", defaultMaxKeys, "bonuses to give before the promotion ends")
	flags.DurationVar(&cfg.MinAccountAge, "min-account-age", defaultMinAge, "younger X accounts get nothing")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	cfg.PublicURL = strings.TrimRight(*publicURL, "/")
	handler, err := wire(cfg, strings.TrimRight(*gatewayURL, "/"), *ledgerFile, logger)
	if err != nil {
		logger.Error("bonus wiring failed", "err", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: headerTimeout, ReadTimeout: readTimeout,
		WriteTimeout: writeTimeout, IdleTimeout: idleTimeout}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("bonus listening", "addr", *listen, "account", cfg.Account, "budget_usd", cfg.BudgetUSD, "max_keys", cfg.MaxKeys)
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

// wire refuses to start on anything that would send a token or a key over plain HTTP, or give bonuses without bounds.
func wire(cfg bonus.Config, gatewayURL, ledgerFile string, logger *slog.Logger) (http.Handler, error) {
	token, clientID := os.Getenv(operatorEnv), os.Getenv(clientIDEnv)
	switch {
	case token == "" || clientID == "":
		return nil, errors.New("set " + operatorEnv + " and " + clientIDEnv)
	case !strings.HasPrefix(cfg.PublicURL, "https://") || !strings.HasPrefix(gatewayURL, "https://"):
		return nil, errors.New("-public-url and -gateway must be https origins")
	case cfg.BudgetUSD <= 0 || cfg.RPMLimit <= 0 || cfg.MaxKeys <= 0 || cfg.Account == "":
		return nil, errors.New("-budget, -rpm and -max-keys must be positive, and -account set")
	}
	ledger, err := bonus.OpenLedger(ledgerFile)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: callTimeout}
	x := &bonus.X{ClientID: clientID, ClientSecret: os.Getenv(clientSecretEnv), AuthorizeURL: bonus.DefaultAuthorizeURL,
		APIBase: bonus.DefaultAPIBase, HTTP: client}
	keys := &operator.Client{BaseURL: gatewayURL, Token: token, HTTP: client}
	mux := http.NewServeMux()
	bonus.New(cfg, x, keys, ledger, logger).Register(mux)
	logger.Info("bonus ledger read", "given", ledger.Count())
	return mux, nil
}
