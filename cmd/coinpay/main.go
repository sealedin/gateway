// Command coinpay sells keys for coins other than USDC on Solana through a forwarder with no merchant account. It is the
// operator's tool and runs outside the enclave: it holds the operator token and has the gateway issue keys through the
// operator's route, so no measured image knows of it.
package main

import (
	"context"
	"encoding/json"
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

	"github.com/sealedin/gateway/internal/coinpay"
	"github.com/sealedin/gateway/internal/operator"
)

const (
	operatorEnv = "SEALEDIN_OPERATOR_API_KEY"

	defaultListen     = ":8481"
	defaultSite       = "https://sealedin.ai"
	defaultMinUSD     = 20
	defaultMaxUSD     = 500
	defaultRPM        = 60
	defaultQuoteTTL   = time.Hour
	defaultKeepKeys   = 7 * 24 * time.Hour
	defaultKeepUnpaid = 90 * 24 * time.Hour

	callTimeout    = 15 * time.Second
	headerTimeout  = 5 * time.Second
	readTimeout    = 10 * time.Second
	writeTimeout   = 4 * callTimeout // a late quote, a lookup and an issue behind one callback
	idleTimeout    = 60 * time.Second
	shutdownBudget = writeTimeout

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

// options is what the flags say beyond the service's own config.
type options struct {
	gatewayURL  string
	forwarder   string
	payoutsFile string
	ordersFile  string
	keepKeys    time.Duration
	keepUnpaid  time.Duration
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("coinpay", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", defaultListen, "listen address, behind a TLS reverse proxy")
	cfg, opts := coinpay.Config{}, options{}
	flags.StringVar(&cfg.PublicURL, "public-url", "", "this service's own https origin, which the forwarder calls back")
	flags.StringVar(&cfg.SiteURL, "site", defaultSite, "the origin whose pages may call this service")
	flags.Float64Var(&cfg.MinUSD, "min-usd", defaultMinUSD, "the smallest purchase")
	flags.Float64Var(&cfg.MaxUSD, "max-usd", defaultMaxUSD, "the largest credit one payment can buy")
	flags.IntVar(&cfg.RPMLimit, "rpm", defaultRPM, "requests a minute a bought key may make")
	flags.DurationVar(&cfg.QuoteTTL, "quote-ttl", defaultQuoteTTL, "how long an order's price holds")
	flags.StringVar(&opts.gatewayURL, "gateway", "", "the gateway's https origin, whose /v1/keys issues the keys")
	flags.StringVar(&opts.forwarder, "forwarder", coinpay.DefaultPayGateAPI, "the forwarder's API origin")
	flags.StringVar(&opts.payoutsFile, "payouts-file", "", "JSON object of our payout addresses by kind: btc, evm, tron, sol, xmr, ...")
	flags.StringVar(&opts.ordersFile, "orders-file", "coinpay-orders", "file recording the orders")
	flags.DurationVar(&opts.keepKeys, "keep-keys", defaultKeepKeys, "how long a paid order's key stays readable")
	flags.DurationVar(&opts.keepUnpaid, "keep-unpaid", defaultKeepUnpaid, "how long an unpaid order is remembered")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	cfg.PublicURL, opts.gatewayURL = strings.TrimRight(cfg.PublicURL, "/"), strings.TrimRight(opts.gatewayURL, "/")
	handler, err := wire(cfg, opts, logger)
	if err != nil {
		logger.Error("coinpay wiring failed", "err", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: headerTimeout, ReadTimeout: readTimeout,
		WriteTimeout: writeTimeout, IdleTimeout: idleTimeout}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("coinpay listening", "addr", *listen, "min_usd", cfg.MinUSD, "max_usd", cfg.MaxUSD)
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

// wire refuses to start on anything that would send a token or a key over plain HTTP, sell without bounds, or pay out to
// an address it cannot place.
func wire(cfg coinpay.Config, opts options, logger *slog.Logger) (http.Handler, error) {
	token := os.Getenv(operatorEnv)
	switch {
	case token == "":
		return nil, errors.New("set " + operatorEnv)
	case !strings.HasPrefix(cfg.PublicURL, "https://") || !strings.HasPrefix(opts.gatewayURL, "https://") ||
		!strings.HasPrefix(opts.forwarder, "https://"):
		return nil, errors.New("-public-url, -gateway and -forwarder must be https origins")
	case !(cfg.MinUSD > 0) || cfg.MaxUSD < cfg.MinUSD || cfg.RPMLimit <= 0 || cfg.QuoteTTL <= 0:
		return nil, errors.New("-min-usd, -rpm and -quote-ttl must be positive, and -max-usd no less than -min-usd")
	}
	raw, err := os.ReadFile(opts.payoutsFile)
	if err != nil {
		return nil, fmt.Errorf("-payouts-file: %w", err)
	}
	if err = json.Unmarshal(raw, &cfg.Payouts); err != nil {
		return nil, errors.New("-payouts-file: not a JSON object of addresses")
	}
	if err = coinpay.ValidatePayouts(cfg.Payouts); err != nil {
		return nil, err
	}
	store, err := coinpay.OpenStore(opts.ordersFile, opts.keepKeys, opts.keepUnpaid, time.Now())
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: callTimeout}
	forwarder, err := coinpay.NewPayGate(opts.forwarder, client)
	if err != nil {
		return nil, err
	}
	keys := &operator.Client{BaseURL: opts.gatewayURL, Token: token, HTTP: client}
	mux := http.NewServeMux()
	coinpay.New(cfg, forwarder, keys, store, logger).Register(mux)
	return mux, nil
}
