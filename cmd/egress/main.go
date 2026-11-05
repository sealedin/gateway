// Command egress is LiteLLM's only upstream: each request goes E2EE to a TEE instance verified against the policy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sealedin/gateway/internal/egress"
	"github.com/sealedin/gateway/internal/egress/chutes"
	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/limits"
	"github.com/sealedin/gateway/internal/teeverify/nvidia"
	"github.com/sealedin/gateway/internal/teeverify/tdx"
)

const (
	defaultListen   = ":8474"
	defaultPolicy   = "/policy.yaml"
	apiKeyEnv       = "CHUTES_API_KEY"    //nolint:gosec // the variable's name, not a credential
	upstreamTimeout = limits.UpstreamCall // one call end to end, streaming included
	verifierTimeout = time.Minute         // one attestation-side call (catalog, NRAS)
	headerTimeout   = 10 * time.Second
	readTimeout     = time.Minute
	idleTimeout     = 2 * time.Minute
	shutdownBudget  = 15 * time.Second
	writeMargin     = 30 * time.Second // past the upstream's cut, so the closing usage of a cut stream still gets out

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("egress", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", defaultListen, "listen address on the compose network")
	policyPath := flags.String("policy", defaultPolicy, "measured upstream policy (egress/policy.yaml)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	handler, err := wire(*policyPath, os.Getenv(apiKeyEnv), logger)
	if err != nil {
		logger.Error("egress wiring failed", "err", err)
		return exitUsage
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: headerTimeout, ReadTimeout: readTimeout,
		WriteTimeout: upstreamTimeout + writeMargin, IdleTimeout: idleTimeout}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("egress listening", "addr", *listen)
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

// wire builds the provider from the policy; an unset API key is a startup error, not a runtime 503.
func wire(policyPath, apiKey string, logger *slog.Logger) (http.Handler, error) {
	if apiKey == "" {
		return nil, errors.New(apiKeyEnv + " is not set")
	}
	f, err := os.Open(policyPath) //nolint:gosec // the operator's -policy path, fixed in the measured compose
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	defer func() { _ = f.Close() }()
	policy, err := egress.LoadPolicy(f)
	if err != nil {
		return nil, err
	}
	verifier := &chutes.Verifier{
		TDX:    tdx.Verifier{Getter: tdx.HTTPGetter(newClient(verifierTimeout)), Now: time.Now},
		NRAS:   nvidia.NewNRAS(nvidia.DefaultAttestURL, nvidia.DefaultJWKSURL, newClient(verifierTimeout)),
		Policy: policy.Upstream,
		Now:    time.Now,
	}
	attester, err := chutes.NewAttester(policy.Hosts.API, apiKey, newClient(verifierTimeout), verifier,
		policy.ReattestInterval, logger)
	if err != nil {
		return nil, err
	}
	catalog := chutes.NewCatalog(policy.Hosts.Catalog, newClient(verifierTimeout))
	provider := chutes.NewProvider(policy.Hosts.API, apiKey, newClient(upstreamTimeout), catalog, attester)
	logger.Info("egress policy loaded", "provider", policy.Provider, "api", policy.Hosts.API,
		"reattest_interval", policy.ReattestInterval, "images", len(policy.Upstream.TDX.Images))
	return egress.NewMux(provider, gateway.MaxOutputTokens(), logger), nil
}

// newClient talks only to the hosts the policy names: no proxy from the environment, no redirects.
func newClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck,forcetypeassert // stdlib type
	transport.Proxy = nil
	return &http.Client{Timeout: timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
