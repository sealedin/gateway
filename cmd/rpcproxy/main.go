// Command rpcproxy is the sales service's only path to Solana: an allowlist of JSON-RPC methods to the measured hosts.
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

	"github.com/sealedin/gateway/internal/rpcproxy"
	"github.com/sealedin/gateway/internal/solanarpc"
)

const (
	defaultListen  = ":8475"
	defaultPolicy  = "/policy.yaml"
	apiKeyEnv      = "SOLANA_RPC_API_KEY" //nolint:gosec // the variable's name, not a credential
	callTimeout    = solanarpc.ProxyUpstreamTimeout
	writeTimeout   = callTimeout + 2*time.Second // so a slow host's 502 is not a torn reply
	headerTimeout  = 5 * time.Second
	shutdownBudget = 5 * time.Second

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("rpcproxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", defaultListen, "listen address on the compose network")
	policyPath := flags.String("policy", defaultPolicy, "measured RPC policy (rpcproxy/policy.yaml)")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	handler, err := wire(*policyPath, os.Getenv(apiKeyEnv), logger)
	if err != nil {
		logger.Error("rpcproxy wiring failed", "err", err)
		return exitUsage
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: headerTimeout, ReadTimeout: callTimeout,
		WriteTimeout: writeTimeout}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("rpcproxy listening", "addr", *listen)
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

// wire loads the policy; a placeholder host or a missing key is a startup error, not a stream of 502s.
func wire(policyPath, apiKey string, logger *slog.Logger) (http.Handler, error) {
	f, err := os.Open(policyPath) //nolint:gosec // the operator's -policy path, fixed in the measured image
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	defer func() { _ = f.Close() }()
	policy, err := rpcproxy.LoadPolicy(f)
	if err != nil {
		return nil, err
	}
	if policy.Placeholder() {
		return nil, errors.New("the policy's primary host is still the placeholder")
	}
	return rpcproxy.NewMux(policy, apiKey, newClient(), logger)
}

// newClient talks only to the policy's hosts: no proxy from the environment, no redirects.
func newClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck,forcetypeassert // stdlib type
	transport.Proxy = nil
	return &http.Client{Timeout: callTimeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
