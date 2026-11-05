// Command drain sits between the edge and LiteLLM's inference routes and reads every reply to its end, so a client hanging
// up or stalling cannot escape metering. Holds no secret and has no route out.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sealedin/gateway/internal/drain"
	"github.com/sealedin/gateway/internal/limits"
)

const (
	defaultListen = ":8477"
	defaultTarget = "http://gateway:4000"
	// upstreamLimit is the hard cut, a minute above the egress's limit, so what a slow reader held back still drains.
	upstreamLimit = limits.UpstreamCall + time.Minute
	// stallLimit is how long one write may block before the client counts as gone: a judgment, not a measurement.
	stallLimit     = 30 * time.Second
	headerTimeout  = 5 * time.Second
	readTimeout    = time.Minute
	idleTimeout    = 3 * time.Minute // above the edge's keep-alive, so the edge never reuses a connection being closed
	shutdownBudget = upstreamLimit   // what is running finishes
	// defaultFlushWait keeps this exit, and so the gateway's, which the compose orders after it, past LiteLLM's spend flush
	// of 10 to 15 seconds: without it a stream finishing at shutdown goes unbilled.
	defaultFlushWait = 25 * time.Second

	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("drain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", defaultListen, "listen address on the compose network, reached only by the edge")
	targetURL := flags.String("gateway", defaultTarget, "LiteLLM base URL")
	flushWait := flags.Duration("flush-wait", defaultFlushWait, "how long to wait after the last reply before exiting")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	handler, err := wire(*targetURL, logger)
	if err != nil {
		logger.Error("drain wiring failed", "err", err)
		return exitUsage
	}
	// No WriteTimeout: a stream may run for the whole upstream limit, and each write has its own stall deadline.
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: headerTimeout, ReadTimeout: readTimeout,
		IdleTimeout: idleTimeout}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe() }()
	logger.Info("drain listening", "addr", *listen)
	select {
	case err = <-serveErr:
		logger.Error("server failed", "err", err)
		return exitError
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
		defer cancel()
		err = server.Shutdown(shutdownCtx) //nolint:contextcheck // the parent context is already done
		time.Sleep(*flushWait)
		if err != nil {
			logger.Error("shutdown failed", "err", err)
			return exitError
		}
		return exitOK
	}
}

func wire(targetURL string, logger *slog.Logger) (http.Handler, error) {
	target, err := url.Parse(targetURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("-gateway must be a base URL, got %q", targetURL)
	}
	bounds := drain.Limits{Deliver: limits.UpstreamCall, Upstream: upstreamLimit, Stall: stallLimit, Parallel: limits.ParallelRequests}
	return drain.New(target, bounds, logger), nil
}
