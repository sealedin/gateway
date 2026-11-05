// Package sales sells virtual keys on the TLS site: over x402 at POST /v1/keys/buy and /v1/keys/recover, by a Solana Pay
// transfer at POST /v1/keys/claim. It turns a
// settled payment into a credit at the gateway; everything about the payment itself is internal/x402's.
package sales

import (
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/sealedin/gateway/internal/usage"
	"github.com/sealedin/gateway/internal/x402"
)

const (
	buyRoute     = "/v1/keys/buy"
	recoverRoute = "/v1/keys/recover"

	aliasPrefix    = "x402-"
	aliasHashChars = 32 // 128 bits of the digest
	maxBodyBytes   = 4 << 10

	// Bearer lookups are unauthenticated work at the gateway, so they have their own global bucket.
	lookupsPerSecond = 5
	lookupsBurst     = 20

	reconcileAlertTTL = 24 * time.Hour // a payment still uncredited alerts again daily
)

// AliasFor is the key alias of a payment's digest: one alias per transaction, nameable before anyone signed it.
func AliasFor(digest string) string { return aliasPrefix + digest[:aliasHashChars] }

// Sales holds the routes' state.
type Sales struct {
	gateway *usage.Gateway
	models  []string
	settler *x402.Settler
	logger  *slog.Logger
	lookups *rate.Limiter
	// Transactions already reported for the operator to reconcile.
	reconciling *x402.Claims

	ledgerMu sync.Mutex // a top-up reads a key's budget, then writes it

	issued   atomic.Int64
	toppedUp atomic.Int64
	rejected atomic.Int64
}

// New wires the routes.
func New(gateway *usage.Gateway, models []string, settler *x402.Settler, logger *slog.Logger) *Sales {
	return &Sales{gateway: gateway, models: models, settler: settler, logger: logger,
		lookups: rate.NewLimiter(lookupsPerSecond, lookupsBurst), reconciling: &x402.Claims{TTL: reconcileAlertTTL, Now: time.Now}}
}

// Register mounts the routes on mux.
func (s *Sales) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+buyRoute, s.buy)
	mux.HandleFunc("POST "+recoverRoute, s.recoverKey)
	mux.HandleFunc("POST "+claimRoute, s.claim)
}
