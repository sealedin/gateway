// Package drain sits between the edge and LiteLLM's inference routes and reads every reply to its end, whatever the client
// does: LiteLLM books spend only when a stream completes, so a client hanging up or stalling would otherwise get what it
// read for free. It holds no key but the ones passing through on requests, and logs no content.
package drain

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxBodyBytes bounds a request before it reaches LiteLLM, which reads an unauthenticated body into memory: room for a
// model's whole context plus images, a judgment and not a measurement.
const MaxBodyBytes = 32 << 20

// MaxInFlightBodyBytes bounds all running requests' bodies together, since any key passes the per-key limit: LiteLLM must not
// run out of memory on a tdx.medium's 4 GB. A body of unknown length counts as MaxBodyBytes.
const MaxInFlightBodyBytes = 512 << 20

const bodyBudgetRetryAfter = "1"

const litellmHeaderPrefix = "X-Litellm-"

// credentialHeaders are all the headers the pinned LiteLLM authenticates from, whichever comes first. Only the bearer form
// and x-api-key are accepted here, and one normalized header goes on, so no other header can change what the limit counts.
func credentialHeaders() []string {
	return []string{"Authorization", "API-Key", "X-Api-Key", "X-Goog-Api-Key", "Ocp-Apim-Subscription-Key", "X-Litellm-Api-Key"}
}

// Limits bound a request. Deliver is how long a client may take its copy of the reply: a slow reader holds LiteLLM back
// through backpressure, and past the egress's own limit that would cut LiteLLM before it books, so from then on the reply is
// only read. Upstream is the hard cut, above Deliver so the backlog drains first. Stall is one write to a client before it
// counts as gone. Parallel is how many may run per credential.
type Limits struct {
	Deliver  time.Duration
	Upstream time.Duration
	Stall    time.Duration
	Parallel int
}

// Routes are the inference paths of LiteLLM, all this proxy serves; edge/Caddyfile routes exactly these here.
func Routes() []string {
	return []string{"/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/messages",
		"/v1/messages/count_tokens", "/v1/responses"}
}

type proxy struct {
	reverse *httputil.ReverseProxy
	limits  Limits
	logger  *slog.Logger
	drained atomic.Int64

	slotsMu sync.Mutex
	slots   map[[sha256.Size]byte]int // requests running per credential hash; entries live only while they run
	bodies  int64                     // bytes reserved by running requests
}

// New proxies the inference routes to target.
func New(target *url.URL, limits Limits, logger *slog.Logger) http.Handler {
	p := &proxy{limits: limits, logger: logger, slots: map[[sha256.Size]byte]int{}}
	p.reverse = &httputil.ReverseProxy{
		Rewrite: func(out *httputil.ProxyRequest) {
			out.SetURL(target)
			out.Out.Host = target.Host
		},
		FlushInterval: -1,                         // a stream reaches the client as it is produced
		ErrorLog:      log.New(io.Discard, "", 0), // its messages can quote the request's URL
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			logger.Warn("drain: upstream failed")
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	mux := http.NewServeMux()
	for _, route := range Routes() {
		mux.Handle(route, p)
	}
	return mux
}

// ServeHTTP detaches the upstream from the client, which can then only lose its copy of the reply. Past the limit the
// reverse proxy aborts the handler, cutting both sides.
func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > MaxBodyBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	token, ok := normalizeCredential(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	credential := sha256.Sum256([]byte(token))
	if !p.acquire(credential) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	defer p.release(credential)
	size := r.ContentLength
	if size < 0 {
		size = MaxBodyBytes
	}
	if !p.reserveBody(size) {
		w.Header().Set("Retry-After", bodyBudgetRetryAfter)
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	defer p.releaseBody(size)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), p.limits.Upstream)
	defer cancel()
	client := &clientWriter{ResponseWriter: w, control: http.NewResponseController(w), stall: p.limits.Stall,
		deliverBy: time.Now().Add(p.limits.Deliver)}
	p.reverse.ServeHTTP(client, r.WithContext(ctx))
	client.endOfBody()
	if client.gone {
		p.logger.Info("drain: client left, reply read to its end", "drained_total", p.drained.Add(1))
	}
}

// normalizeCredential reads the one credential that counts and forwards only it, as a bearer, so no other header can change
// which key LiteLLM charges or which count this holds it to. A bearer wins over x-api-key, as at LiteLLM: Claude Code can send
// both, with different values.
func normalizeCredential(r *http.Request) (string, bool) {
	token := r.Header.Get("X-Api-Key")
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		bearer, ok := strings.CutPrefix(authorization, "Bearer ")
		if !ok {
			return "", false
		}
		token = bearer
	}
	if !strings.HasPrefix(token, "sk-") || strings.ContainsAny(token, " \t") {
		return "", false
	}
	for _, header := range credentialHeaders() {
		r.Header.Del(header)
	}
	for header := range r.Header { // LiteLLM's own request controls, the call id the budget guard counts under among them
		if strings.HasPrefix(header, litellmHeaderPrefix) {
			r.Header.Del(header)
		}
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return token, true
}

func (p *proxy) acquire(credential [sha256.Size]byte) bool {
	p.slotsMu.Lock()
	defer p.slotsMu.Unlock()
	if p.slots[credential] >= p.limits.Parallel {
		return false
	}
	p.slots[credential]++
	return true
}

func (p *proxy) release(credential [sha256.Size]byte) {
	p.slotsMu.Lock()
	defer p.slotsMu.Unlock()
	if p.slots[credential]--; p.slots[credential] == 0 {
		delete(p.slots, credential)
	}
}

func (p *proxy) reserveBody(size int64) bool {
	p.slotsMu.Lock()
	defer p.slotsMu.Unlock()
	if p.bodies+size > MaxInFlightBodyBytes {
		return false
	}
	p.bodies += size
	return true
}

func (p *proxy) releaseBody(size int64) {
	p.slotsMu.Lock()
	defer p.slotsMu.Unlock()
	p.bodies -= size
}

// clientWriter gives the client its copy while it takes it, then swallows the rest, so the copy from upstream never stops.
type clientWriter struct {
	http.ResponseWriter

	control   *http.ResponseController
	stall     time.Duration
	deliverBy time.Time
	gone      bool
}

func (c *clientWriter) Write(p []byte) (int, error) {
	c.armDeadline()
	if !c.gone {
		if _, err := c.ResponseWriter.Write(p); err != nil {
			c.gone = true
		}
	}
	return len(p), nil
}

// armDeadline gives the next write the stall limit, never past the delivery limit; once that is past the client is gone.
func (c *clientWriter) armDeadline() {
	now := time.Now()
	if c.gone || !now.Before(c.deliverBy) {
		c.gone = true
		return
	}
	deadline := now.Add(c.stall)
	if deadline.After(c.deliverBy) {
		deadline = c.deliverBy
	}
	c.gone = c.control.SetWriteDeadline(deadline) != nil
}

// endOfBody refreshes the deadline for the terminating chunk the server writes after the handler: quiet before the end of a
// stream must not cost the client a clean finish.
func (c *clientWriter) endOfBody() { c.armDeadline() }

// FlushError is what the reverse proxy flushes through.
func (c *clientWriter) FlushError() error {
	if !c.gone && c.control.Flush() != nil {
		c.gone = true
	}
	return nil
}
