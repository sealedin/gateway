package near

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sealedin/gateway/internal/egress/upstream"
)

const (
	maxReply        = 64 << 20
	maxRefusal      = 1 << 20
	idleConnTimeout = 90 * time.Second
	maxIdleConns    = 16
	routeName       = "near-gateway" // the log's routing field: the attestation covers the router, not an instance
)

// Provider forwards requests to the provider's gateway over attested connections. A connection is used for at most
// Lifetime plus one request before a fresh one attests again.
type Provider struct {
	api      string
	apiKey   string
	timeout  time.Duration
	lifetime time.Duration
	dialer   *dialer
	now      func() time.Time

	mu     sync.Mutex
	client *http.Client
	born   time.Time
}

// Options are NewProvider's inputs.
type Options struct {
	APIKey   string
	Verifier *Verifier
	Timeout  time.Duration // one call end to end, streaming included
	Lifetime time.Duration // how long a pool of attested connections is used
	Roots    *x509.CertPool
	Log      *slog.Logger
	Now      func() time.Time
}

// NewProvider builds a provider for the policy's API origin.
func NewProvider(o Options) (*Provider, error) {
	if err := o.Verifier.Policy.Validate(); err != nil {
		return nil, err
	}
	if o.APIKey == "" || o.Lifetime <= 0 {
		return nil, errors.New("near: an API key and a positive connection lifetime are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Provider{api: o.Verifier.Policy.API, apiKey: o.APIKey, timeout: o.Timeout, lifetime: o.Lifetime, now: o.Now,
		dialer: &dialer{verifier: o.Verifier, roots: o.Roots, log: o.Log}}, nil
}

// current returns the client whose pool is still within its lifetime, retiring the previous pool: its idle connections
// close now and those mid-request close once idle.
func (p *Provider) current() *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client != nil && p.now().Sub(p.born) < p.lifetime {
		return p.client
	}
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
	// No proxy, no HTTP/2 and no dialer but ours: every connection this client can use has attested itself.
	transport := &http.Transport{DialTLSContext: p.dialer.DialTLS, MaxIdleConnsPerHost: maxIdleConns,
		IdleConnTimeout: idleConnTimeout, DisableCompression: true}
	p.client = &http.Client{Timeout: p.timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	p.born = p.now()
	return p.client
}

// Invoke sends body as is: the gateway speaks the OpenAI format and model is its own id for the model.
func (p *Provider) Invoke(ctx context.Context, _, path string, stream bool, body []byte,
	call *upstream.Call) (*upstream.Reply, error) {
	call.Chute = routeName
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.api+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("near: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	// The request must fail rather than be served by another model under an alias.
	req.Header.Set("X-No-Aliasing", "true")
	call.Sent = time.Now()
	resp, err := p.current().Do(req)
	if err != nil {
		return nil, sendError(err)
	}
	if !stream {
		call.FirstByte = time.Now()
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxRefusal))
		// The refusal may quote the prompt, so only its size is kept.
		return nil, &upstream.Error{Status: resp.StatusCode, Detail: fmt.Sprintf("withheld, %d bytes", len(detail))}
	}
	if stream {
		return &upstream.Reply{ContentType: "text/event-stream", Body: resp.Body}, nil
	}
	defer func() { _ = resp.Body.Close() }()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if err != nil {
		return nil, fmt.Errorf("near: read reply: %w", err)
	}
	if len(reply) > maxReply {
		return nil, fmt.Errorf("near: reply exceeds %d bytes", maxReply)
	}
	call.CompletionTokens = completionTokens(reply)
	return &upstream.Reply{ContentType: "application/json", Body: io.NopCloser(bytes.NewReader(reply))}, nil
}

// sendError turns a connection the attestation refused into the no-attested-instance refusal.
func sendError(err error) error {
	if failure, isURL := errors.AsType[*url.Error](err); isURL {
		err = failure.Err
	}
	if _, refused := errors.AsType[*CheckError](err); refused {
		return fmt.Errorf("%w: %w", upstream.ErrNoAttestedInstance, err)
	}
	return fmt.Errorf("near: send: %w", err)
}

// completionTokens reads only the count; a reply without one logs without one.
func completionTokens(reply []byte) *int {
	var parsed struct {
		Usage struct {
			CompletionTokens *int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(reply, &parsed) != nil {
		return nil
	}
	return parsed.Usage.CompletionTokens
}
