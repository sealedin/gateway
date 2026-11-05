// Package upstream is the provider-neutral contract between the egress HTTP surface and a TEE upstream provider.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	// ErrUnknownModel is returned for a model id the provider does not serve.
	ErrUnknownModel = errors.New("upstream: model not in catalog")
	// ErrNotConfidential is returned for a model the provider does not serve from a TEE.
	ErrNotConfidential = errors.New("upstream: model is not served from a TEE")
	// ErrNoAttestedInstance is returned when no instance currently passes verification.
	ErrNoAttestedInstance = errors.New("upstream: no attested instance available")
)

// Reply is a decrypted upstream reply: JSON for a non-streaming request, SSE for a streaming one.
type Reply struct {
	ContentType string
	Body        io.ReadCloser
}

// Call is what one upstream call reports for its log line: routing and timing, never content, keys or nonces.
type Call struct {
	Chute, Instance  string
	AttestWait       time.Duration
	Sent             time.Time // when the request left; zero if it never did
	FirstByte        time.Time // a reply's headers; for a stream, set by whoever reads the first decrypted chunk
	CompletionTokens *int      // nil until the upstream reports it
}

// Error carries a provider API refusal through to the client with its status.
type Error struct {
	Status int
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("upstream: HTTP %d: %s", e.Status, e.Detail) }

// Provider forwards an OpenAI-compatible request for model to an attested instance, filling call as it goes. Every
// error from Invoke and from reading a Reply's Body is logged, so none may carry content, keys or nonces.
type Provider interface {
	Invoke(ctx context.Context, model, path string, stream bool, body []byte, call *Call) (*Reply, error)
}
