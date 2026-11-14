package egress

import (
	"context"

	"github.com/sealedin/gateway/internal/egress/upstream"
)

// Dispatcher sends each model to the provider of its family: the ones ByModel lists, and Default for every other.
type Dispatcher struct {
	Default upstream.Provider
	ByModel map[string]upstream.Provider
}

// Invoke forwards to the model's provider unchanged.
func (d Dispatcher) Invoke(ctx context.Context, model, path string, stream bool, body []byte,
	call *upstream.Call) (*upstream.Reply, error) {
	if provider, listed := d.ByModel[model]; listed {
		return provider.Invoke(ctx, model, path, stream, body, call)
	}
	return d.Default.Invoke(ctx, model, path, stream, body, call)
}
