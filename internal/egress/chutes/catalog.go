// Package chutes resolves models to TEE chutes, verifies each instance's evidence and sends requests E2EE to its key.
package chutes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sealedin/gateway/internal/egress/upstream"
)

const (
	catalogTTL     = 5 * time.Minute
	catalogMinAge  = 30 * time.Second // rate-limits refetches triggered by unknown model ids
	catalogGrace   = time.Hour        // a known model keeps resolving from a stale catalog this long
	maxBody        = 8 << 20
	modelsPath     = "/v1/models"
	invokePath     = "/e2e/invoke"
	nonceByteLen   = 32
	evidenceBudget = 90 * time.Second
)

func instancesURL(api, chuteID string) string {
	return api + "/e2e/instances/" + url.PathEscape(chuteID)
}

func evidenceURL(api, chuteID, nonce string) string {
	return api + "/chutes/" + url.PathEscape(chuteID) + "/evidence?nonce=" + nonce
}

// Catalog resolves model ids to chute ids and refuses anything not flagged confidential.
type Catalog struct {
	base   string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	entries   map[string]catalogEntry
	fetchedAt time.Time
}

type catalogEntry struct {
	ChuteID      string `json:"chute_id"`
	Confidential bool   `json:"confidential_compute"`
}

// NewCatalog returns a catalog backed by base (the llm.chutes.ai host).
func NewCatalog(base string, client *http.Client) *Catalog {
	return &Catalog{base: base, client: client, now: time.Now}
}

// Resolve returns the chute id serving model; a failed refresh keeps serving known models for catalogGrace.
func (c *Catalog) Resolve(ctx context.Context, model string) (string, error) {
	entries, age := c.snapshot()
	entry, ok := entries[model]
	if (!ok && age > catalogMinAge) || age > catalogTTL {
		fresh, err := c.refresh(ctx)
		switch {
		case err == nil:
			entry, ok = fresh[model]
		case !ok || age > catalogTTL+catalogGrace:
			return "", err
		}
	}
	switch {
	case !ok:
		return "", fmt.Errorf("%w: %q", upstream.ErrUnknownModel, model)
	case !entry.Confidential:
		return "", fmt.Errorf("%w: %q", upstream.ErrNotConfidential, model)
	case entry.ChuteID == "":
		return "", fmt.Errorf("%w: %q has no chute id", upstream.ErrUnknownModel, model)
	}
	return entry.ChuteID, nil
}

func (c *Catalog) snapshot() (map[string]catalogEntry, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries, c.now().Sub(c.fetchedAt)
}

func (c *Catalog) refresh(ctx context.Context) (map[string]catalogEntry, error) {
	body, err := get(ctx, c.client, c.base+modelsPath, "")
	if err != nil {
		return nil, fmt.Errorf("chutes: catalog: %w", err)
	}
	var list struct {
		Data []struct {
			catalogEntry

			ID string `json:"id"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("chutes: catalog: %w", err)
	}
	entries := make(map[string]catalogEntry, len(list.Data))
	for _, m := range list.Data {
		entries[m.ID] = m.catalogEntry
	}
	c.mu.Lock()
	c.entries, c.fetchedAt = entries, c.now()
	c.mu.Unlock()
	return entries, nil
}

func get(ctx context.Context, client *http.Client, target, apiKey string) ([]byte, error) {
	// Errors reach the log and the caller, and the query of an evidence URL is the attestation nonce.
	path, _, _ := strings.Cut(target, "?")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		if failure, isURL := errors.AsType[*url.Error](err); isURL {
			return nil, fmt.Errorf("GET %s: %w", path, failure.Err)
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", path, maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return body, nil
}
