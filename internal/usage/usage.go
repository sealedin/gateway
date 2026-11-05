// Package usage provisions keys and reads per-key spend through the LiteLLM admin API.
package usage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sealedin/gateway/internal/limits"
)

// maxReplyBytes bounds what the admin client reads back: a key object is a few KB, a page of /key/list a few tens.
const maxReplyBytes = 1 << 20

const (
	// MasterKeyPath is the guest agent derivation path of the LiteLLM master key: the KMS derives per app id and path,
	// so one path is one key for the app's lifetime and rotation means a new version suffix here.
	MasterKeyPath = "sealedin/litellm-master/v1"
	// MasterKeyPurpose labels that derivation for the agent.
	MasterKeyPurpose = "litellm master key"
	// DefaultRPMLimit is the rate limit of a key whose issuer names none.
	DefaultRPMLimit = 60
	// aliasField is LiteLLM's name for the key alias in bodies, replies and the /key/list filter.
	aliasField = "key_alias"
)

// ErrKeyUnknown means the gateway has no key under that alias.
var ErrKeyUnknown = errors.New("usage: key not known to the gateway")

// FormatMasterKey is the master key as LiteLLM expects it: the sk- prefix and the 64 hex chars of the derived bytes.
func FormatMasterKey(raw [32]byte) string {
	return "sk-" + hex.EncodeToString(raw[:])
}

// Gateway is an admin client of one LiteLLM instance.
type Gateway struct {
	BaseURL   string
	MasterKey string
	HTTP      *http.Client
}

// KeyLimits bounds an issued key: MaxBudgetUSD caps lifetime spend, Models is the scope, RPMLimit the rate. Key names the
// key's value instead of leaving it to LiteLLM, Metadata records what it is for, and Blocked creates it unusable.
type KeyLimits struct {
	MaxBudgetUSD float64
	Models       []string
	RPMLimit     int
	Metadata     map[string]any
	Key          string
	Blocked      bool
}

// IssuedKey is the reply of /key/generate; with a caller-named key it can echo a request whose row already existed.
type IssuedKey struct {
	Key          string
	Alias        string
	MaxBudgetUSD float64
	RPMLimit     int
	Models       []string
}

// KeyInfo is one key as the gateway holds it; Token is its hash, the handle that needs no secret.
type KeyInfo struct {
	Alias        string
	Token        string
	SpendUSD     float64
	MaxBudgetUSD float64
	RPMLimit     int
	Models       []string
	Metadata     map[string]any
	Blocked      bool
}

// keyFields is a key object as /key/info and /key/list carry it.
type keyFields struct {
	Token     string         `json:"token"`
	KeyAlias  string         `json:"key_alias"`
	Spend     float64        `json:"spend"`
	MaxBudget float64        `json:"max_budget"`
	RPMLimit  int            `json:"rpm_limit"`
	Models    []string       `json:"models"`
	Metadata  map[string]any `json:"metadata"`
	Blocked   bool           `json:"blocked"`
}

func (k keyFields) info() KeyInfo {
	return KeyInfo{Alias: k.KeyAlias, Token: k.Token, SpendUSD: k.Spend, MaxBudgetUSD: k.MaxBudget, RPMLimit: k.RPMLimit,
		Models: k.Models, Metadata: k.Metadata, Blocked: k.Blocked}
}

// TokenHash is the handle LiteLLM keeps a key under: the SHA-256 of a raw sk- key, anything else already being a hash.
func TokenHash(key string) string {
	if !strings.HasPrefix(key, "sk-") {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// statusError is a non-200 from the admin API.
type statusError struct {
	path string
	code int
}

func (e *statusError) Error() string { return fmt.Sprintf("usage: %s: status %d", e.path, e.code) }

// Issue creates a key under alias within limits: no budget_duration (prepaid credits never reset), nothing else.
func (g *Gateway) Issue(ctx context.Context, alias string, bounds KeyLimits) (IssuedKey, error) {
	body := map[string]any{
		aliasField:              alias,
		"max_budget":            bounds.MaxBudgetUSD,
		"rpm_limit":             bounds.RPMLimit,
		"models":                bounds.Models,
		"max_parallel_requests": limits.ParallelRequests,
	}
	if bounds.Metadata != nil {
		body["metadata"] = bounds.Metadata
	}
	if bounds.Key != "" {
		body["key"] = bounds.Key
	}
	if bounds.Blocked {
		body["blocked"] = true
	}
	var reply struct {
		Key       string   `json:"key"`
		KeyAlias  string   `json:"key_alias"`
		MaxBudget float64  `json:"max_budget"`
		RPMLimit  int      `json:"rpm_limit"`
		Models    []string `json:"models"`
	}
	if err := g.post(ctx, "/key/generate", body, &reply); err != nil {
		return IssuedKey{}, err
	}
	if reply.Key == "" {
		return IssuedKey{}, errors.New("usage: key/generate: reply carries no key")
	}
	return IssuedKey{Key: reply.Key, Alias: reply.KeyAlias, MaxBudgetUSD: reply.MaxBudget, RPMLimit: reply.RPMLimit,
		Models: reply.Models}, nil
}

// LookupAlias reads the key named alias through /key/list (exact alias match); ErrKeyUnknown when no key carries it.
func (g *Gateway) LookupAlias(ctx context.Context, alias string) (KeyInfo, error) {
	query := url.Values{aliasField: {alias}, "return_full_object": {"true"}}
	var reply struct {
		Keys []keyFields `json:"keys"`
	}
	if err := g.get(ctx, "/key/list", query, &reply); err != nil {
		return KeyInfo{}, err
	}
	for _, k := range reply.Keys {
		if k.KeyAlias == alias {
			return k.info(), nil
		}
	}
	return KeyInfo{}, ErrKeyUnknown
}

// LookupKey reads a key by its raw value or its token hash through /key/info; ErrKeyUnknown when there is none. Only the
// hash travels: a raw key in a query string would reach LiteLLM's access log.
func (g *Gateway) LookupKey(ctx context.Context, key string) (KeyInfo, error) {
	var reply struct {
		Info keyFields `json:"info"`
	}
	token := TokenHash(key)
	err := g.get(ctx, "/key/info", url.Values{"key": {token}}, &reply)
	if status, ok := errors.AsType[*statusError](err); ok && status.code == http.StatusNotFound {
		return KeyInfo{}, ErrKeyUnknown
	}
	if err != nil {
		return KeyInfo{}, err
	}
	reply.Info.Token = token // /key/info strips the hash from its reply
	return reply.Info.info(), nil
}

// SetBudget changes one key's budget and replaces its whole metadata in one update, given raw or as its token hash.
func (g *Gateway) SetBudget(ctx context.Context, key string, budgetUSD float64, metadata map[string]any) error {
	var reply struct{}
	return g.post(ctx, "/key/update", map[string]any{"key": key, "max_budget": budgetUSD, "metadata": metadata}, &reply)
}

// scrubURL drops the URL an http.Client error quotes, query string included.
func scrubURL(err error) error {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		return urlErr.Err
	}
	return err
}

// post sends body and decodes the 200 response into reply.
func (g *Gateway) post(ctx context.Context, path string, body map[string]any, reply any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("usage: encode %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.BaseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("usage: %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	return g.do(req, path, reply)
}

func (g *Gateway) get(ctx context.Context, path string, query url.Values, reply any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.BaseURL+path+"?"+query.Encode(), nil)
	if err != nil {
		return fmt.Errorf("usage: %s: %w", path, err)
	}
	return g.do(req, path, reply)
}

func (g *Gateway) do(req *http.Request, path string, reply any) error {
	req.Header.Set("Authorization", "Bearer "+g.MasterKey)
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("usage: %s: %w", path, scrubURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &statusError{path: path, code: resp.StatusCode}
	}
	if decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxReplyBytes)).Decode(reply); decodeErr != nil {
		return fmt.Errorf("usage: %s: decode: %w", path, decodeErr)
	}
	return nil
}
