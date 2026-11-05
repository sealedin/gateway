// Package rpcproxy is the sales service's only path to Solana: an allowlist of JSON-RPC methods forwarded to the hosts of
// a measured policy, holding the provider's API key so the sales service never does.
package rpcproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sealedin/gateway/internal/httpjson"
	"github.com/sealedin/gateway/internal/solanarpc"
)

const (
	maxRequestBytes = 16 << 10 // a 1232-byte transaction in base64 with its options
	maxReplyBytes   = 4 << 20
	placeholderTLD  = ".invalid"
)

// Host is one RPC endpoint; APIKeyParam names the query parameter its API key travels in, empty for none.
type Host struct {
	URL         string `yaml:"url"`
	APIKeyParam string `yaml:"api_key_param"`
}

// Policy names the two hosts.
type Policy struct {
	Primary      Host `yaml:"primary"`
	Confirmation Host `yaml:"confirmation"`
}

// LoadPolicy reads and validates a policy file; a host outside the measured form is a startup error.
func LoadPolicy(r io.Reader) (Policy, error) {
	var policy Policy
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("rpcproxy: policy: %w", err)
	}
	primary, err := checkHost(policy.Primary.URL)
	if err != nil {
		return Policy{}, err
	}
	confirmation, err := checkHost(policy.Confirmation.URL)
	if err != nil {
		return Policy{}, err
	}
	if primary == confirmation {
		return Policy{}, errors.New("rpcproxy: the confirmation host must be independent of the primary")
	}
	if policy.Confirmation.APIKeyParam != "" {
		return Policy{}, errors.New("rpcproxy: the provider's key goes to the primary only")
	}
	return policy, nil
}

func checkHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("rpcproxy: host: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return "", fmt.Errorf("rpcproxy: host %q must be a plain https URL", raw)
	}
	return u.Host, nil
}

// Placeholder says whether the primary is still the placeholder host, which never resolves.
func (p Policy) Placeholder() bool {
	u, err := url.Parse(p.Primary.URL)
	return err != nil || strings.HasSuffix(u.Hostname(), placeholderTLD)
}

// call is the whole of what is forwarded: the body is rebuilt from it, so what the allowlist read is what goes out.
type call struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type route struct {
	target  string
	methods []string
	client  *http.Client
	logger  *slog.Logger
}

// NewMux mounts the two routes; apiKey must be present when the primary's policy names a parameter for it.
func NewMux(policy Policy, apiKey string, client *http.Client, logger *slog.Logger) (*http.ServeMux, error) {
	target, err := url.Parse(policy.Primary.URL)
	if err != nil {
		return nil, fmt.Errorf("rpcproxy: primary: %w", err)
	}
	if param := policy.Primary.APIKeyParam; param != "" {
		if apiKey == "" {
			return nil, errors.New("rpcproxy: the policy names an API key parameter but no key is set")
		}
		target.RawQuery = url.Values{param: {apiKey}}.Encode()
	}
	primary := &route{target: target.String(), client: client, logger: logger, methods: []string{solanarpc.MethodLatestBlockhash,
		solanarpc.MethodSimulate, solanarpc.MethodSend, solanarpc.MethodSignatureStatuses, solanarpc.MethodTransaction,
		solanarpc.MethodSignaturesForAddress}}
	confirmation := &route{target: policy.Confirmation.URL, client: client, logger: logger,
		methods: []string{solanarpc.MethodSignatureStatuses}}
	mux := http.NewServeMux()
	mux.Handle("POST "+solanarpc.PrimaryRoute, primary)
	mux.Handle("POST "+solanarpc.ConfirmationRoute, confirmation)
	return mux, nil
}

func (rt *route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req call
	if err := httpjson.DecodeStrict(r, maxRequestBytes, &req); err != nil {
		httpjson.Error(w, http.StatusBadRequest, "not one JSON-RPC call")
		return
	}
	if !slices.Contains(rt.methods, req.Method) {
		rt.logger.Warn("rpcproxy: method refused", "method", req.Method)
		httpjson.Error(w, http.StatusForbidden, "method not allowed")
		return
	}
	body, err := json.Marshal(req)
	if err != nil {
		httpjson.Error(w, http.StatusBadRequest, "not one JSON-RPC call")
		return
	}
	rt.forward(w, r, req.Method, body)
}

func (rt *route) forward(w http.ResponseWriter, r *http.Request, method string, body []byte) {
	out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, rt.target, bytes.NewReader(body))
	if err != nil {
		rt.fail(w, method, err)
		return
	}
	out.Header.Set("Content-Type", "application/json")
	resp, err := rt.client.Do(out)
	if err != nil {
		rt.fail(w, method, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(w, io.LimitReader(resp.Body, maxReplyBytes)); err != nil {
		rt.logger.Warn("rpcproxy: reply cut short", "method", method, "err", scrub(err))
	}
}

func (rt *route) fail(w http.ResponseWriter, method string, err error) {
	rt.logger.Warn("rpcproxy: upstream failed", "method", method, "err", scrub(err))
	httpjson.Error(w, http.StatusBadGateway, "upstream unavailable")
}

// scrub drops the URL an http.Client error quotes: it carries the API key.
func scrub(err error) error {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		return urlErr.Err
	}
	return err
}
