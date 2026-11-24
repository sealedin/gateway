// Package operator is the client of the gateway's operator key issuance, the route a hand-issued key takes. The services
// that run outside the enclave hold the operator token and issue keys through it, so no measured image knows of them.
package operator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const maxReplyBytes = 64 << 10

// Client calls the gateway as the operator.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Exists reports whether a key was ever issued under alias.
func (c *Client) Exists(ctx context.Context, alias string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/keys/"+alias, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("operator: lookup: %w", err)
	}
	status, err := c.do(req, nil)
	switch {
	case err != nil:
		return false, err
	case status == http.StatusOK:
		return true, nil
	case status == http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("operator: lookup: status %d", status)
}

// Issue creates the key under alias and returns its value, which the gateway shows this once.
func (c *Client) Issue(ctx context.Context, alias string, budgetUSD float64, rpm int) (string, error) {
	body, err := json.Marshal(map[string]any{"alias": alias, "max_budget_usd": budgetUSD, "rpm_limit": rpm})
	if err != nil {
		return "", fmt.Errorf("operator: issue: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/keys", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("operator: issue: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	var reply struct {
		Key string `json:"key"`
	}
	status, err := c.do(req, &reply)
	switch {
	case err != nil:
		return "", err
	case status != http.StatusOK:
		return "", fmt.Errorf("operator: issue: status %d", status)
	case reply.Key == "":
		return "", errors.New("operator: issue: reply carries no key")
	}
	return reply.Key, nil
}

func (c *Client) do(req *http.Request, reply any) (int, error) {
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("operator: %s: %w", req.Method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if reply == nil || resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxReplyBytes)).Decode(reply); err != nil {
		return 0, errors.New("operator: invalid reply")
	}
	return resp.StatusCode, nil
}
