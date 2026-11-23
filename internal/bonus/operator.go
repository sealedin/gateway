package bonus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

const ledgerFileMode = 0o600

// Operator is the client of the gateway's operator key issuance, the same route a hand-issued key takes.
type Operator struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// Exists reports whether a key was ever issued under alias.
func (o *Operator) Exists(ctx context.Context, alias string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"/v1/keys/"+alias, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("operator: lookup: %w", err)
	}
	status, err := o.do(req, nil)
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
func (o *Operator) Issue(ctx context.Context, alias string, budgetUSD float64, rpm int) (string, error) {
	body, err := json.Marshal(map[string]any{"alias": alias, "max_budget_usd": budgetUSD, "rpm_limit": rpm})
	if err != nil {
		return "", fmt.Errorf("operator: issue: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.BaseURL+"/v1/keys", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("operator: issue: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	var reply struct {
		Key string `json:"key"`
	}
	status, err := o.do(req, &reply)
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

func (o *Operator) do(req *http.Request, reply any) (int, error) {
	req.Header.Set("Authorization", "Bearer "+o.Token)
	resp, err := o.HTTP.Do(req)
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

// Ledger is the list of aliases given a bonus, one a line: the promotion's cap survives a restart through it.
type Ledger struct {
	mu    sync.Mutex
	path  string
	count int
}

// OpenLedger reads how many bonuses the file at path records; no file yet means none.
func OpenLedger(path string) (*Ledger, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's own path
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	return &Ledger{path: path, count: len(strings.Fields(string(raw)))}, nil
}

// Count is how many bonuses were given.
func (l *Ledger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// Add records one more. The count moves even when the file cannot be written, so the cap holds while the process lives.
func (l *Ledger) Add(alias string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.count++
	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, ledgerFileMode)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	if _, err = file.WriteString(alias + "\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("ledger: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	return nil
}
