package bonus

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

const ledgerFileMode = 0o600

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
