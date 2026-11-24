package coinpay

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	storeFileMode = 0o600
	maxOrderLine  = 64 << 10
)

// Order is one purchase: an address a buyer was shown and, once paid, the key it bought.
type Order struct {
	ID        string    `json:"id"`
	Ticker    string    `json:"ticker"`
	USD       float64   `json:"usd"`        // what the buyer asked to buy
	Amount    string    `json:"amount"`     // the coin amount quoted for it
	Rate      float64   `json:"rate"`       // coin per USD at the quote
	Address   string    `json:"address"`    // where the buyer pays
	ClaimHash string    `json:"claim_hash"` // of the secret that reads the key
	Created   time.Time `json:"created"`

	TxID        string    `json:"txid,omitempty"`
	PaidCoin    string    `json:"paid_coin,omitempty"`
	CreditedUSD float64   `json:"credited_usd,omitempty"`
	PaidAt      time.Time `json:"paid_at,omitzero"`
	Alias       string    `json:"alias,omitempty"`
	Key         string    `json:"key,omitempty"` // kept until Store drops it, so a buyer who closed the page can still read it
}

// Paid reports whether a payment was credited to the order.
func (o *Order) Paid() bool { return o.TxID != "" }

// Store keeps the orders in a file, one JSON record a line, the last record of an order winning.
type Store struct {
	mu     sync.Mutex
	path   string
	orders map[string]Order
}

// OpenStore reads the orders at path and rewrites the file without what time has made useless: the keys of orders paid
// more than keepKeys ago, and orders nobody paid within keepUnpaid. No file yet means no orders.
func OpenStore(path string, keepKeys, keepUnpaid time.Duration, now time.Time) (*Store, error) {
	store := &Store{path: path, orders: map[string]Order{}}
	file, err := os.Open(path) //nolint:gosec // the operator's own path
	switch {
	case errors.Is(err, os.ErrNotExist):
		return store, nil
	case err != nil:
		return nil, fmt.Errorf("orders: %w", err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, maxOrderLine), maxOrderLine)
	for scanner.Scan() {
		var order Order
		if json.Unmarshal(scanner.Bytes(), &order) != nil || order.ID == "" {
			continue // a line cut short by a crash
		}
		store.orders[order.ID] = order
	}
	err = scanner.Err()
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("orders: %w", err)
	}
	for id, order := range store.orders {
		switch {
		case !order.Paid() && now.Sub(order.Created) > keepUnpaid:
			delete(store.orders, id)
		case order.Paid() && now.Sub(order.PaidAt) > keepKeys:
			order.Key = ""
			store.orders[id] = order
		}
	}
	return store, store.rewrite()
}

// rewrite replaces the file with one record per order.
func (s *Store) rewrite() error {
	temp := s.path + ".tmp"
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, storeFileMode) //nolint:gosec // the operator's own path
	if err != nil {
		return fmt.Errorf("orders: %w", err)
	}
	writer := bufio.NewWriter(file)
	for _, order := range s.orders {
		if err = writeOrder(writer, order); err != nil {
			break
		}
	}
	if err == nil {
		err = writer.Flush()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temp, s.path)
	}
	if err != nil {
		return fmt.Errorf("orders: %w", err)
	}
	return nil
}

func writeOrder(writer *bufio.Writer, order Order) error {
	line, err := json.Marshal(order)
	if err != nil {
		return fmt.Errorf("orders: %w", err)
	}
	if _, err = writer.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("orders: %w", err)
	}
	return nil
}

// Get returns the order under id.
func (s *Store) Get(id string) (Order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	order, ok := s.orders[id]
	return order, ok
}

// Put records the order's present state. Memory moves even when the file cannot be written, so a paid order stays paid
// while the process lives.
func (s *Store) Put(order Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orders[order.ID] = order
	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, storeFileMode)
	if err != nil {
		return fmt.Errorf("orders: %w", err)
	}
	writer := bufio.NewWriter(file)
	err = writeOrder(writer, order)
	if err == nil {
		err = writer.Flush()
	}
	if closeErr := file.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("orders: %w", closeErr)
	}
	return err
}
