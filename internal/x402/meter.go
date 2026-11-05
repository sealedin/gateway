package x402

import (
	"sync"
	"time"
)

// DailyFeeCeilingLamports is what the fee payer may spend per UTC day: 500 settlements at MaxFeeLamports, about 1 SOL.
const DailyFeeCeilingLamports = 500 * MaxFeeLamports

// DailyFailureCeilingLamports is the fifth of that which fees not yet known to have bought anything may hold, so griefing
// cannot use up the budget of successful purchases.
const DailyFailureCeilingLamports = 100 * MaxFeeLamports

// FeeMeter is the in-process daily ceiling on fees; a restart zeroes it, which only a crash loop could exploit.
type FeeMeter struct {
	Ceiling        uint64
	FailureCeiling uint64
	Now            func() time.Time

	mu         sync.Mutex
	day        string
	spent      uint64
	unresolved uint64 // reserved and not yet confirmed: failed, dropped or still in flight
}

// Reserve books lamports against today and names the day it booked them on; false past the ceiling. A payer without a settled
// purchase behind it is also held to the failure ceiling, past which a griefer is out of road and known buyers still are not.
func (m *FeeMeter) Reserve(lamports uint64, proven bool) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if today := m.Now().UTC().Format(time.DateOnly); today != m.day {
		m.day, m.spent, m.unresolved = today, 0, 0
	}
	if m.spent+lamports > m.Ceiling || (!proven && m.unresolved+lamports > m.FailureCeiling) {
		return "", false
	}
	m.spent += lamports
	m.unresolved += lamports
	return m.day, true
}

// Refund returns a reservation that cost nothing. One from an earlier day is past caring: today's counters do not hold it.
func (m *FeeMeter) Refund(lamports uint64, day string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if day == m.day {
		m.spent -= min(lamports, m.spent)
		m.unresolved -= min(lamports, m.unresolved)
	}
}

// Resolved marks a reservation as having bought a confirmed payment.
func (m *FeeMeter) Resolved(lamports uint64, day string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if day == m.day {
		m.unresolved -= min(lamports, m.unresolved)
	}
}

// Unresolved is today's total not yet known to have bought anything.
func (m *FeeMeter) Unresolved() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unresolved
}

// Spent is today's booked total, for the logs.
func (m *FeeMeter) Spent() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.spent
}

// Claims is a set whose entries expire: in-flight settlements and spent one-time values.
type Claims struct {
	TTL time.Duration
	Now func() time.Time

	mu      sync.Mutex
	entries map[string]time.Time
}

// Claim adds key, false when it is already present and unexpired.
func (c *Claims) Claim(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.Now()
	for k, expires := range c.entries {
		if now.After(expires) {
			delete(c.entries, k)
		}
	}
	if _, held := c.entries[key]; held {
		return false
	}
	if c.entries == nil {
		c.entries = map[string]time.Time{}
	}
	c.entries[key] = now.Add(c.TTL)
	return true
}

// Held says whether key is present and unexpired.
func (c *Claims) Held(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires, held := c.entries[key]
	return held && !c.Now().After(expires)
}

// Release drops key.
func (c *Claims) Release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}
