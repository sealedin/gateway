package chutes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/sealedin/gateway/internal/egress/upstream"
)

const (
	verifyWorkers    = 8                // each verification is a DCAP check plus an NRAS round trip
	nonceSafety      = 5 * time.Second  // nonces this close to expiry are discarded
	nonceTTLFallback = 55 * time.Second // when the API omits nonce_expires_in (documented as 60)
	refreshBackoff   = 10 * time.Second
)

// Target is one request's destination: a verified instance and a single-use invocation nonce.
type Target struct {
	ChuteID    string
	InstanceID string
	Pubkey     string
	Nonce      string
}

// InstanceVerifier is the per-instance check; *Verifier in production, a stub in attester tests.
type InstanceVerifier interface {
	Verify(ctx context.Context, ev Evidence, nonceHex, pubkeyB64 string) (*Verified, error)
}

// Attester keeps per chute the verified instances and the nonce pool, re-attesting on interval, expiry or key change.
type Attester struct {
	api      string
	apiKey   string
	get      getter
	verifier InstanceVerifier
	interval time.Duration
	now      func() time.Time
	log      *slog.Logger

	mu     sync.Mutex
	chutes map[string]*chuteState
}

type getter func(ctx context.Context, url, apiKey string) ([]byte, error)

type chuteState struct {
	mu         sync.Mutex
	verified   map[string]*Verified
	pool       []poolInstance
	poolEnd    time.Time
	lastFailed time.Time
	lastErr    error
}

type poolInstance struct {
	id     string
	pubkey string
	nonces []string
}

type e2eInstances struct {
	Instances []struct {
		InstanceID string   `json:"instance_id"`
		Pubkey     string   `json:"e2e_pubkey"`
		Nonces     []string `json:"nonces"`
	} `json:"instances"`
	NonceExpiresIn int `json:"nonce_expires_in"`
}

// NewAttester returns an attester for the Chutes API at api, re-attesting every interval.
func NewAttester(api, apiKey string, client *http.Client, verifier InstanceVerifier, interval time.Duration,
	log *slog.Logger) (*Attester, error) {
	if interval <= 0 {
		return nil, errors.New("chutes: re-attestation interval must be positive")
	}
	get := func(ctx context.Context, url, apiKey string) ([]byte, error) { return get(ctx, client, url, apiKey) }
	return &Attester{api: api, apiKey: apiKey, get: get, verifier: verifier, interval: interval, now: time.Now, log: log,
		chutes: map[string]*chuteState{}}, nil
}

// Take returns a verified instance of chuteID with a single-use nonce; it fails closed.
func (a *Attester) Take(ctx context.Context, chuteID string) (Target, error) {
	state := a.state(chuteID)
	state.mu.Lock()
	defer state.mu.Unlock()
	if target, ok := a.take(state, chuteID); ok {
		return target, nil
	}
	if a.now().Sub(state.lastFailed) < refreshBackoff {
		return Target{}, fmt.Errorf("%w: chute %s: last refresh failed: %w", upstream.ErrNoAttestedInstance, chuteID, state.lastErr)
	}
	// The refresh serves every waiter on this chute, so the first caller's cancellation must not abort it.
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), evidenceBudget)
	defer cancel()
	if err := a.refresh(refreshCtx, state, chuteID); err != nil {
		state.lastFailed, state.lastErr = a.now(), err
		return Target{}, err
	}
	if target, ok := a.take(state, chuteID); ok {
		return target, nil
	}
	return Target{}, fmt.Errorf("%w: chute %s", upstream.ErrNoAttestedInstance, chuteID)
}

func (a *Attester) state(chuteID string) *chuteState {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, ok := a.chutes[chuteID]
	if !ok {
		state = &chuteState{verified: map[string]*Verified{}}
		a.chutes[chuteID] = state
	}
	return state
}

func (a *Attester) take(state *chuteState, chuteID string) (Target, bool) {
	now := a.now()
	if now.After(state.poolEnd) {
		return Target{}, false
	}
	for i := range state.pool {
		inst := &state.pool[i]
		if len(inst.nonces) == 0 || !a.current(state.verified[inst.id], inst.pubkey, now) {
			continue
		}
		nonce := inst.nonces[0]
		inst.nonces = inst.nonces[1:]
		return Target{ChuteID: chuteID, InstanceID: inst.id, Pubkey: inst.pubkey, Nonce: nonce}, true
	}
	return Target{}, false
}

func (a *Attester) current(v *Verified, pubkey string, now time.Time) bool {
	return v != nil && v.Pubkey == pubkey && now.Before(v.ExpiresAt) && now.Sub(v.VerifiedAt) < a.interval
}

func (a *Attester) refresh(ctx context.Context, state *chuteState, chuteID string) error {
	body, err := a.get(ctx, instancesURL(a.api, chuteID), a.apiKey)
	if err != nil {
		return fmt.Errorf("chutes: instances for %s: %w", chuteID, err)
	}
	var listed e2eInstances
	if err = json.Unmarshal(body, &listed); err != nil {
		return fmt.Errorf("chutes: instances for %s: %w", chuteID, err)
	}
	ttl := nonceTTLFallback
	if listed.NonceExpiresIn > 0 {
		ttl = time.Duration(listed.NonceExpiresIn) * time.Second
	}
	now := a.now()
	pool := make([]poolInstance, 0, len(listed.Instances))
	stale := map[string]string{}
	for _, inst := range listed.Instances {
		if inst.Pubkey == "" || len(inst.Nonces) == 0 {
			continue
		}
		pool = append(pool, poolInstance{id: inst.InstanceID, pubkey: inst.Pubkey, nonces: inst.Nonces})
		if !a.current(state.verified[inst.InstanceID], inst.Pubkey, now) {
			stale[inst.InstanceID] = inst.Pubkey
		}
	}
	if len(stale) > 0 {
		if err = a.attest(ctx, state, chuteID, stale); err != nil {
			return err
		}
	}
	state.pool, state.poolEnd = pool, now.Add(ttl-nonceSafety)
	return nil
}

func (a *Attester) attest(ctx context.Context, state *chuteState, chuteID string, stale map[string]string) error {
	nonce, err := NewNonce()
	if err != nil {
		return err
	}
	body, err := a.get(ctx, evidenceURL(a.api, chuteID, nonce), a.apiKey)
	if err != nil {
		return fmt.Errorf("chutes: evidence for %s: %w", chuteID, err)
	}
	var evidence struct {
		Evidence []Evidence `json:"evidence"`
	}
	if err = json.Unmarshal(body, &evidence); err != nil {
		return fmt.Errorf("chutes: evidence for %s: %w", chuteID, err)
	}
	var work []Evidence
	for _, ev := range evidence.Evidence {
		if _, wanted := stale[ev.InstanceID]; wanted {
			delete(state.verified, ev.InstanceID)
			work = append(work, ev)
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	slots := make(chan struct{}, verifyWorkers)
	for _, ev := range work {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			verified, verifyErr := a.verifier.Verify(ctx, ev, nonce, stale[ev.InstanceID])
			if verifyErr != nil {
				a.log.Warn("chutes: instance rejected", "chute", chuteID, "instance", ev.InstanceID, "err", verifyErr)
				return
			}
			mu.Lock()
			state.verified[verified.InstanceID] = verified
			mu.Unlock()
			a.log.Info("chutes: instance attested", "chute", chuteID, "instance", ev.InstanceID, "until", verified.ExpiresAt)
		}()
	}
	wg.Wait()
	return nil
}
