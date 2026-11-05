// Package testsupport is the httptest stub of the gateway admin API; test-only.
package testsupport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sealedin/gateway/internal/usage"
)

// GenerateCall is one /key/generate request as the stub recorded it.
type GenerateCall struct {
	Key                 string
	Alias               string
	MaxBudget           float64
	RPMLimit            int
	MaxParallelRequests int
	Models              []string
	Metadata            map[string]any
	Blocked             bool
	BudgetDuration      any // nil when the request carried none
}

// liveKey is a key the stub currently holds.
type liveKey struct {
	Alias     string
	MaxBudget float64
	RPMLimit  int
	Models    []string
	Metadata  map[string]any
	Blocked   bool
}

// FakeGateway is a LiteLLM admin stub: exported fields configure responses, accessors read recorded state back.
type FakeGateway struct {
	MasterKey string
	SpendUSD  float64 // lifetime spend the stub reports for any key

	mu        sync.Mutex
	fail      map[string]bool // admin paths that answer 500, to play a gateway going down mid-flow
	lateMint  bool            // /key/generate lands its row, then answers 500: a reply lost after the work
	raceAlias bool            // the next alias lookup and alias check see nothing: a commit landing just after them
	generated []GenerateCall
	live      map[string]*liveKey // by token hash
}

// Client starts the stub server and returns a gateway client wired to it.
func (g *FakeGateway) Client(t *testing.T) *usage.Gateway {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /key/generate", g.authed(g.generate(t), "/key/generate"))
	mux.HandleFunc("GET /key/list", g.authed(g.list(t), "/key/list"))
	mux.HandleFunc("GET /key/info", g.authed(g.info(t), "/key/info"))
	mux.HandleFunc("POST /key/update", g.authed(g.update(t), "/key/update"))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &usage.Gateway{BaseURL: server.URL, MasterKey: g.MasterKey, HTTP: server.Client()}
}

// LoseNextMintReply makes the next /key/generate land its row, then answer 500.
func (g *FakeGateway) LoseNextMintReply() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lateMint = true
}

func (g *FakeGateway) takeLateMint() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	late := g.lateMint
	g.lateMint = false
	return late
}

// RaceNextIssue hides a row from the next alias lookup and alias check, as a commit landing just after them would.
func (g *FakeGateway) RaceNextIssue() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.raceAlias = true
}

// Block blocks a key, as an operator revoking it does.
func (g *FakeGateway) Block(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if live, ok := g.live[usage.TokenHash(key)]; ok {
		live.Blocked = true
	}
}

// Delete removes a key, as an operator cleaning up does.
func (g *FakeGateway) Delete(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.live, usage.TokenHash(key))
}

// SetFail switches an admin path's failure on or off.
func (g *FakeGateway) SetFail(path string, fail bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail == nil {
		g.fail = map[string]bool{}
	}
	g.fail[path] = fail
}

// generate records the request and echoes it back as LiteLLM does, minting a key when the caller named none and refusing
// an alias a live key holds.
func (g *FakeGateway) generate(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body := decodeKeyBody(t, r)
		call := GenerateCall{BudgetDuration: body["budget_duration"]}
		call.Key, _ = body["key"].(string)
		call.Alias, _ = body["key_alias"].(string)
		call.MaxBudget, _ = body["max_budget"].(float64)
		rpm, _ := body["rpm_limit"].(float64)
		call.RPMLimit = int(rpm)
		parallel, _ := body["max_parallel_requests"].(float64)
		call.MaxParallelRequests = int(parallel)
		call.Metadata, _ = body["metadata"].(map[string]any)
		call.Blocked, _ = body["blocked"].(bool)
		if raw, _ := body["models"].([]any); raw != nil {
			for _, m := range raw {
				call.Models = append(call.Models, fmt.Sprint(m))
			}
		}
		if err := g.mint(&call); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if g.takeLateMint() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body["key"] = call.Key
		assert.NoError(t, json.NewEncoder(w).Encode(body), "testsupport: key/generate reply")
	}
}

func (g *FakeGateway) mint(call *GenerateCall) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	raced := g.raceAlias
	g.raceAlias = false
	for _, key := range g.live {
		if key.Alias == call.Alias && !raced {
			return errors.New("alias taken")
		}
	}
	if call.Key == "" {
		call.Key = "sk-" + strconv.Itoa(len(g.generated))
	}
	g.generated = append(g.generated, *call)
	if g.live == nil {
		g.live = map[string]*liveKey{}
	}
	// The pinned LiteLLM upserts on the token with an empty update: a repeat succeeds and changes nothing.
	if _, taken := g.live[usage.TokenHash(call.Key)]; !taken {
		g.live[usage.TokenHash(call.Key)] = &liveKey{Alias: call.Alias, MaxBudget: call.MaxBudget, RPMLimit: call.RPMLimit,
			Models: call.Models, Metadata: call.Metadata, Blocked: call.Blocked}
	}
	return nil
}

func (g *FakeGateway) fields(token string, key *liveKey) map[string]any {
	return map[string]any{"token": token, "key_alias": key.Alias, "spend": g.SpendUSD, "max_budget": key.MaxBudget,
		"rpm_limit": key.RPMLimit, "models": key.Models, "metadata": key.Metadata, "blocked": key.Blocked}
}

// list is the exact alias filter with full objects, as LiteLLM's /key/list answers it.
func (g *FakeGateway) list(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		alias := r.URL.Query().Get("key_alias")
		keys := make([]map[string]any, 0, 1)
		g.mu.Lock()
		for token, key := range g.live {
			if key.Alias == alias && !g.raceAlias {
				keys = append(keys, g.fields(token, key))
			}
		}
		g.mu.Unlock()
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"keys": keys, "total_count": len(keys)}),
			"testsupport: key/list reply")
	}
}

// info answers by raw key or hash and strips the token from the reply, as LiteLLM's /key/info does.
func (g *FakeGateway) info(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("key")
		g.mu.Lock()
		defer g.mu.Unlock()
		key, ok := g.live[usage.TokenHash(param)]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fields := g.fields("", key)
		delete(fields, "token")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"key": param, "info": fields}), "testsupport: key/info reply")
	}
}

func (g *FakeGateway) update(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body := decodeKeyBody(t, r)
		param, _ := body["key"].(string)
		g.mu.Lock()
		defer g.mu.Unlock()
		key, ok := g.live[usage.TokenHash(param)]
		if !ok {
			w.WriteHeader(http.StatusBadRequest) // LiteLLM reports an unknown key on /key/update as a bad request
			return
		}
		if v, set := body["max_budget"].(float64); set {
			key.MaxBudget = v
		}
		if v, set := body["metadata"].(map[string]any); set {
			key.Metadata = v
		}
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{"key": param}), "testsupport: key/update reply")
	}
}

// Generated returns the /key/generate calls the stub served, in order.
func (g *FakeGateway) Generated() []GenerateCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.generated)
}

func (g *FakeGateway) authed(next http.HandlerFunc, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+g.MasterKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		g.mu.Lock()
		failing := g.fail[path]
		g.mu.Unlock()
		if failing {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		next(w, r)
	}
}

func decodeKeyBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	assert.NoError(t, json.NewDecoder(r.Body).Decode(&body), "testsupport: key body")
	return body
}
