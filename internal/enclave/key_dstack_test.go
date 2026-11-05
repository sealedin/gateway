package enclave_test

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/enclave"
)

// fakeKeyAgent serves a dstack-style GetKey on a Unix socket and records the path and purpose it was asked for.
type fakeKeyAgent struct {
	socket string
	status int
	reply  any

	mu      sync.Mutex // the handler runs on the server goroutine
	asked   map[string]string
	hitPath string
}

func newFakeKeyAgent(t *testing.T, status int, reply any) *fakeKeyAgent {
	t.Helper()
	agent := &fakeKeyAgent{status: status, reply: reply}
	agent.socket = listenFakeAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var asked map[string]string
		if decodeErr := json.NewDecoder(r.Body).Decode(&asked); decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		agent.mu.Lock()
		agent.hitPath = r.Method + " " + r.URL.Path
		agent.asked = asked
		agent.mu.Unlock()
		w.WriteHeader(agent.status)
		assert.NoError(t, json.NewEncoder(w).Encode(agent.reply))
	}))
	return agent
}

// request returns what the agent was asked: the route hit and the decoded body.
func (a *fakeKeyAgent) request() (string, map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hitPath, a.asked
}

func TestDeriveKeyAsksGetKeyForThePath(t *testing.T) {
	raw := strings.Repeat("ab", enclave.KeySize)
	agent := newFakeKeyAgent(t, http.StatusOK, map[string]any{"key": raw, "signature_chain": []string{"00"}})

	key, err := enclave.DeriveKeyFrom(agent.socket, "sealedin/some-key", "some purpose")
	require.NoError(t, err)
	require.Equal(t, raw, hex.EncodeToString(key[:]))
	hitPath, asked := agent.request()
	require.Equal(t, "POST /GetKey", hitPath)
	require.Equal(t, map[string]string{"path": "sealedin/some-key", "purpose": "some purpose"}, asked,
		"the same path must yield the same KMS-backed key on every boot")
}

func TestDeriveKeyFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		reply  any
		want   string
	}{
		{"agent error", http.StatusInternalServerError, map[string]string{"error": "kms down"}, "HTTP 500"},
		{"key not hex", http.StatusOK, map[string]string{"key": "zz"}, "not 32 hex bytes"},
		{"key too short", http.StatusOK, map[string]string{"key": hex.EncodeToString(make([]byte, 16))}, "not 32 hex bytes"},
		{"key missing", http.StatusOK, map[string]string{"signature_chain": "00"}, "not 32 hex bytes"},
		{"reply not JSON", http.StatusOK, "plain", "decode GetKey reply"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := newFakeKeyAgent(t, tc.status, tc.reply)
			_, err := enclave.DeriveKeyFrom(agent.socket, "p", "q")
			require.ErrorContains(t, err, tc.want)
			require.NotErrorIs(t, err, enclave.ErrNotAttested, "a present but failing agent is never dev mode")
		})
	}
}

// Same dispatch as the quote: no socket is dev mode; a path that exists with no agent behind it (a plain file) is a
// hard error.
func TestDeriveKeyDispatch(t *testing.T) {
	dir := t.TempDir()
	_, err := enclave.DeriveKeyFrom(filepath.Join(dir, "absent.sock"), "p", "q")
	require.ErrorIs(t, err, enclave.ErrNotAttested)

	plainFile := filepath.Join(dir, "not-a-socket")
	require.NoError(t, os.WriteFile(plainFile, nil, 0o600))
	_, err = enclave.DeriveKeyFrom(plainFile, "p", "q")
	require.Error(t, err)
	require.NotErrorIs(t, err, enclave.ErrNotAttested)
}
