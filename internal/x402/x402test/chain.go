package x402test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/solanarpc"
)

const (
	valueField  = "value"
	errField    = "err"
	hintHeight  = 500
	statusField = "confirmationStatus"
)

// Chain is a fake Solana seen through two RPC hosts: every send lands and confirms unless a field says otherwise.
type Chain struct {
	SimulationFailure  string // the error simulateTransaction reports, as JSON
	SendRefused        bool   // sendTransaction answers an error object
	Dropped            bool   // a sent transaction never lands
	FailOnChain        string // a sent transaction lands with this error
	ConfirmerBlind     bool   // the independent host knows nothing
	PrimaryLies        bool   // the primary reports every signature confirmed without a send
	OnSend             func() // runs when a send arrives, before it is answered
	OnSimulate         func() // the same for a simulation
	SendTransportFail  bool   // a send answers 502, leaving its outcome unknown, and lands unless Dropped
	PrimaryLiesAfter   bool   // the primary reports confirmation for sent transactions, landed or not
	ConfirmerFailure   string // the independent host reports this chain error while the primary reports success
	ConfirmerDown      bool   // the independent host answers 502
	ConfirmerClaims    bool   // the independent host reports every signature confirmed
	Processed          int    // this many status reads say processed before the truth
	Substitute         []byte // getTransaction answers these bytes whatever was asked
	BlockTime          int64  // the blockTime getTransaction reports, unix seconds; zero reports none
	StatusDown         bool   // the primary answers 502 to status and transaction reads
	SimulateDown       bool   // the primary answers 502 to simulations
	WrongSendReply     bool   // sendTransaction reports another signature
	SendAmbiguousError bool   // sendTransaction lands, then answers an error object with no definite meaning

	mu        sync.Mutex
	sent      [][]byte
	simulated [][]byte
	landed    map[string][]byte
	listed    map[string][]string // address, signatures newest first
	failed    map[string]string   // a listed transaction that landed failed
	refused   map[string]bool     // ids getTransaction answers an error for
	calls     map[string]int
}

type rpcRequest struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// Clients starts both hosts.
func (c *Chain) Clients(t *testing.T) (*solanarpc.Client, *solanarpc.Client) {
	t.Helper()
	primary := httptest.NewServer(c.handler(t, false))
	t.Cleanup(primary.Close)
	confirmer := httptest.NewServer(c.handler(t, true))
	t.Cleanup(confirmer.Close)
	return &solanarpc.Client{URL: primary.URL, HTTP: primary.Client()}, &solanarpc.Client{URL: confirmer.URL, HTTP: confirmer.Client()}
}

// Sent is every transaction sendTransaction received.
func (c *Chain) Sent() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.sent...)
}

// Simulated is every transaction simulateTransaction received.
func (c *Chain) Simulated() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.simulated...)
}

// Calls counts one method.
func (c *Chain) Calls(method string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[method]
}

// Land puts a signed transaction on chain directly, as if an earlier process had sent it.
func (c *Chain) Land(t *testing.T, raw []byte) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NoError(t, c.record(raw))
}

// LandUnder lands a transaction listed under an address, failed if failure is set.
func (c *Chain) LandUnder(t *testing.T, raw []byte, address solana.PublicKey, failure string) solana.Signature {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NoError(t, c.record(raw))
	tx, err := solana.TransactionFromBytes(raw)
	require.NoError(t, err)
	id := tx.Signatures[0].String()
	if c.listed == nil {
		c.listed, c.failed = map[string][]string{}, map[string]string{}
	}
	c.listed[address.String()] = append([]string{id}, c.listed[address.String()]...)
	c.failed[id] = failure
	return tx.Signatures[0]
}

// ListOnly lists a signature under an address, as a lying or lagging node may, with no transaction behind it.
func (c *Chain) ListOnly(address solana.PublicKey, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listed == nil {
		c.listed, c.failed = map[string][]string{}, map[string]string{}
	}
	c.listed[address.String()] = append([]string{id}, c.listed[address.String()]...)
}

func (c *Chain) signaturesFor(address string) any {
	entries := []any{}
	for _, id := range c.listed[address] {
		entry := map[string]any{"signature": id, errField: nil}
		if failure := c.failed[id]; failure != "" {
			entry[errField] = failure
		}
		entries = append(entries, entry)
	}
	return entries
}

func (c *Chain) record(raw []byte) error {
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return fmt.Errorf("x402test: landed transaction: %w", err)
	}
	if c.landed == nil {
		c.landed = map[string][]byte{}
	}
	c.landed[tx.Signatures[0].String()] = raw
	return nil
}

// listSent files a sent transaction under its accounts, as a node does.
func (c *Chain) listSent(raw []byte) {
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return
	}
	if c.listed == nil {
		c.listed, c.failed = map[string][]string{}, map[string]string{}
	}
	for _, key := range tx.Message.AccountKeys {
		c.listed[key.String()] = append([]string{tx.Signatures[0].String()}, c.listed[key.String()]...)
	}
}

func (c *Chain) handler(t *testing.T, confirmer bool) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req), "x402test: request")
		c.count(req.Method)
		// Hooks run outside the lock: one may block while the test looks at the chain.
		c.mu.Lock()
		onSend := c.OnSend
		c.mu.Unlock()
		if req.Method == solanarpc.MethodSend && onSend != nil {
			onSend()
		}
		if req.Method == solanarpc.MethodSimulate && c.OnSimulate != nil {
			c.OnSimulate()
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.down(req.Method, confirmer) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if req.Method == solanarpc.MethodSend && c.SendAmbiguousError {
			_, err := c.send(req)
			assert.NoError(t, err, "x402test: send")
			reply := map[string]any{"error": map[string]any{"code": -32000, "message": "internal"}}
			assert.NoError(t, json.NewEncoder(w).Encode(reply), "x402test: reply")
			return
		}
		if req.Method == solanarpc.MethodSend && c.SendTransportFail {
			_, err := c.send(req)
			assert.NoError(t, err, "x402test: send")
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		reply := map[string]any{"jsonrpc": "2.0", "id": 1}
		result, err := c.answer(req, confirmer)
		switch {
		case errors.Is(err, errRefused):
			reply["error"] = map[string]any{"code": -32005, "message": "refused"}
		default:
			assert.NoError(t, err, "x402test: %s", req.Method)
			reply["result"] = result
		}
		assert.NoError(t, json.NewEncoder(w).Encode(reply), "x402test: reply")
	}
}

var errRefused = errors.New("x402test: refused")

// RefuseTransaction makes getTransaction answer an error object for this id, as a node does for a version it does not read.
func (c *Chain) RefuseTransaction(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refused == nil {
		c.refused = map[string]bool{}
	}
	c.refused[id] = true
}

// SetFailOnChain changes FailOnChain while the hosts run.
func (c *Chain) SetFailOnChain(failure string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.FailOnChain = failure
}

// SetStatusDown changes StatusDown while the hosts run.
func (c *Chain) SetStatusDown(down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.StatusDown = down
}

// SetOnSend changes OnSend while the hosts run.
func (c *Chain) SetOnSend(hook func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.OnSend = hook
}

// SetSimulateDown changes SimulateDown while the hosts run.
func (c *Chain) SetSimulateDown(down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SimulateDown = down
}

func (c *Chain) down(method string, confirmer bool) bool {
	if confirmer {
		return c.ConfirmerDown
	}
	switch method {
	case solanarpc.MethodSimulate:
		return c.SimulateDown
	case solanarpc.MethodSignatureStatuses, solanarpc.MethodTransaction:
		return c.StatusDown
	}
	return false
}

func (c *Chain) count(method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[method]++
}

func (c *Chain) answer(req rpcRequest, confirmer bool) (any, error) {
	switch req.Method {
	case solanarpc.MethodLatestBlockhash:
		return map[string]any{valueField: map[string]any{"blockhash": solana.Hash{9}.String(), "lastValidBlockHeight": hintHeight}}, nil
	case solanarpc.MethodSimulate:
		return c.simulate(req)
	case solanarpc.MethodSend:
		return c.send(req)
	case solanarpc.MethodSignatureStatuses:
		var ids []string
		if err := json.Unmarshal(req.Params[0], &ids); err != nil {
			return nil, err
		}
		return map[string]any{valueField: []any{c.status(ids[0], confirmer)}}, nil
	case solanarpc.MethodSignaturesForAddress:
		var address string
		if err := json.Unmarshal(req.Params[0], &address); err != nil {
			return nil, err
		}
		return c.signaturesFor(address), nil
	case solanarpc.MethodTransaction:
		var id string
		if err := json.Unmarshal(req.Params[0], &id); err != nil {
			return nil, err
		}
		if c.refused[id] {
			return nil, errRefused
		}
		return c.transaction(id), nil
	default:
		return nil, fmt.Errorf("x402test: unexpected method %s", req.Method)
	}
}

func (c *Chain) simulate(req rpcRequest) (any, error) {
	raw, err := decodeTx(req)
	if err != nil {
		return nil, err
	}
	c.simulated = append(c.simulated, raw)
	var failure any
	if c.SimulationFailure != "" {
		if err = json.Unmarshal([]byte(c.SimulationFailure), &failure); err != nil {
			return nil, err
		}
	}
	return map[string]any{valueField: map[string]any{errField: failure}}, nil
}

func (c *Chain) send(req rpcRequest) (any, error) {
	if c.SendRefused {
		return nil, errRefused
	}
	raw, err := decodeTx(req)
	if err != nil {
		return nil, err
	}
	c.sent = append(c.sent, raw)
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return nil, err
	}
	if !c.Dropped {
		if err = c.record(raw); err != nil {
			return nil, err
		}
		c.listSent(raw)
	}
	if c.WrongSendReply {
		return solana.Signature{9}.String(), nil
	}
	return tx.Signatures[0].String(), nil
}

func (c *Chain) status(id string, confirmer bool) any {
	_, known := c.landed[id]
	if confirmer && c.ConfirmerClaims {
		known = true
	}
	if !confirmer && (c.PrimaryLies || (c.PrimaryLiesAfter && len(c.sent) > 0)) {
		known = true
	}
	if !known || (confirmer && c.ConfirmerBlind) {
		return nil
	}
	if !confirmer && c.Processed > 0 {
		c.Processed--
		return map[string]any{statusField: "processed", errField: nil}
	}
	if confirmer && c.ConfirmerFailure != "" {
		return map[string]any{statusField: "confirmed", errField: c.ConfirmerFailure}
	}
	return map[string]any{statusField: "confirmed", errField: c.failure()}
}

func (c *Chain) transaction(id string) any {
	raw, known := c.landed[id]
	if c.Substitute != nil {
		raw, known = c.Substitute, true
	}
	if !known {
		return nil
	}
	reply := map[string]any{
		"transaction": []string{base64.StdEncoding.EncodeToString(raw), "base64"},
		"meta":        map[string]any{errField: c.failure()},
	}
	if failure := c.failed[id]; failure != "" {
		reply["meta"] = map[string]any{errField: failure}
	}
	if c.BlockTime != 0 {
		reply["blockTime"] = c.BlockTime
	}
	return reply
}

func (c *Chain) failure() any {
	if c.FailOnChain == "" {
		return nil
	}
	return c.FailOnChain
}

func decodeTx(req rpcRequest) ([]byte, error) {
	var encoded string
	if err := json.Unmarshal(req.Params[0], &encoded); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}
