// Package solanarpc is the JSON-RPC client of the few Solana methods settlement needs, over the measured rpcproxy; on the
// stdlib because solana-go's rpc package would add packages to the measured binary for five calls and caps no reply size.
package solanarpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Routes of the rpcproxy: the provider, and the independent host that is read-only by its allowlist.
const (
	PrimaryRoute      = "/primary"
	ConfirmationRoute = "/confirmation"
)

// One timeout order, innermost first, so a slow host yields a reply the caller can read: the proxy gives up on its upstream
// before the settler gives up on the call, and the HTTP client only guards against a stuck proxy.
const (
	ProxyUpstreamTimeout = 8 * time.Second
	CallTimeout          = 10 * time.Second
	ClientTimeout        = 20 * time.Second
)

// JSON-RPC error codes of the Solana node.
const (
	codeSignatureVerification = -32003
	codeNodeUnhealthy         = -32005
	codeInvalidParams         = -32602
)

// Method names; cmd/rpcproxy forwards exactly these.
const (
	MethodLatestBlockhash      = "getLatestBlockhash"
	MethodSimulate             = "simulateTransaction"
	MethodSend                 = "sendTransaction"
	MethodSignatureStatuses    = "getSignatureStatuses"
	MethodTransaction          = "getTransaction"
	MethodSignaturesForAddress = "getSignaturesForAddress"
	base64Encoding             = "base64"
	confirmedCommitment        = "confirmed"
	finalizedCommitment        = "finalized"
	maxReplyBytes              = 1 << 20 // a status, one transaction of at most 1232 bytes, or a capped list of signatures
	jsonRPCVersion             = "2.0"
	transactionTupleLen        = 2 // [data, encoding]
	commitmentKey              = "commitment"
	encodingKey                = "encoding"
)

// Error is the node's own error object: a definite answer, unlike a transport failure.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("solanarpc: code %d: %s", e.Code, e.Message) }

// Definite says the node certainly did not forward the transaction: a failed signature check, an unhealthy node, bad
// params. Any other error object may follow a forward, and its transaction may still land.
func (e *Error) Definite() bool {
	switch e.Code {
	case codeSignatureVerification, codeNodeUnhealthy, codeInvalidParams:
		return true
	default:
		return false
	}
}

// Client calls one RPC endpoint.
type Client struct {
	URL  string
	HTTP *http.Client
}

func (c *Client) call(ctx context.Context, method string, params []any, result any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": jsonRPCVersion, "id": 1, "method": method, "params": params})
	if err != nil {
		return fmt.Errorf("solanarpc: %s: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("solanarpc: %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("solanarpc: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("solanarpc: %s: status %d", method, resp.StatusCode)
	}
	var reply struct {
		Result json.RawMessage `json:"result"`
		Error  *Error          `json:"error"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxReplyBytes)).Decode(&reply); err != nil {
		return fmt.Errorf("solanarpc: %s: decode: %w", method, err)
	}
	if reply.Error != nil {
		return reply.Error
	}
	if err = json.Unmarshal(reply.Result, result); err != nil {
		return fmt.Errorf("solanarpc: %s: decode result: %w", method, err)
	}
	return nil
}

// failure is a chain error value as text, empty when the value is JSON null or absent.
func failure(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	return string(raw)
}

// LatestBlockhash is the hint of the 402 challenge.
func (c *Client) LatestBlockhash(ctx context.Context) (string, uint64, error) {
	var reply struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	options := map[string]any{commitmentKey: confirmedCommitment}
	if err := c.call(ctx, MethodLatestBlockhash, []any{options}, &reply); err != nil {
		return "", 0, err
	}
	return reply.Value.Blockhash, reply.Value.LastValidBlockHeight, nil
}

// Simulate runs a partially signed transaction and returns the chain's error as text, empty when it would succeed.
func (c *Client) Simulate(ctx context.Context, tx []byte) (string, error) {
	var reply struct {
		Value *struct {
			Err json.RawMessage `json:"err"`
		} `json:"value"`
	}
	options := map[string]any{encodingKey: base64Encoding, "sigVerify": false, commitmentKey: confirmedCommitment}
	params := []any{base64.StdEncoding.EncodeToString(tx), options}
	if err := c.call(ctx, MethodSimulate, params, &reply); err != nil {
		return "", err
	}
	if reply.Value == nil { // an empty reply must not read as a passed simulation
		return "", errors.New("solanarpc: simulateTransaction: no value in the reply")
	}
	return failure(reply.Value.Err), nil
}

// Send broadcasts a fully signed transaction, preflight off since the sponsor just simulated it.
func (c *Client) Send(ctx context.Context, tx []byte) (string, error) {
	var id string
	options := map[string]any{encodingKey: base64Encoding, "skipPreflight": true}
	params := []any{base64.StdEncoding.EncodeToString(tx), options}
	if err := c.call(ctx, MethodSend, params, &id); err != nil {
		return "", err
	}
	return id, nil
}

// Status is where a known transaction stands; Failure is the chain's error as text, empty on success.
type Status struct {
	Confirmed bool
	Failure   string
}

// SignatureStatus is nil for a transaction the node does not know.
func (c *Client) SignatureStatus(ctx context.Context, id string) (*Status, error) {
	var reply struct {
		Value []*struct {
			ConfirmationStatus string          `json:"confirmationStatus"`
			Err                json.RawMessage `json:"err"`
		} `json:"value"`
	}
	options := map[string]any{"searchTransactionHistory": true}
	if err := c.call(ctx, MethodSignatureStatuses, []any{[]string{id}, options}, &reply); err != nil {
		return nil, err
	}
	if len(reply.Value) != 1 {
		return nil, fmt.Errorf("solanarpc: %s: %d statuses for one signature", MethodSignatureStatuses, len(reply.Value))
	}
	got := reply.Value[0]
	if got == nil {
		return nil, nil //nolint:nilnil // an unknown transaction is an answer, not an error
	}
	return &Status{
		Confirmed: got.ConfirmationStatus == confirmedCommitment || got.ConfirmationStatus == finalizedCommitment,
		Failure:   failure(got.Err),
	}, nil
}

// ConfirmedTransaction is a transaction as a node reports it landed; Failure is the chain's error, empty on success.
type ConfirmedTransaction struct {
	Raw       []byte
	Failure   string
	BlockTime time.Time // zero when the node reports none
}

// ListedSignature is one entry of getSignaturesForAddress.
type ListedSignature struct {
	Signature string
	Failure   string
}

// SignaturesForAddress lists what mentions an address at confirmed commitment, newest first.
func (c *Client) SignaturesForAddress(ctx context.Context, address string, limit int) ([]ListedSignature, error) {
	var reply []struct {
		Signature string          `json:"signature"`
		Err       json.RawMessage `json:"err"`
	}
	options := map[string]any{commitmentKey: confirmedCommitment, "limit": limit}
	if err := c.call(ctx, MethodSignaturesForAddress, []any{address, options}, &reply); err != nil {
		return nil, err
	}
	listed := make([]ListedSignature, 0, len(reply))
	for _, entry := range reply {
		listed = append(listed, ListedSignature{Signature: entry.Signature, Failure: failure(entry.Err)})
	}
	return listed, nil
}

// Transaction is nil for a transaction the node does not hold at confirmed commitment.
func (c *Client) Transaction(ctx context.Context, id string) (*ConfirmedTransaction, error) {
	var reply *struct {
		Transaction []string `json:"transaction"`
		BlockTime   *int64   `json:"blockTime"`
		Meta        *struct {
			Err json.RawMessage `json:"err"`
		} `json:"meta"`
	}
	options := map[string]any{encodingKey: base64Encoding, commitmentKey: confirmedCommitment, "maxSupportedTransactionVersion": 0}
	if err := c.call(ctx, MethodTransaction, []any{id, options}, &reply); err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, nil //nolint:nilnil // an unknown transaction is an answer, not an error
	}
	if reply.Meta == nil || len(reply.Transaction) != transactionTupleLen || reply.Transaction[1] != base64Encoding {
		return nil, errors.New("solanarpc: getTransaction: unexpected reply shape")
	}
	raw, err := base64.StdEncoding.DecodeString(reply.Transaction[0])
	if err != nil {
		return nil, fmt.Errorf("solanarpc: getTransaction: %w", err)
	}
	confirmed := &ConfirmedTransaction{Raw: raw, Failure: failure(reply.Meta.Err)}
	if reply.BlockTime != nil {
		confirmed.BlockTime = time.Unix(*reply.BlockTime, 0)
	}
	return confirmed, nil
}
