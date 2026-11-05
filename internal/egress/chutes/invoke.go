package chutes

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/sealedin/gateway/internal/egress/upstream"
)

const (
	maxLine       = 4 << 20
	frameNonceB64 = 16 // base64 length of the 12-byte frame nonce, the prefix that identifies a replay
)

// Provider routes OpenAI-compatible requests to attested Chutes instances over E2EE.
type Provider struct {
	api      string
	apiKey   string
	client   *http.Client
	catalog  *Catalog
	attester *Attester
}

// NewProvider wires the catalog and attester to the invoke endpoint at api.
func NewProvider(api, apiKey string, client *http.Client, catalog *Catalog, attester *Attester) *Provider {
	return &Provider{api: api, apiKey: apiKey, client: client, catalog: catalog, attester: attester}
}

// Invoke sends body to an attested instance chosen per request and returns the decrypted reply.
func (p *Provider) Invoke(ctx context.Context, model, path string, stream bool, body []byte) (*upstream.Reply, error) {
	chuteID, err := p.catalog.Resolve(ctx, model)
	if err != nil {
		return nil, err
	}
	target, err := p.attester.Take(ctx, chuteID)
	if err != nil {
		return nil, err
	}
	blob, session, err := EncryptRequest(target.Pubkey, body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.api+invokePath, bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("chutes: invoke request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Chute-Id", target.ChuteID)
	req.Header.Set("X-Instance-Id", target.InstanceID)
	req.Header.Set("X-E2e-Nonce", target.Nonce)
	req.Header.Set("X-E2e-Stream", strconv.FormatBool(stream))
	req.Header.Set("X-E2e-Path", path)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chutes: invoke: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxLine))
		return nil, &upstream.Error{Status: resp.StatusCode, Detail: strings.TrimSpace(string(detail))}
	}
	if stream {
		return &upstream.Reply{ContentType: "text/event-stream", Body: decryptStream(resp.Body, session)}, nil
	}
	defer func() { _ = resp.Body.Close() }()
	blob, err = io.ReadAll(io.LimitReader(resp.Body, maxPlaintext+1))
	if err != nil {
		return nil, fmt.Errorf("chutes: read reply: %w", err)
	}
	if len(blob) > maxPlaintext {
		return nil, fmt.Errorf("chutes: reply exceeds %d bytes", maxPlaintext)
	}
	plain, err := session.DecryptResponse(blob)
	if err != nil {
		return nil, err
	}
	return &upstream.Reply{ContentType: "application/json", Body: io.NopCloser(bytes.NewReader(plain))}, nil
}

// decryptStream turns the encrypted SSE (e2e_init, then e2e frames wrapping the upstream's own SSE) into plain SSE. A
// [DONE] outside the encryption is a relay forgery, a repeated frame nonce a replay, and usage must precede [DONE];
// frames carry no sequence, so a dropped middle frame is undetectable here.
func decryptStream(upstream io.ReadCloser, session *Session) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = upstream.Close() }()
		_ = pw.CloseWithError(relayStream(upstream, pw, session))
	}()
	return pr
}

func relayStream(encrypted io.Reader, w io.Writer, session *Session) error {
	scanner := bufio.NewScanner(encrypted)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxLine)
	st := &streamState{session: session, seen: map[string]struct{}{}}
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data: ")
		if !ok {
			continue
		}
		if data == "[DONE]" {
			return errors.New("chutes: stream terminator outside the encryption")
		}
		var event map[string]json.RawMessage
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			return fmt.Errorf("chutes: stream event: %w", err)
		}
		done, err := st.relay(event, w)
		if err != nil || done {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("chutes: stream: %w", err)
	}
	return errors.New("chutes: stream ended without [DONE]")
}

type streamState struct {
	session   *Session
	key       []byte
	seen      map[string]struct{}
	usageSeen bool
}

func (st *streamState) relay(event map[string]json.RawMessage, w io.Writer) (bool, error) {
	var value string
	switch {
	case event["e2e_init"] != nil:
		if err := json.Unmarshal(event["e2e_init"], &value); err != nil {
			return false, fmt.Errorf("chutes: e2e_init: %w", err)
		}
		key, err := st.session.StreamKey(value)
		if err != nil {
			return false, err
		}
		st.key = key
	case event["e2e"] != nil:
		if st.key == nil {
			return false, errors.New("chutes: e2e chunk before e2e_init")
		}
		if err := json.Unmarshal(event["e2e"], &value); err != nil {
			return false, fmt.Errorf("chutes: e2e chunk: %w", err)
		}
		if _, dup := st.seen[value[:min(len(value), frameNonceB64)]]; dup {
			return false, errors.New("chutes: repeated stream frame nonce")
		}
		st.seen[value[:min(len(value), frameNonceB64)]] = struct{}{}
		plain, err := DecryptChunk(st.key, value)
		if err != nil {
			return false, err
		}
		// The upstream's SSE arrives one line per frame, so its terminator is a frame of its own.
		if bytes.Equal(bytes.TrimSpace(plain), []byte("data: [DONE]")) {
			if !st.usageSeen {
				return false, errors.New("chutes: stream ended before the final usage chunk")
			}
			_, err = io.WriteString(w, "data: [DONE]\n\n")
			return true, err
		}
		if bytes.Contains(plain, []byte(`"usage"`)) {
			st.usageSeen = true
		}
		_, err = w.Write(plain)
		return false, err
	case event["e2e_error"] != nil:
		return false, fmt.Errorf("chutes: instance reported %s", string(event["e2e_error"]))
	}
	return false, nil
}
