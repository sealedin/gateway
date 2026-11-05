package chutes_test

import (
	"bytes"
	"compress/gzip"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/egress/chutes"
)

// instanceKey plays the chute runtime, an independent implementation of the wire format.
type instanceKey struct {
	dk *mlkem.DecapsulationKey768
}

func newInstanceKey(t *testing.T) *instanceKey {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	require.NoError(t, err)
	return &instanceKey{dk: dk}
}

func (k *instanceKey) pubkeyB64() string {
	return base64.StdEncoding.EncodeToString(k.dk.EncapsulationKey().Bytes())
}

// open decrypts a request blob into its payload and the client's response key; handlers call it, so it returns errors.
func (k *instanceKey) open(blob []byte) (map[string]json.RawMessage, *mlkem.EncapsulationKey768, error) {
	if len(blob) <= mlkem.CiphertextSize768+12+16 {
		return nil, nil, errors.New("blob too short")
	}
	shared, err := k.dk.Decapsulate(blob[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, nil, err
	}
	key := chutes.DeriveKey(shared, blob[:mlkem.CiphertextSize768], "e2e-req-v1")
	plain, err := chutes.OpenChaCha(key, blob[mlkem.CiphertextSize768:])
	if err != nil {
		return nil, nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(gz)
	if err != nil {
		return nil, nil, err
	}
	var payload map[string]json.RawMessage
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, nil, err
	}
	var pkB64 string
	if err = json.Unmarshal(payload["e2e_response_pk"], &pkB64); err != nil {
		return nil, nil, err
	}
	pk, err := base64.StdEncoding.DecodeString(pkB64)
	if err != nil {
		return nil, nil, err
	}
	ek, err := mlkem.NewEncapsulationKey768(pk)
	return payload, ek, err
}

func TestEncryptRequestRoundTrip(t *testing.T) {
	inst := newInstanceKey(t)
	blob, session, err := chutes.EncryptRequest(inst.pubkeyB64(), []byte(`{"model":"m","messages":[]}`))
	require.NoError(t, err)

	payload, responseKey, err := inst.open(blob)
	require.NoError(t, err)
	require.JSONEq(t, `"m"`, string(payload["model"]))

	// Non-streaming reply: mlkem_ct || nonce || ciphertext || tag over gzip(JSON), key info e2e-resp-v1.
	shared, ct := responseKey.Encapsulate()
	respKey := chutes.DeriveKey(shared, ct, "e2e-resp-v1")
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"hi"}}]}`))
	_ = w.Close()
	reply := append(append([]byte(nil), ct...), chutes.SealChaCha(t, respKey, gz.Bytes())...)
	plain, err := session.DecryptResponse(reply)
	require.NoError(t, err)
	require.JSONEq(t, `{"choices":[{"message":{"content":"hi"}}]}`, string(plain))

	// A reply encrypted to a different client key must not open.
	other := newInstanceKey(t)
	_, foreignCT := other.dk.EncapsulationKey().Encapsulate()
	_, err = session.DecryptResponse(append(append([]byte(nil), foreignCT...), chutes.SealChaCha(t, respKey, gz.Bytes())...))
	require.Error(t, err)

	// Streaming: e2e_init carries the KEM ciphertext, chunks are ChaCha frames under the stream key.
	shared, ct = responseKey.Encapsulate()
	streamKey, err := session.StreamKey(base64.StdEncoding.EncodeToString(ct))
	require.NoError(t, err)
	wantKey := chutes.DeriveKey(shared, ct, "e2e-stream-v1")
	chunk := chutes.SealChaCha(t, wantKey, []byte("data: {\"x\":1}\n\n"))
	plainChunk, err := chutes.DecryptChunk(streamKey, base64.StdEncoding.EncodeToString(chunk))
	require.NoError(t, err)
	require.Equal(t, "data: {\"x\":1}\n\n", string(plainChunk))
	chunk[len(chunk)-1] ^= 1
	_, err = chutes.DecryptChunk(streamKey, base64.StdEncoding.EncodeToString(chunk))
	require.Error(t, err)
}

func TestEncryptRequestRejects(t *testing.T) {
	tests := []struct {
		name   string
		pubkey string
		body   string
	}{
		{"pubkey not base64", "!!", `{}`},
		{"pubkey wrong size", base64.StdEncoding.EncodeToString(make([]byte, 10)), `{}`},
		{"body not an object", newInstanceKey(t).pubkeyB64(), `[1]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := chutes.EncryptRequest(tt.pubkey, []byte(tt.body))
			require.Error(t, err)
		})
	}
}
