package chutes

import (
	"bytes"
	"compress/gzip"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Chutes E2EE wire format (chutes-e2ee-transport): ML-KEM-768 encapsulation to the instance key, HKDF-SHA256 with
// salt = ciphertext[:16] and a per-direction info string, ChaCha20-Poly1305 frames nonce || ciphertext || tag.
const (
	infoRequest  = "e2e-req-v1"
	infoResponse = "e2e-resp-v1"
	infoStream   = "e2e-stream-v1"
	hkdfSaltLen  = 16
	keyLen       = 32
	maxPlaintext = 16 << 20 // decompressed
)

// Session holds the client's ephemeral response key for one request.
type Session struct {
	dk *mlkem.DecapsulationKey768
}

// EncryptRequest gzips and seals the body (plus our response key as e2e_response_pk) to the instance's ML-KEM key.
func EncryptRequest(instancePubkeyB64 string, body []byte) ([]byte, *Session, error) {
	pub, err := base64.StdEncoding.DecodeString(instancePubkeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("chutes: instance e2e_pubkey: %w", err)
	}
	ek, err := mlkem.NewEncapsulationKey768(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("chutes: instance e2e_pubkey: %w", err)
	}
	var payload map[string]json.RawMessage
	if err = json.Unmarshal(body, &payload); err != nil || payload == nil {
		return nil, nil, errors.New("chutes: request body is not a JSON object")
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, fmt.Errorf("chutes: generate response key: %w", err)
	}
	pk, _ := json.Marshal(base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes())) //nolint:errchkjson // a string
	payload["e2e_response_pk"] = pk
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("chutes: encode request: %w", err)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(plain)
	_ = w.Close()
	shared, ct := ek.Encapsulate()
	frame, err := sealChaCha(deriveKey(shared, ct, infoRequest), gz.Bytes())
	if err != nil {
		return nil, nil, err
	}
	return append(ct, frame...), &Session{dk: dk}, nil
}

// DecryptResponse opens a non-streaming reply: mlkem_ct || nonce || ciphertext || tag over gzip(JSON).
func (s *Session) DecryptResponse(blob []byte) ([]byte, error) {
	if len(blob) < mlkem.CiphertextSize768 {
		return nil, errors.New("chutes: response blob shorter than a KEM ciphertext")
	}
	shared, err := s.dk.Decapsulate(blob[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, fmt.Errorf("chutes: response decapsulate: %w", err)
	}
	compressed, err := openChaCha(deriveKey(shared, blob[:mlkem.CiphertextSize768], infoResponse), blob[mlkem.CiphertextSize768:])
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("chutes: response gzip: %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(gz, maxPlaintext+1))
	if err != nil {
		return nil, fmt.Errorf("chutes: response gunzip: %w", err)
	}
	if len(plain) > maxPlaintext {
		return nil, fmt.Errorf("chutes: response exceeds %d bytes", maxPlaintext)
	}
	return plain, nil
}

// StreamKey derives the stream key from the e2e_init event's KEM ciphertext.
func (s *Session) StreamKey(ctB64 string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil || len(ct) != mlkem.CiphertextSize768 {
		return nil, errors.New("chutes: e2e_init is not a KEM ciphertext")
	}
	shared, err := s.dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("chutes: e2e_init decapsulate: %w", err)
	}
	return deriveKey(shared, ct, infoStream), nil
}

// DecryptChunk opens one streamed e2e event (not gzipped).
func DecryptChunk(streamKey []byte, frameB64 string) ([]byte, error) {
	frame, err := base64.StdEncoding.DecodeString(frameB64)
	if err != nil {
		return nil, fmt.Errorf("chutes: stream chunk: %w", err)
	}
	return openChaCha(streamKey, frame)
}

func deriveKey(shared, ct []byte, info string) []byte {
	key, err := hkdf.Key(sha256.New, shared, ct[:hkdfSaltLen], info, keyLen)
	if err != nil {
		panic(fmt.Sprintf("hkdf: %v", err))
	}
	return key
}

func sealChaCha(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chutes: chacha: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("chutes: nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func openChaCha(key, frame []byte) ([]byte, error) {
	if len(frame) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, errors.New("chutes: encrypted frame too short")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chutes: chacha: %w", err)
	}
	plain, err := aead.Open(nil, frame[:chacha20poly1305.NonceSize], frame[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, errors.New("chutes: frame authentication failed")
	}
	return plain, nil
}
