package enclave

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// KeySize is the byte length of a key the guest agent derives.
const KeySize = 32

// DeriveKey asks the guest agent's KMS-backed GetKey for the key under path: the same path yields the same key for
// this app on every boot, so it never exists outside the CVM. ErrNotAttested without a socket (dev mode), any other
// failure is hard. The signature chain proves KMS provenance to a verifier; here the key is a secret, so only its
// shape is checked.
func DeriveKey(ctx context.Context, path, purpose string) ([KeySize]byte, error) {
	return deriveKeyFrom(ctx, dstackSocket, path, purpose)
}

func deriveKeyFrom(ctx context.Context, socket, path, purpose string) ([KeySize]byte, error) {
	var key [KeySize]byte
	if err := statSocket(socket); err != nil {
		return key, err
	}
	raw, err := postDstack(ctx, socket, "GetKey", map[string]string{"path": path, "purpose": purpose})
	if err != nil {
		return key, err
	}
	var reply struct {
		Key string `json:"key"`
	}
	if decodeErr := json.Unmarshal(raw, &reply); decodeErr != nil {
		return key, fmt.Errorf("dstack: decode GetKey reply: %w", decodeErr)
	}
	decoded, err := hex.DecodeString(reply.Key)
	if err != nil || len(decoded) != KeySize {
		return key, fmt.Errorf("dstack: GetKey key is not %d hex bytes", KeySize)
	}
	copy(key[:], decoded)
	return key, nil
}
