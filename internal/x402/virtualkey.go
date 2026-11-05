package x402

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
)

const (
	virtualKeyDomain   = "sealedin-x402-virtual-key-v1"
	referenceKeyDomain = "sealedin-pay-key-v1"
	transferKeyDomain  = "sealedin-pay-transfer-v1"
)

// VirtualKeys derives gateway keys from a secret the KMS derives inside the enclave, which no operator holds: the fee payer
// key is theirs, so nothing here may depend on it.
type VirtualKeys struct {
	secret [SecretBytes]byte
}

// SecretBytes is the size of the derivation secret.
const SecretBytes = 32

// NewVirtualKeys wraps the derivation secret.
func NewVirtualKeys(secret [SecretBytes]byte) *VirtualKeys { return &VirtualKeys{secret: secret} }

// GoString keeps %#v from reaching the secret.
func (*VirtualKeys) GoString() string { return "x402.VirtualKeys" }

// ForPayment is the gateway key of one payment, derived so recovery can return it and so a late or repeated issuance lands on
// the same token: LiteLLM's alias check is check-then-create, but its insert upserts on the token. A wire contract: any change
// strands recovery of every key already sold.
func (k *VirtualKeys) ForPayment(digest string) string {
	return k.derive(virtualKeyDomain, []byte(digest))
}

// ForReference is the gateway key of a Solana Pay reference, so a repeated claim gets the same key. A wire contract as above.
func (k *VirtualKeys) ForReference(reference []byte) string {
	return k.derive(referenceKeyDomain, reference)
}

// ForTransfer is the value of the marker that credits one Solana Pay transaction once.
func (k *VirtualKeys) ForTransfer(id []byte) string { return k.derive(transferKeyDomain, id) }

func (k *VirtualKeys) derive(domain string, input []byte) string {
	derived, err := hkdf.Key(sha256.New, k.secret[:], nil, domain+"\x00"+string(input), sha256.Size)
	if err != nil {
		panic("x402: hkdf refused a constant hash and length: " + err.Error()) // only an unsupported FIPS mode can do this
	}
	return "sk-" + hex.EncodeToString(derived)
}
