package x402

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/gagliardetto/solana-go"
)

// FeePayer holds the sponsor key; only its public half ever prints.
type FeePayer struct {
	key ed25519.PrivateKey
}

// NewFeePayer wraps the key the operators hold, which reaches this service alone through the sealed env.
func NewFeePayer(key ed25519.PrivateKey) *FeePayer { return &FeePayer{key: key} }

// ParseFeePayerKey reads a key in wallet form, the base58 of seed and public key, and never repeats it in an error.
func ParseFeePayerKey(text string) (ed25519.PrivateKey, error) {
	key, err := solana.PrivateKeyFromBase58(text)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("fee payer key must be the base58 of a 64-byte Solana keypair")
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) {
		return nil, errors.New("fee payer key: the public half is not the seed's")
	}
	return derived, nil
}

// Public is the account that pays the fees.
func (f *FeePayer) Public() solana.PublicKey {
	return solana.PublicKeyFromBytes(f.key[ed25519.SeedSize:])
}

func (f *FeePayer) String() string { return f.Public().String() }

// GoString keeps %#v from reaching the key.
func (f *FeePayer) GoString() string { return f.String() }

// TransactionID is the sponsor's signature over the message, which is the transaction's on-chain id. Holding it is holding
// a broadcastable transaction, so nothing computes it before simulation passed, unless the id is already public.
func (f *FeePayer) TransactionID(pay Payment) solana.Signature {
	return solana.SignatureFromBytes(ed25519.Sign(f.key, pay.message()))
}

// CoSign returns the fully signed transaction bytes.
func (f *FeePayer) CoSign(pay Payment) []byte {
	out := append([]byte(nil), pay.Raw...)
	id := f.TransactionID(pay)
	copy(out[signaturesPrefixLen:], id[:])
	return out
}
