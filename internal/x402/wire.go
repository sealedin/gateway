package x402

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

const (
	// HeaderRequired carries the challenge (transports-v2/http.md).
	HeaderRequired = "PAYMENT-REQUIRED"
	// HeaderSignature carries the client's payment.
	HeaderSignature = "PAYMENT-SIGNATURE"
	// HeaderResponse carries the settlement result.
	HeaderResponse = "PAYMENT-RESPONSE"

	// Version is the x402 protocol version of every object here.
	Version = 2
	scheme  = "exact"
	// MaxTimeoutSeconds is the challenge's maxTimeoutSeconds: how long settlement waits for confirmation.
	MaxTimeoutSeconds = 60
	// maxPayloadBytes bounds PAYMENT-SIGNATURE: a 1232-byte transaction in base64, in JSON with its requirements, in base64.
	maxPayloadBytes = 8 << 10
	timestampBytes  = 8
)

// recoverDomain tags the message a payer signs to recover a key; wire format, bumped on any layout change.
const recoverDomain = "sealedin-key-recover-v1"

// RecoverMessage is what the payer's wallet signs: the tag, one NUL, the 64-byte transaction signature, the 8-byte
// big-endian unix time.
func RecoverMessage(id solana.Signature, unixSeconds int64) []byte {
	msg := make([]byte, 0, len(recoverDomain)+1+len(id)+timestampBytes)
	msg = append(msg, recoverDomain...)
	msg = append(msg, 0)
	msg = append(msg, id[:]...)
	return binary.BigEndian.AppendUint64(msg, uint64(unixSeconds)) //nolint:gosec // the caller checked it is recent
}

// VerifyRecoverProof says whether the payer's wallet signed the recovery message.
func VerifyRecoverProof(payer solana.PublicKey, id solana.Signature, unixSeconds int64, proof solana.Signature) bool {
	return ed25519.Verify(payer[:], RecoverMessage(id, unixSeconds), proof[:])
}

// Resource names what the payment buys.
type Resource struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// Extra is the scheme's extra object; the blockhash fields are construction hints, never checked.
type Extra struct {
	FeePayer             string `json:"feePayer"`
	RecentBlockhash      string `json:"recentBlockhash,omitempty"`
	LastValidBlockHeight string `json:"lastValidBlockHeight,omitempty"`
}

// Requirements is one entry of accepts[].
type Requirements struct {
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	Amount            string `json:"amount"`
	Asset             string `json:"asset"`
	PayTo             string `json:"payTo"`
	MaxTimeoutSeconds int    `json:"maxTimeoutSeconds"`
	Extra             Extra  `json:"extra"`
}

// Required is the object PAYMENT-REQUIRED carries.
type Required struct {
	X402Version int            `json:"x402Version"`
	Error       string         `json:"error,omitempty"`
	Resource    Resource       `json:"resource"`
	Accepts     []Requirements `json:"accepts"`
}

// Payload is the object PAYMENT-SIGNATURE carries.
type Payload struct {
	X402Version int          `json:"x402Version"`
	Resource    Resource     `json:"resource"`
	Accepted    Requirements `json:"accepted"`
	Payload     struct {
		Transaction string `json:"transaction"`
	} `json:"payload"`
}

// Settlement is the object PAYMENT-RESPONSE carries.
type Settlement struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason,omitempty"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer,omitempty"`
}

// EncodeHeader is the base64 of the JSON the three headers carry.
func EncodeHeader(v any) (string, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("x402: encode header: %w", err)
	}
	return base64.StdEncoding.EncodeToString(body), nil
}

// DecodePayload reads PAYMENT-SIGNATURE and returns the payload with the transaction bytes it carries.
func DecodePayload(header string) (Payload, []byte, error) {
	if len(header) > maxPayloadBytes {
		return Payload{}, nil, errors.New("x402: payment header too large")
	}
	body, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return Payload{}, nil, fmt.Errorf("x402: payment header: %w", err)
	}
	var payload Payload
	if err = json.Unmarshal(body, &payload); err != nil {
		return Payload{}, nil, fmt.Errorf("x402: payment payload: %w", err)
	}
	if payload.X402Version != Version {
		return Payload{}, nil, fmt.Errorf("x402: unsupported x402Version %d", payload.X402Version)
	}
	raw, err := base64.StdEncoding.DecodeString(payload.Payload.Transaction)
	if err != nil {
		return Payload{}, nil, fmt.Errorf("x402: payment transaction: %w", err)
	}
	return payload, raw, nil
}
