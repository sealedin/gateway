package enclave

// The signed catalog is a wire contract. Its preimage, byte for byte: the ASCII tag "sealedin-catalog-v1", one NUL
// byte, then the canonical JSON of the reply with "signature" removed: a single object, keys in lexicographic order at
// every level, no whitespace, integers unquoted, prices as decimal strings, UTF-8 with only the escapes JSON requires
// (no HTML escaping). `jq -cjS 'del(.signature)'` on the reply reproduces that JSON.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/httpjson"
)

const catalogDomain = "sealedin-catalog-v1" // wire-format tag, frozen at the first published image digest; any change after that bumps it

// Catalog is the signed body: the price sheet and payment terms stamped with the issue time and the enclave key.
type Catalog struct {
	gateway.Catalog

	IssuedAt int64  `json:"issued_at"`
	Pubkey   string `json:"pubkey"`
	FeePayer string `json:"fee_payer,omitempty"` // the x402 sponsor's public key; absent when purchases are off
}

// SignedCatalog is the reply: the body plus its signature.
type SignedCatalog struct {
	Catalog

	Signature string `json:"signature"`
}

// canonicalJSON is what jq -cS prints: keys sorted at every level (the generic round trip lets encoding/json sort
// them), no whitespace, no HTML escaping.
func canonicalJSON(v any) ([]byte, error) {
	typed, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err = json.Unmarshal(typed, &generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err = enc.Encode(generic); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Message is the signed byte string: tag, NUL, canonical JSON of the body.
func (c Catalog) Message() ([]byte, error) {
	body, err := canonicalJSON(c)
	if err != nil {
		return nil, fmt.Errorf("enclave: encode catalog: %w", err)
	}
	msg := make([]byte, 0, len(catalogDomain)+1+len(body))
	msg = append(msg, catalogDomain...)
	msg = append(msg, 0)
	return append(msg, body...), nil
}

// SignCatalog signs the catalog with the enclave key.
func (id *Identity) SignCatalog(c Catalog) ([]byte, error) {
	msg, err := c.Message()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(id.priv, msg), nil
}

// CatalogHandler answers GET /v1/catalog with the signed price sheet and payment terms; unauthenticated, it is
// self-authenticating.
func CatalogHandler(id *Identity, content gateway.Catalog, feePayer func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		catalog := Catalog{Catalog: content, IssuedAt: time.Now().Unix(), Pubkey: id.PublicKeyHex(), FeePayer: feePayer()}
		sig, err := id.SignCatalog(catalog)
		if err != nil {
			writeError(w, err)
			return
		}
		httpjson.Write(w, http.StatusOK, SignedCatalog{Catalog: catalog, Signature: hex.EncodeToString(sig)})
	}
}
