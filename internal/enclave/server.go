package enclave

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/sealedin/gateway/internal/httpjson"
)

// ErrEdgeUnavailable is returned when the edge TLS certificate cannot be fetched.
var ErrEdgeUnavailable = errors.New("enclave: edge certificate unavailable")

// ErrBadBlockID is returned when the query string or its block_id parameter cannot be parsed.
var ErrBadBlockID = errors.New("enclave: block_id must be hex of at most 64 characters (0x prefix allowed)")

const (
	pubkeyField       = "pubkey"        // JSON key every identity reply names the enclave key under
	reportDataVersion = 2               // a client on the old REPORT_DATA layout fails loudly instead of misreading
	freshQuoteBudget  = 8 * time.Second // under cmd/identity's write timeout, so a completed fetch is deliverable
)

// NewMux is the whole plaintext surface: the quote and the TLS endorsement; the price lives on the private listener.
func NewMux(id *Identity, edge CertSource) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, r *http.Request) {
		handleQuote(w, r, id)
	})
	mux.HandleFunc("GET /v1/tls", func(w http.ResponseWriter, r *http.Request) {
		handleTLS(w, r, id, edge)
	})
	return mux
}

// handleQuote parses the query strictly: url.Query drops a malformed pair and would downgrade to the startup quote.
func handleQuote(w http.ResponseWriter, r *http.Request, id *Identity) {
	query, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		writeError(w, fmt.Errorf("%w: malformed query string", ErrBadBlockID))
		return
	}
	blockID, fresh, err := parseBlockID(query.Get("block_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	var quote []byte
	if fresh {
		ctx, cancel := context.WithTimeout(r.Context(), freshQuoteBudget)
		defer cancel()
		quote, err = id.QuoteFor(ctx, blockID)
	} else {
		quote, err = id.StartupQuote()
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if fresh {
		slog.Info("enclave: fresh quote served", "block_id", hex.EncodeToString(blockID[:]))
	}
	reply := map[string]any{
		"quote":               base64.StdEncoding.EncodeToString(quote),
		pubkeyField:           id.PublicKeyHex(),
		"block_id":            hex.EncodeToString(blockID[:]),
		"report_data_version": reportDataVersion,
	}
	if id.Attested() {
		reply["event_log"] = json.RawMessage(id.EventLog())
	}
	httpjson.Write(w, http.StatusOK, reply)
}

// parseBlockID takes hex up to 64 chars, optional 0x, right-aligned into 32 bytes; empty means no fresh quote.
func parseBlockID(raw string) ([BlockIDSize]byte, bool, error) {
	var blockID [BlockIDSize]byte
	if raw == "" {
		return blockID, false, nil
	}
	if len(raw) >= 2 && (raw[:2] == "0x" || raw[:2] == "0X") {
		raw = raw[2:]
	}
	if raw == "" || len(raw) > 2*BlockIDSize {
		return blockID, false, ErrBadBlockID
	}
	if len(raw)%2 == 1 {
		raw = "0" + raw
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return blockID, false, ErrBadBlockID
	}
	copy(blockID[BlockIDSize-len(decoded):], decoded)
	return blockID, true, nil
}

// handleTLS serves the signed endorsement of the current edge leaf.
func handleTLS(w http.ResponseWriter, r *http.Request, id *Identity, edge CertSource) {
	if edge == nil {
		writeError(w, ErrEdgeUnavailable)
		return
	}
	leaf, err := edge(r.Context())
	if err != nil {
		writeError(w, fmt.Errorf("%w: %w", ErrEdgeUnavailable, err))
		return
	}
	endorsement := Endorsement{
		SPKISHA256: sha256.Sum256(leaf.RawSubjectPublicKeyInfo),
		NotAfter:   leaf.NotAfter,
	}
	httpjson.Write(w, http.StatusOK, map[string]any{
		"spki_sha256": hex.EncodeToString(endorsement.SPKISHA256[:]),
		"not_after":   endorsement.NotAfter.Unix(),
		pubkeyField:   id.PublicKeyHex(),
		"signature":   hex.EncodeToString(id.Endorse(endorsement)),
	})
}

// writeError maps the sentinels to 404/400/503; anything else stays generic so internals never reach a client.
func writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotAttested):
		httpjson.Error(w, http.StatusNotFound, ErrNotAttested.Error())
	case errors.Is(err, ErrBadBlockID):
		httpjson.Error(w, http.StatusBadRequest, ErrBadBlockID.Error())
	case errors.Is(err, ErrAttestationBroken):
		slog.Error("enclave: attestation broken", "err", err)
		httpjson.Error(w, http.StatusServiceUnavailable, ErrAttestationBroken.Error())
	case errors.Is(err, ErrQuoteUnavailable):
		slog.Warn("enclave: fresh quote failed", "err", err)
		httpjson.Error(w, http.StatusServiceUnavailable, ErrQuoteUnavailable.Error())
	case errors.Is(err, ErrEdgeUnavailable):
		slog.Warn("enclave: edge certificate fetch failed", "err", err)
		httpjson.Error(w, http.StatusServiceUnavailable, ErrEdgeUnavailable.Error())
	default:
		slog.Error("enclave: request failed", "err", err)
		httpjson.Error(w, http.StatusInternalServerError, "internal error")
	}
}
