// Package httpjson writes the JSON replies every HTTP surface in this repo shares.
package httpjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Write encodes v as the response body with status; an unencodable value is a 500, never a half-written body.
func Write(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "encoding failure", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Error writes the {"error": msg} envelope the identity and egress endpoints answer failures with.
func Error(w http.ResponseWriter, status int, msg string) {
	Write(w, status, map[string]string{"error": msg})
}

// DecodeStrict reads exactly one JSON value of at most limit bytes into v: unknown fields and trailing data are errors.
func DecodeStrict(r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid body: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid body: trailing data")
	}
	return nil
}

// DecodeStatus is the HTTP status of a DecodeStrict failure.
func DecodeStatus(err error) int {
	if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
