package httpjson_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/httpjson"
)

func TestWrite(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	httpjson.Write(rec, http.StatusCreated, map[string]int{"n": 1})
	require.Equal(t, http.StatusCreated, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.JSONEq(t, `{"n":1}`, rec.Body.String())

	rec = httptest.NewRecorder()
	httpjson.Write(rec, http.StatusOK, make(chan int))
	require.Equal(t, http.StatusInternalServerError, rec.Code, "an unencodable value is a 500, never a half body")

	rec = httptest.NewRecorder()
	httpjson.Error(rec, http.StatusNotFound, "nope")
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.JSONEq(t, `{"error":"nope"}`, rec.Body.String())
}

func TestDecodeStrict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, body string
		wantStatus int // 0 for success
	}{
		{"one value", `{"a":1}`, 0},
		{"unknown field", `{"b":1}`, http.StatusBadRequest},
		{"trailing data", `{"a":1}{"a":2}`, http.StatusBadRequest},
		{"stray closing brace", `{"a":1}}`, http.StatusBadRequest},
		{"not json", `nope`, http.StatusBadRequest},
		{"too large", `{"a":"` + strings.Repeat("x", 64) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var v struct {
				A int `json:"a"`
			}
			err := httpjson.DecodeStrict(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), 32, &v)
			if tc.wantStatus == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Equal(t, tc.wantStatus, httpjson.DecodeStatus(err))
		})
	}
}
