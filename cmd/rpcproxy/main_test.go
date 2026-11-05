package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	devPolicy         = "primary: {url: 'https://rpc.test/', api_key_param: api-key}\nconfirmation: {url: 'https://other.test/'}\n"
	placeholderPolicy = "primary: {url: 'https://rpc.invalid/', api_key_param: api-key}\nconfirmation: {url: 'https://other.test/'}\n"
)

func writePolicy(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
	return path
}

func TestRunRejectsBadFlag(t *testing.T) {
	t.Parallel()
	require.Equal(t, exitUsage, run(context.Background(), []string{"-nope"}, io.Discard))
}

func TestWire(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	measured := filepath.Join("..", "..", "rpcproxy", "policy.yaml")
	tests := []struct {
		name, path, key, wantErr string
	}{
		{"missing file", filepath.Join(t.TempDir(), "absent"), "k", "policy"},
		{"bad policy", writePolicy(t, "primary: {url: 'http://rpc.test/'}\n"), "k", "https"},
		{"placeholder refuses to start", writePolicy(t, placeholderPolicy), "k", "placeholder"},
		{"measured", measured, "k", ""},
		{"missing key", writePolicy(t, devPolicy), "", "no key"},
		{"good", writePolicy(t, devPolicy), "k", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := wire(tc.path, tc.key, logger)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestClientFollowsNoRedirect(t *testing.T) {
	t.Parallel()
	client := newClient()
	require.ErrorIs(t, client.CheckRedirect(nil, nil), http.ErrUseLastResponse)
}

// run serves the routes and shuts down on cancel; the variable needs a non-parallel test.
func TestRunServesAndStops(t *testing.T) {
	t.Setenv(apiKeyEnv, "k")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	policy := writePolicy(t, devPolicy)
	go func() { done <- run(ctx, []string{"-listen", addr, "-policy", policy}, io.Discard) }()
	require.Eventually(t, func() bool {
		body := strings.NewReader(`{"method":"getBalance"}`)
		req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/primary", body)
		if reqErr != nil {
			return false
		}
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusForbidden
	}, 5*time.Second, 20*time.Millisecond)
	cancel()
	select {
	case code := <-done:
		require.Equal(t, exitOK, code)
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit")
	}
}
