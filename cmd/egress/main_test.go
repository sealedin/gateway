package main

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/gateway"
)

func TestRunRefusesToStartWithoutKeyOrPolicy(t *testing.T) {
	policy := filepath.Join("..", "..", "egress", "policy.yaml")
	tests := []struct {
		name string
		key  string
		args []string
		want string
	}{
		{"no api key", "", []string{"-policy", policy}, "CHUTES_API_KEY"},
		{"no policy file", "cpk_x", []string{"-policy", filepath.Join(t.TempDir(), "missing.yaml")}, "policy"},
		{"bad flag", "cpk_x", []string{"-nope"}, "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CHUTES_API_KEY", tt.key)
			var stderr bytes.Buffer
			require.Equal(t, exitUsage, run(context.Background(), tt.args, &stderr))
			require.Contains(t, stderr.String(), tt.want)
		})
	}
}

// syncBuffer lets the test read stderr while run writes it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunServesAndStopsOnCancel(t *testing.T) {
	t.Setenv("CHUTES_API_KEY", "cpk_x")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var stderr syncBuffer
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-policy", filepath.Join("..", "..", "egress", "policy.yaml")}, &stderr)
	}()
	require.Eventually(t, func() bool { return strings.Contains(stderr.String(), "egress listening") }, 5*time.Second,
		10*time.Millisecond)
	cancel()
	select {
	case code := <-done:
		require.Equal(t, exitOK, code, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("egress did not stop on cancel")
	}
	require.Contains(t, stderr.String(), "egress policy loaded")
}

// Dockerfile.egress must build with the same toolchain and flags as the identity image's Dockerfile.
func TestEgressDockerfileBuildsLikeIdentity(t *testing.T) {
	identity, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	require.NoError(t, err)
	egress, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile.egress"))
	require.NoError(t, err)
	for _, line := range []string{"FROM golang@sha256:", "ENV GOTOOLCHAIN=local", "RUN CGO_ENABLED=0 go build",
		"FROM gcr.io/distroless/static-debian12@sha256:"} {
		want := lineContaining(string(identity), line)
		require.NotEmpty(t, want, line)
		require.Contains(t, string(egress), want, "Dockerfile.egress drifted from Dockerfile on: %s", line)
	}
	require.Contains(t, string(egress), `-ldflags "-s -w -buildid="`)
}

func lineContaining(text, needle string) string {
	for l := range strings.SplitSeq(text, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// The gateway's measured api_base literal and the egress listen port are written in two places; keep them tied.
func TestDefaultListenMatchesGatewayEgressBase(t *testing.T) {
	_, port, err := net.SplitHostPort(defaultListen)
	require.NoError(t, err)
	base, err := url.Parse(gateway.EgressBase)
	require.NoError(t, err)
	require.Equal(t, base.Port(), port)
}
