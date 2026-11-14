package main

import (
	"bytes"
	"context"
	"fmt"
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

// A policy with a second family needs that family's key, and routes only models the measured allowlist holds.
func TestRunRefusesASecondFamilyItCannotServe(t *testing.T) {
	measured, err := os.ReadFile(filepath.Join("..", "..", "egress", "policy.yaml"))
	require.NoError(t, err)
	const block = `
near:
  models: [%s]
  api: https://cloud-api.near.ai
  guests:
    - mrtd: 7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173
      rtmr0: d090162bff4b1d1dc74dc59dc548838efc4b811b173da8536efa8e2a9c045da70ee092301293ad90afebee448bcd0211
      rtmr1: 4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec
      rtmr2: 764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d
  td_attributes: "0000001000000000"
  xfam: e702060000000000
  app_ids: [f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae]
  key_providers: [7b7d]
`
	tests := []struct{ name, model, nearKey, want string }{
		{"no key for it", "Qwen/Qwen3.8-27B-TEE", "", "NEARAI_API_KEY"},
		{"a model outside the allowlist", "not/measured", "sk-x", "not in the measured allowlist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := filepath.Join(t.TempDir(), "policy.yaml")
			require.NoError(t, os.WriteFile(policy, append(measured, []byte(fmt.Sprintf(block, tt.model))...), 0o600))
			t.Setenv("CHUTES_API_KEY", "cpk_x")
			t.Setenv("NEARAI_API_KEY", tt.nearKey)
			var stderr bytes.Buffer
			require.Equal(t, exitUsage, run(context.Background(), []string{"-policy", policy}, &stderr))
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
		"FROM gcr.io/distroless/static-debian13@sha256:"} {
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
