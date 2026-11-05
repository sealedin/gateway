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
	"gopkg.in/yaml.v3"
)

func TestRunRejectsBadFlag(t *testing.T) {
	t.Parallel()
	require.Equal(t, exitUsage, run(context.Background(), []string{"-nope"}, io.Discard))
}

func TestWireRefusesABadTarget(t *testing.T) {
	t.Parallel()
	_, err := wire("not a url", slog.New(slog.DiscardHandler))
	require.Error(t, err)
	require.Equal(t, exitUsage, run(context.Background(), []string{"-gateway", "::"}, io.Discard))
}

// The host must wait out the shutdown budget and the flush wait, or what finishes last goes unbilled; the gateway outlasts it.
func TestComposeWaitsOutTheShutdown(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	var compose struct {
		Services map[string]struct {
			StopGracePeriod string   `yaml:"stop_grace_period"`
			DependsOn       []string `yaml:"depends_on"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &compose))
	grace, err := time.ParseDuration(compose.Services["drain"].StopGracePeriod)
	require.NoError(t, err)
	require.Greater(t, grace, shutdownBudget+defaultFlushWait)
	require.Contains(t, compose.Services["drain"].DependsOn, "gateway", "compose stops the drain first")
}

func TestRunServesAndStops(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"-listen", addr, "-gateway", "http://127.0.0.1:1", "-flush-wait", "0s"}, io.Discard)
	}()
	require.Eventually(t, func() bool {
		req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/v1/messages", strings.NewReader("{}"))
		if reqErr != nil {
			return false
		}
		req.Header.Set("X-Api-Key", "sk-a")
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusBadGateway
	}, 5*time.Second, 20*time.Millisecond)
	cancel()
	select {
	case code := <-done:
		require.Equal(t, exitOK, code)
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit")
	}
}
