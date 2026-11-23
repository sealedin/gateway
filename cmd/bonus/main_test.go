package main

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/sealedin/gateway/internal/bonus"
)

func TestWireRefusesPlainHTTPAndUnboundedPromotions(t *testing.T) {
	t.Setenv(operatorEnv, "token")
	t.Setenv(clientIDEnv, "client")
	logger := slog.New(slog.DiscardHandler)
	ledger := filepath.Join(t.TempDir(), "ledger")
	good := bonus.Config{PublicURL: "https://bonus.example", Account: "ours", BudgetUSD: 10, RPMLimit: 20, MaxKeys: 5}
	if _, err := wire(good, "https://api.example", ledger, logger); err != nil {
		t.Fatalf("a good config: %v", err)
	}
	unbounded := good
	unbounded.MaxKeys = 0
	plain := good
	plain.PublicURL = "http://bonus.example"
	for name, c := range map[string]struct {
		cfg     bonus.Config
		gateway string
	}{
		"no cap":         {unbounded, "https://api.example"},
		"plain callback": {plain, "https://api.example"},
		"plain gateway":  {good, "http://api.example"},
	} {
		if _, err := wire(c.cfg, c.gateway, ledger, logger); err == nil {
			t.Errorf("%s: wired", name)
		}
	}
}
