package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sealedin/gateway/internal/coinpay"
)

func TestWireRefusesPlainHTTPUnboundedSalesAndUnplacedPayouts(t *testing.T) {
	t.Setenv(operatorEnv, "token")
	logger := slog.New(slog.DiscardHandler)
	dir := t.TempDir()
	payouts := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := coinpay.Config{PublicURL: "https://pay.example", SiteURL: "https://site.example", MinUSD: 20, MaxUSD: 500,
		RPMLimit: 60, QuoteTTL: time.Hour}
	opts := options{gatewayURL: "https://api.example", forwarder: "https://forwarder.example",
		payoutsFile: payouts("good", `{"btc":"bc1qexample","evm":"0xexample"}`), ordersFile: filepath.Join(dir, "orders"),
		keepKeys: time.Hour, keepUnpaid: time.Hour}
	if _, err := wire(good, opts, logger); err != nil {
		t.Fatalf("a good config: %v", err)
	}
	for name, change := range map[string]func(*coinpay.Config, *options){
		"plain callback":  func(c *coinpay.Config, _ *options) { c.PublicURL = "http://pay.example" },
		"plain gateway":   func(_ *coinpay.Config, o *options) { o.gatewayURL = "http://api.example" },
		"plain forwarder": func(_ *coinpay.Config, o *options) { o.forwarder = "http://forwarder.example" },
		"no ceiling":      func(c *coinpay.Config, _ *options) { c.MaxUSD = 0 },
		"no payouts":      func(_ *coinpay.Config, o *options) { o.payoutsFile = payouts("empty", `{}`) },
		"unknown kind":    func(_ *coinpay.Config, o *options) { o.payoutsFile = payouts("typo", `{"bitcoin":"bc1qexample"}`) },
		"missing file":    func(_ *coinpay.Config, o *options) { o.payoutsFile = filepath.Join(dir, "absent") },
	} {
		cfg, changed := good, opts
		change(&cfg, &changed)
		if _, err := wire(cfg, changed, logger); err == nil {
			t.Errorf("%s: wired", name)
		}
	}
}

func TestWireNeedsTheOperatorToken(t *testing.T) {
	t.Setenv(operatorEnv, "")
	if _, err := wire(coinpay.Config{}, options{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("wired with no operator token")
	}
}
