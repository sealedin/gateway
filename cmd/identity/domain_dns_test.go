package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	dnsAppID   = "0123456789012345678901234567890123456789"
	dnsAccount = "https://acme-v02.api.letsencrypt.org/acme/acct/42"
	dnsPin     = `0 issue "letsencrypt.org; validationmethods=tls-alpn-01; accounturi=` + dnsAccount + `"`
)

// fakeDig answers from a table of "<type> <name>" keys, so the records under test are all the script can see.
func fakeDig(t *testing.T, records map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for key, answer := range records {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "rr "+key), []byte(answer+"\n"), 0o600))
	}
	status := "NOERROR"
	if answer, ok := records["status"]; ok {
		status = answer
	}
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = +noall ]; then echo \";; status: %s,\"; exit 0; fi\n"+
		"cat %q/\"rr $2 $3\" 2>/dev/null\nexit 0\n", status, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dig"), []byte(script), 0o700))
	return dir
}

func TestCheckDomainDNS(t *testing.T) {
	t.Parallel()
	const domain, gateway = "api.example.test", "cluster.example.test"
	good := func() map[string]string {
		return map[string]string{
			"TXT _dstack-app-address." + domain: `"` + dnsAppID + `:443"`,
			"A " + domain:                       "192.0.2.1",
			"A gateway." + gateway:              "192.0.2.1\n192.0.2.2",
			"CAA " + domain:                     dnsPin,
		}
	}
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"the documented records", func(map[string]string) {}, ""},
		{"wildcards refused", func(r map[string]string) { r["CAA "+domain] = dnsPin + "\n" + `0 issuewild ";"` }, ""},
		{"a report address beside the pin", func(r map[string]string) {
			r["CAA "+domain] = dnsPin + "\n" + `0 iodef "mailto:a@b"`
		}, ""},
		{"a CNAME hands CAA to its target", func(r map[string]string) {
			r["CNAME "+domain] = "gateway." + gateway + "."
		}, "must carry A records"},
		{"no address", func(r map[string]string) { delete(r, "A "+domain) }, "no A record"},
		{"a stale address", func(r map[string]string) { r["A "+domain] = "192.0.2.9" }, "not an address"},
		{"an address the gateway lacks", func(r map[string]string) { r["AAAA "+domain] = "2001:db8::1" }, "not an address"},
		{"another app", func(r map[string]string) { r["TXT _dstack-app-address."+domain] = `"abc:443"` }, "expected"},
		{"no pin, the parent would rule", func(r map[string]string) { delete(r, "CAA "+domain) }, "must pin"},
		{"another account", func(r map[string]string) {
			r["CAA "+domain] = strings.Replace(dnsPin, "acct/42", "acct/7", 1)
		}, "expected only"},
		{"a second way in", func(r map[string]string) { r["CAA "+domain] = dnsPin + "\n" + `0 issue "other-ca.example"` }, "expected only"},
		{"a second way in, in capitals", func(r map[string]string) {
			r["CAA "+domain] = dnsPin + "\n" + `0 ISSUE "other-ca.example"`
		}, "expected only"},
		{"a resolver failure is not an absent CNAME", func(r map[string]string) { r["status"] = "SERVFAIL" }, "answered 'SERVFAIL'"},
		{"no account named", func(r map[string]string) { r["CAA "+domain] = `0 issue "letsencrypt.org"` }, "expected only"},
		{"wildcards admitted", func(r map[string]string) {
			r["CAA "+domain] = dnsPin + "\n" + `0 issuewild "letsencrypt.org"`
		}, "wildcards"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			records := good()
			tt.mutate(records)
			cmd := exec.CommandContext(t.Context(), filepath.Join("..", "..", "scripts", "check-domain-dns.sh"), domain)
			cmd.Env = append(os.Environ(), "PATH="+fakeDig(t, records)+":"+os.Getenv("PATH"), "SEALEDIN_EXPECTED_APP_ID="+dnsAppID,
				"SEALEDIN_EXPECTED_GATEWAY="+gateway, "SEALEDIN_EXPECTED_ACME_ACCOUNT="+dnsAccount)
			out, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				require.NoError(t, err, string(out))
				return
			}
			require.Error(t, err, string(out))
			require.Contains(t, string(out), tt.wantErr)
		})
	}
}
