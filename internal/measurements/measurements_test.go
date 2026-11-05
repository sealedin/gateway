package measurements_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/egress"
	"github.com/sealedin/gateway/internal/measurements"
)

const (
	syncDate   = "2026-11-05"
	oldHeader  = "last synced on 2026-01-02 from"
	newHeader  = "last synced on " + syncDate + " from"
	knownImage = "a1"
)

func hex96(b string) string { return strings.Repeat(b, 48) }

func entry(version, name, mrtd, rtmr0, image string) measurements.Entry {
	return measurements.Entry{Version: version, Name: name, MRTD: strings.ToUpper(hex96(mrtd)), RuntimeRTMRs: map[string]string{
		"RTMR0": strings.ToUpper(hex96(rtmr0)),
		"RTMR1": strings.ToUpper(hex96(image)),
		"RTMR2": strings.ToUpper(hex96(image[:1] + "2")),
		"RTMR3": strings.ToUpper(hex96(image[:1] + "3")),
	}}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return raw
}

// syncedPolicy is the fixture after list.json: two values inserted in order, the date moved, not another byte changed.
func syncedPolicy(t *testing.T) []byte {
	t.Helper()
	text := string(readTestdata(t, "policy.yaml"))
	text = strings.Replace(text, oldHeader, newHeader, 1)
	text = strings.Replace(text, "    - "+hex96("44")+"\n", "    - "+hex96("33")+"\n    - "+hex96("44")+"\n    - "+hex96("55")+"\n", 1)
	return []byte(text)
}

type run struct {
	code           int
	stdout, stderr string
	policy         []byte
}

// runTool serves body as the list and runs the tool over a copy of policy.
func runTool(t *testing.T, policy []byte, status int, body []byte, extra ...string) run {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, policy, 0o600))
	var stdout, stderr bytes.Buffer
	args := append([]string{"-url", srv.URL, "-policy", path}, extra...)
	now := func() time.Time { return time.Date(2026, time.November, 5, 23, 0, 0, 0, time.UTC) }
	code := measurements.Run(context.Background(), args, &stdout, &stderr, now)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	return run{code, stdout.String(), stderr.String(), got}
}

func TestSyncInsertsNewValuesAndNothingElse(t *testing.T) {
	policy, list := readTestdata(t, "policy.yaml"), readTestdata(t, "list.json")
	first := runTool(t, policy, http.StatusOK, list)
	require.Equal(t, measurements.ExitOK, first.code, first.stderr)
	require.Equal(t, string(syncedPolicy(t)), string(first.policy))
	require.Contains(t, first.stdout, `1.5.0 "new high"`)
	require.Contains(t, first.stdout, `1.5.0 "new low again"`)
	require.NotContains(t, first.stdout, "too old")
	require.NotContains(t, first.stdout, "already pinned")

	again := runTool(t, first.policy, http.StatusOK, list)
	require.Equal(t, measurements.ExitOK, again.code, again.stderr)
	require.Equal(t, string(first.policy), string(again.policy), "a rerun changes no byte, the date included")
}

func TestCheckWritesNothing(t *testing.T) {
	policy, list := readTestdata(t, "policy.yaml"), readTestdata(t, "list.json")
	pending := runTool(t, policy, http.StatusOK, list, "--check")
	require.Equal(t, measurements.ExitChanges, pending.code, pending.stderr)
	require.Equal(t, string(policy), string(pending.policy))
	require.Contains(t, pending.stdout, hex96("33"))

	clean := runTool(t, syncedPolicy(t), http.StatusOK, list, "--check")
	require.Equal(t, measurements.ExitOK, clean.code, clean.stderr)
}

func TestSyncIgnoresEntriesBelowTheMinimumVersion(t *testing.T) {
	policy := readTestdata(t, "policy.yaml")
	feed := mustJSON(t, []measurements.Entry{
		entry("1.3.9", "new rtmr0", "11", "55", knownImage),
		entry("1.3.9", "new image", "11", "22", "b1"),
		entry("1.3.9", "new mrtd", "98", "22", knownImage),
		entry("0.9.0", "malformed", "11", "2", knownImage),
	})
	got := runTool(t, policy, http.StatusOK, feed)
	require.Equal(t, measurements.ExitOK, got.code, got.stderr)
	require.Equal(t, string(policy), string(got.policy))
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}

// Each refused list also carries an addable value, so an unchanged file proves the refusal covers the whole run.
func TestSyncRefuses(t *testing.T) {
	policy := readTestdata(t, "policy.yaml")
	addable := entry("1.5.0", "addable", "11", "55", knownImage)
	listOf := func(e measurements.Entry) []byte { return mustJSON(t, []measurements.Entry{addable, e}) }
	short := entry("1.5.0", "short", "11", "55", knownImage)
	short.RuntimeRTMRs["RTMR0"] = hex96("55")[:95]
	nonHex := entry("1.5.0", "non-hex", "11", "55", knownImage)
	nonHex.MRTD = hex96("zz")
	missing := entry("1.5.0", "missing", "11", "55", knownImage)
	delete(missing.RuntimeRTMRs, "RTMR3")
	tests := []struct {
		name    string
		status  int
		body    []byte
		code    int
		wantErr string
	}{
		{"new mrtd", http.StatusOK, listOf(entry("1.5.0", "odd firmware", "98", "22", knownImage)),
			measurements.ExitError, hex96("98")},
		{"new image", http.StatusOK, listOf(entry("1.6.0", "next build", "11", "22", "b1")),
			measurements.ExitNewImage, `1.6.0 "next build"`},
		{"known rtmr1, other rtmr2 and rtmr3", http.StatusOK, listOf(mixedImage()), measurements.ExitNewImage, `1.6.0 "mixed"`},
		{"new image and new mrtd", http.StatusOK, mustJSON(t, []measurements.Entry{
			entry("1.6.0", "next build", "11", "22", "b1"), entry("1.5.0", "odd firmware", "98", "22", knownImage)}),
			measurements.ExitError, `1.6.0 "next build"`},
		{"short value", http.StatusOK, listOf(short), measurements.ExitError, "96 hex"},
		{"non-hex value", http.StatusOK, listOf(nonHex), measurements.ExitError, "96 hex"},
		{"missing rtmr", http.StatusOK, listOf(missing), measurements.ExitError, "96 hex"},
		{"unparseable version", http.StatusOK, listOf(entry("1.5", "odd version", "11", "22", knownImage)),
			measurements.ExitError, "version"},
		{"empty list", http.StatusOK, []byte(`[]`), measurements.ExitError, "empty"},
		{"not json", http.StatusOK, []byte(`<html>`), measurements.ExitError, "decode"},
		{"http error", http.StatusBadGateway, []byte(`[]`), measurements.ExitError, "502"},
		{"redirect", http.StatusFound, []byte(`[]`), measurements.ExitError, "302"},
		{"name with a line break", http.StatusOK, listOf(entry("1.6.0", "x\n::error::forged", "11", "22", "b1")),
			measurements.ExitNewImage, `1.6.0 "x\n::error::forged"`},
		{"oversized reply", http.StatusOK, bytes.Repeat([]byte(" "), measurements.MaxListBytes+1), measurements.ExitError, "exceeds"},
	}
	for _, tt := range tests {
		for _, mode := range [][]string{nil, {"--check"}} {
			t.Run(tt.name+strings.Join(mode, ""), func(t *testing.T) {
				got := runTool(t, policy, tt.status, tt.body, mode...)
				require.Equal(t, tt.code, got.code)
				require.Contains(t, got.stderr, tt.wantErr)
				require.Equal(t, string(policy), string(got.policy))
			})
		}
	}
}

func mixedImage() measurements.Entry {
	e := entry("1.6.0", "mixed", "11", "22", "b1")
	e.RuntimeRTMRs["RTMR1"] = strings.ToUpper(hex96(knownImage))
	return e
}

func TestApplyRefusesAPolicyItCannotEditSafely(t *testing.T) {
	policy := string(readTestdata(t, "policy.yaml"))
	add := []measurements.Entry{entry("1.5.0", "addable", "11", "55", knownImage)}
	tests := []struct {
		name   string
		policy string
	}{
		{"no date line", strings.Replace(policy, oldHeader, "synced some time ago from", 1)},
		{"comment inside the rtmr0 list", strings.Replace(policy, "    - "+hex96("44"), "    # note\n    - "+hex96("44"), 1)},
		{"uppercase rtmr0 value", strings.Replace(policy, hex96("44"), hex96("AB"), 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := measurements.Apply([]byte(tt.policy), add, syncDate)
			require.Error(t, err)
		})
	}
}

// The committed policy must stay editable by the tool, and an edit must touch only the date and the rtmr0 list.
func TestCommittedPolicyIsSyncable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "egress", "policy.yaml"))
	require.NoError(t, err)
	policy, err := egress.LoadPolicy(bytes.NewReader(raw))
	require.NoError(t, err)
	image := policy.Upstream.TDX.Images[0]
	value := hex96("ff")
	result, err := measurements.Apply(raw, []measurements.Entry{{Version: measurements.MinVersion, Name: "next",
		MRTD: policy.Upstream.TDX.MRTD[0], RuntimeRTMRs: map[string]string{
			"RTMR0": value, "RTMR1": image.RTMR1, "RTMR2": image.RTMR2, "RTMR3": image.RTMR3,
		}}}, "2099-12-31")
	require.NoError(t, err)
	before, after := strings.Split(string(raw), "\n"), strings.Split(string(result.Policy), "\n")
	require.Len(t, after, len(before)+1)
	inserted := slices.Index(after, "    - "+value)
	require.Positive(t, inserted)
	after = slices.Delete(after, inserted, inserted+1)
	var changed []string
	for i := range before {
		if before[i] != after[i] {
			changed = append(changed, after[i])
		}
	}
	require.Len(t, changed, 1)
	require.Contains(t, changed[0], "last synced on 2099-12-31 from "+strings.TrimPrefix(measurements.SourceURL, "https://"))
}
