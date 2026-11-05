package enclave_test

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/enclave"
)

// quoteReportDataOffset mirrors the TDX v4 layout the client checks: REPORT_DATA at byte 568 of the quote.
const quoteReportDataOffset = 568

const sampleEventLog = `[{"imr":3,"event_type":134217729,"digest":"00","event":"compose-hash","event_payload":"ab"}]`

// quoteBinding builds a structurally minimal quote whose REPORT_DATA field carries reportData.
func quoteBinding(reportData [enclave.ReportDataSize]byte) []byte {
	quote := make([]byte, quoteReportDataOffset+enclave.ReportDataSize+16)
	copy(quote[quoteReportDataOffset:], reportData[:])
	return quote
}

// fakeAgent serves a dstack-style GetQuote on a Unix socket and records the report_data it was asked to bind.
type fakeAgent struct {
	socket string
	reply  func(reportData string) (int, map[string]string)
	asked  string
}

// listenFakeAgent serves handler on a fresh Unix socket and returns its path.
func listenFakeAgent(t *testing.T, handler http.Handler) string {
	t.Helper()
	// macOS caps Unix socket paths at 104 bytes; t.TempDir embeds the test name and can exceed that.
	dir, err := os.MkdirTemp("", "ds") //nolint:usetesting // socket path length, see above
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return socket
}

func newFakeAgent(t *testing.T, reply func(reportData string) (int, map[string]string)) *fakeAgent {
	t.Helper()
	agent := &fakeAgent{reply: reply}
	agent.socket = listenFakeAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/GetQuote" {
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		var req struct {
			ReportData string `json:"report_data"`
		}
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		agent.asked = req.ReportData
		status, body := agent.reply(req.ReportData)
		w.WriteHeader(status)
		assert.NoError(t, json.NewEncoder(w).Encode(body))
	}))
	return agent
}

func testReportData() [enclave.ReportDataSize]byte {
	var rd [enclave.ReportDataSize]byte
	for i := range rd {
		rd[i] = byte(i)
	}
	return rd
}

// honestReply is what a working agent answers: a quote binding the asked data, the echo, and a boot event log.
func honestReply(reportData string) (int, map[string]string) {
	rd, _ := hex.DecodeString(reportData)
	var fixed [enclave.ReportDataSize]byte
	copy(fixed[:], rd)
	return http.StatusOK, map[string]string{
		"quote":       hex.EncodeToString(quoteBinding(fixed)),
		"event_log":   sampleEventLog,
		"report_data": reportData,
	}
}

func TestFetchEvidenceDstackBindsReportData(t *testing.T) {
	rd := testReportData()
	agent := newFakeAgent(t, honestReply)

	quote, eventLog, err := enclave.FetchEvidenceDstack(agent.socket, rd)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(rd[:]), agent.asked, "the agent must be asked for our 64 raw bytes")
	require.Equal(t, quoteBinding(rd), quote)
	require.JSONEq(t, sampleEventLog, string(eventLog))
}

func TestFetchEvidenceDstackFailsClosed(t *testing.T) {
	rd := testReportData()
	ours := hex.EncodeToString(rd[:])
	var foreign [enclave.ReportDataSize]byte
	cases := []struct {
		name  string
		reply func(string) (int, map[string]string)
		want  string
	}{
		{"agent error", func(string) (int, map[string]string) {
			return http.StatusInternalServerError, map[string]string{"error": "qgs down"}
		}, "HTTP 500"},
		{"quote not hex", func(string) (int, map[string]string) {
			return http.StatusOK, map[string]string{"quote": "zz", "report_data": ours, "event_log": sampleEventLog}
		}, "not hex"},
		{"quote too short to carry report_data", func(string) (int, map[string]string) {
			return http.StatusOK, map[string]string{"quote": "0102", "report_data": ours, "event_log": sampleEventLog}
		}, "does not bind"},
		{"quote binds someone else's data", func(string) (int, map[string]string) {
			return http.StatusOK, map[string]string{
				"quote": hex.EncodeToString(quoteBinding(foreign)), "report_data": ours, "event_log": sampleEventLog,
			}
		}, "does not bind"},
		{"echo disagrees with the quote", func(string) (int, map[string]string) {
			return http.StatusOK, map[string]string{
				"quote": hex.EncodeToString(quoteBinding(rd)), "report_data": hex.EncodeToString(foreign[:]),
				"event_log": sampleEventLog,
			}
		}, "echoed report_data"},
		{"echo missing", func(string) (int, map[string]string) {
			return http.StatusOK, map[string]string{"quote": hex.EncodeToString(quoteBinding(rd)), "event_log": sampleEventLog}
		}, "echoed report_data"},
		{"event log missing", func(string) (int, map[string]string) {
			return http.StatusOK, map[string]string{"quote": hex.EncodeToString(quoteBinding(rd)), "report_data": ours}
		}, "no event log"},
		{"event log not JSON", func(string) (int, map[string]string) {
			return http.StatusOK, map[string]string{
				"quote": hex.EncodeToString(quoteBinding(rd)), "report_data": ours, "event_log": "{broken",
			}
		}, "no event log"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			agent := newFakeAgent(t, tc.reply)
			_, _, err := enclave.FetchEvidenceDstack(agent.socket, rd)
			require.ErrorContains(t, err, tc.want)
			require.NotErrorIs(t, err, enclave.ErrNotAttested, "a present but failing agent is never dev mode")
		})
	}
}

// A socket nobody listens on or an unreadable path is a hard error; only a missing socket means dev mode.
func TestFetchEvidenceDispatch(t *testing.T) {
	rd := testReportData()
	agent := newFakeAgent(t, honestReply)
	quote, eventLog, err := enclave.FetchEvidenceFrom(agent.socket, rd)
	require.NoError(t, err)
	require.Equal(t, quoteBinding(rd), quote)
	require.NotEmpty(t, eventLog)

	dir := t.TempDir()
	dead := filepath.Join(dir, "dead.sock")
	require.NoError(t, os.WriteFile(dead, nil, 0o600))
	_, _, err = enclave.FetchEvidenceFrom(dead, rd)
	require.Error(t, err)
	require.NotErrorIs(t, err, enclave.ErrNotAttested, "a socket path with no agent behind it is a hard error")

	notDir := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(notDir, nil, 0o600))
	_, _, err = enclave.FetchEvidenceFrom(filepath.Join(notDir, "a.sock"), rd)
	require.Error(t, err)
	require.NotErrorIs(t, err, enclave.ErrNotAttested, "an unreadable socket path is a hard error, not dev mode")

	_, _, err = enclave.FetchEvidenceFrom(filepath.Join(dir, "absent.sock"), rd)
	require.ErrorIs(t, err, enclave.ErrNotAttested, "no socket must read as unattested")
}
