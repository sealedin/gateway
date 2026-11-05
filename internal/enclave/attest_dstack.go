package enclave

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	dstackTimeout     = 30 * time.Second // a wedged agent must not hang startup or a fresh-quote request
	dstackMaxResponse = 4 << 20          // a quote is a few KB, the event log a few hundred KB
	// quoteReportDataOffset is REPORT_DATA in a TDX v4 quote: 48-byte header plus TD10 body offset 520.
	quoteReportDataOffset = 568
)

// postDstack is one call of the agent's frozen v0 API over its socket: one connection, bounded time and size.
func postDstack(ctx context.Context, socket, route string, request any) ([]byte, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("dstack: encode request: %w", err)
	}
	// One connection per call: a kept-alive transport would leak an idle socket per request.
	client := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
	ctx, cancel := context.WithTimeout(ctx, dstackTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://dstack/"+route, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("dstack: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dstack: %s: %w", route, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, dstackMaxResponse))
	if err != nil {
		return nil, fmt.Errorf("dstack: read %s reply: %w", route, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dstack: %s returned HTTP %d: %.200s", route, resp.StatusCode, raw)
	}
	return raw, nil
}

// fetchEvidenceDstack is the agent's GetQuote: raw REPORT_DATA in, quote plus RTMR3 event log out.
func fetchEvidenceDstack(socket string, reportData [ReportDataSize]byte) (evidence, error) {
	// The quote fetch has no caller context: QuoteFor bounds it through the slot, startup through dstackTimeout.
	raw, err := postDstack(context.Background(), socket, "GetQuote",
		map[string]string{"report_data": hex.EncodeToString(reportData[:])})
	if err != nil {
		return evidence{}, err
	}
	var reply struct {
		Quote      string `json:"quote"`
		EventLog   string `json:"event_log"`
		ReportData string `json:"report_data"`
	}
	if decodeErr := json.Unmarshal(raw, &reply); decodeErr != nil {
		return evidence{}, fmt.Errorf("dstack: decode GetQuote reply: %w", decodeErr)
	}
	quote, err := hex.DecodeString(reply.Quote)
	if err != nil {
		return evidence{}, fmt.Errorf("dstack: quote is not hex: %w", err)
	}
	// The quote bytes are the authority; the echo disagreeing means a quote for someone else's data.
	if len(quote) < quoteReportDataOffset+ReportDataSize ||
		!bytes.Equal(quote[quoteReportDataOffset:quoteReportDataOffset+ReportDataSize], reportData[:]) {
		return evidence{}, errors.New("dstack: quote does not bind our report_data")
	}
	if reply.ReportData != hex.EncodeToString(reportData[:]) {
		return evidence{}, fmt.Errorf("dstack: GetQuote echoed report_data %q, not ours", reply.ReportData)
	}
	// dstack always measures the workload at boot, so a missing log is a broken agent.
	if !json.Valid([]byte(reply.EventLog)) {
		return evidence{}, errors.New("dstack: GetQuote reply carries no event log")
	}
	return evidence{quote: quote, eventLog: []byte(reply.EventLog)}, nil
}
