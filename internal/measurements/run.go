package measurements

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// ExitOK means the policy is current, or was just brought up to date.
	ExitOK = 0
	// ExitError covers usage, fetch and parse failures and an unknown MRTD.
	ExitError = 1
	// ExitChanges means --check found values the sync would add.
	ExitChanges = 2
	// ExitNewImage means the list names a guest image the policy does not pin.
	ExitNewImage = 3

	fetchTimeout = 30 * time.Second
	dateLayout   = time.DateOnly
)

// Run is the command: it fetches the list and updates, or with --check only reports on, the policy file.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, now func() time.Time) int {
	flags := flag.NewFlagSet("sync-measurements", flag.ContinueOnError)
	flags.SetOutput(stderr)
	check := flags.Bool("check", false, "write nothing, print what would change, exit "+strconv.Itoa(ExitChanges)+" if anything would")
	policyPath := flags.String("policy", "egress/policy.yaml", "policy file to update")
	url := flags.String("url", SourceURL, "measurement list")
	if err := flags.Parse(args); err != nil {
		return ExitError
	}
	code, err := syncPolicy(ctx, *url, *policyPath, *check, stdout, now)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sync-measurements:", err)
	}
	return code
}

func syncPolicy(ctx context.Context, url, path string, check bool, stdout io.Writer, now func() time.Time) (int, error) {
	entries, err := fetch(ctx, url)
	if err != nil {
		return ExitError, err
	}
	policy, err := os.ReadFile(path) //nolint:gosec // the -policy path of a command run by hand or in CI
	if err != nil {
		return ExitError, err
	}
	result, err := Apply(policy, entries, now().UTC().Format(dateLayout))
	if errors.Is(err, ErrNewImage) && !errors.Is(err, ErrUnknownMRTD) {
		return ExitNewImage, err
	}
	if err != nil {
		return ExitError, err
	}
	if len(result.Added) == 0 {
		_, _ = fmt.Fprintln(stdout, "policy is up to date")
		return ExitOK, nil
	}
	verb := "added"
	if check {
		verb = "would add"
	}
	for _, a := range result.Added {
		_, _ = fmt.Fprintf(stdout, "%s rtmr0 %s: %s\n", verb, a.Value, strings.Join(a.Sources, ", "))
	}
	if check {
		return ExitChanges, nil
	}
	if err = replaceFile(path, result.Policy); err != nil {
		return ExitError, err
	}
	return ExitOK, nil
}

func fetch(ctx context.Context, url string) ([]Entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := newClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list: HTTP %d", resp.StatusCode)
	}
	body, err := readLimited(resp.Body)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	if err = json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("list is empty")
	}
	return entries, nil
}

// readLimited reads a reply whole, refusing one past the cap rather than truncating it into a shorter valid list.
func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxListBytes {
		return nil, fmt.Errorf("list exceeds %d bytes", MaxListBytes)
	}
	return body, nil
}

// newClient has a timeout and, as for the egress's own clients, no proxy from the environment and no redirects.
func newClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck,forcetypeassert // stdlib type
	transport.Proxy = nil
	return &http.Client{Timeout: fetchTimeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// replaceFile swaps the file in whole, so a failed run cannot leave a partial policy.
func replaceFile(path string, content []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), info.Mode()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
