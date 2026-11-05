// Package measurements folds the Chutes measurement list into egress/policy.yaml. It runs on a developer's machine or
// in CI only: the egress must never read that list, or Chutes would set the rules of its own verification.
package measurements

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sealedin/gateway/internal/egress"
	"github.com/sealedin/gateway/internal/teeverify/tdx"
)

const (
	// SourceURL is the public list, served without a key.
	SourceURL = "https://api.chutes.ai/servers/tee/measurements"
	// MinVersion is the oldest guest release whose entries the sync reads.
	MinVersion = "1.4.0"
	// MaxListBytes caps the reply; the list was 70791 bytes on 2026-11-05.
	MaxListBytes = 4 << 20

	versionParts = 3
)

var (
	// ErrUnknownMRTD refuses a list naming firmware the policy does not pin.
	ErrUnknownMRTD = errors.New("MRTD not in the policy: new firmware needs a governance review")
	// ErrNewImage refuses a list naming a guest image the policy does not pin.
	ErrNewImage = errors.New("RTMR1-3 not in the policy: a new guest image needs a governance review")

	measurementHex = regexp.MustCompile(`^[0-9a-f]{96}$`)
	versionShape   = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	rtmr0Block     = regexp.MustCompile(`(?m)^  rtmr0:\n((?:    - [0-9a-f]{96}\n)+)`)
	syncedOn       = regexp.MustCompile(`(?m)^(# Measurements last synced on )\d{4}-\d{2}-\d{2}( from )`)
)

// Entry is one element of the list; the fields not read here (boot_rtmrs, gpu_count, fingerprint) stay undecoded.
type Entry struct {
	Version      string            `json:"version"`
	Name         string            `json:"name"`
	MRTD         string            `json:"mrtd"`
	RuntimeRTMRs map[string]string `json:"runtime_rtmrs"`
}

// Added is one RTMR0 value new to the policy with the entries that name it.
type Added struct {
	Value   string
	Sources []string
}

// Result is the edited policy; with nothing added, Policy is the input unchanged.
type Result struct {
	Policy []byte
	Added  []Added
}

// Apply refuses the whole list on any unknown MRTD or image, otherwise inserts the new RTMR0 values into the policy text.
func Apply(policy []byte, entries []Entry, today string) (Result, error) {
	parsed, err := egress.LoadPolicy(bytes.NewReader(policy))
	if err != nil {
		return Result{}, err
	}
	added, err := review(parsed.Upstream.TDX, entries)
	if err != nil {
		return Result{}, err
	}
	if len(added) == 0 {
		return Result{Policy: policy}, nil
	}
	edited, err := insert(policy, parsed.Upstream.TDX.RTMR0, added, today)
	if err != nil {
		return Result{}, err
	}
	return Result{Policy: edited, Added: added}, nil
}

// review returns the new RTMR0 values in sorted order, or every reason to refuse the list.
func review(policy tdx.Policy, entries []Entry) ([]Added, error) {
	floor, err := parseVersion(MinVersion)
	if err != nil {
		return nil, err
	}
	var refusals []error
	sources := map[string][]string{}
	for _, e := range entries {
		version, versionErr := parseVersion(e.Version)
		if versionErr != nil {
			return nil, fmt.Errorf("%q: %w", e.Name, versionErr)
		}
		if slices.Compare(version, floor) < 0 {
			continue
		}
		label := e.Version + " " + e.Name
		values, valuesErr := e.measurements(label)
		if valuesErr != nil {
			return nil, valuesErr
		}
		if !slices.Contains(policy.MRTD, values.mrtd) {
			refusals = append(refusals, fmt.Errorf("%w: %s: %s", ErrUnknownMRTD, label, values.mrtd))
		}
		if !slices.Contains(policy.Images, values.image) {
			refusals = append(refusals, fmt.Errorf("%w: %s: rtmr1 %s rtmr2 %s rtmr3 %s", ErrNewImage, label,
				values.image.RTMR1, values.image.RTMR2, values.image.RTMR3))
		}
		if !slices.Contains(policy.RTMR0, values.rtmr0) {
			sources[values.rtmr0] = append(sources[values.rtmr0], label)
		}
	}
	if len(refusals) > 0 {
		return nil, errors.Join(refusals...)
	}
	added := make([]Added, 0, len(sources))
	for value, labels := range sources {
		added = append(added, Added{value, labels})
	}
	slices.SortFunc(added, func(a, b Added) int { return strings.Compare(a.Value, b.Value) })
	return added, nil
}

type entryValues struct {
	mrtd, rtmr0 string
	image       tdx.Image
}

func (e Entry) measurements(label string) (entryValues, error) {
	field := func(name, value string) (string, error) {
		lower := strings.ToLower(value)
		if !measurementHex.MatchString(lower) {
			return "", fmt.Errorf("%s: %s is not 96 hex digits: %q", label, name, value)
		}
		return lower, nil
	}
	mrtd, err := field("mrtd", e.MRTD)
	if err != nil {
		return entryValues{}, err
	}
	rtmrs := make([]string, 0, len(rtmrNames()))
	for _, name := range rtmrNames() {
		value, fieldErr := field(name, e.RuntimeRTMRs[name])
		if fieldErr != nil {
			return entryValues{}, fieldErr
		}
		rtmrs = append(rtmrs, value)
	}
	return entryValues{mrtd, rtmrs[0], tdx.Image{RTMR1: rtmrs[1], RTMR2: rtmrs[2], RTMR3: rtmrs[3]}}, nil
}

func rtmrNames() []string { return []string{"RTMR0", "RTMR1", "RTMR2", "RTMR3"} }

// parseVersion compares by numbers, so 1.10.0 is above 1.4.0; anything but three numbers is refused.
func parseVersion(s string) ([]int, error) {
	if !versionShape.MatchString(s) {
		return nil, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
	}
	parts := make([]int, 0, versionParts)
	for part := range strings.SplitSeq(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("version %q: %w", s, err)
		}
		parts = append(parts, n)
	}
	return parts, nil
}

// insert edits the text rather than re-encoding the YAML, so comments and layout survive, then re-reads the result.
func insert(policy []byte, pinned []string, added []Added, today string) ([]byte, error) {
	if n := len(rtmr0Block.FindAll(policy, -1)); n != 1 {
		return nil, fmt.Errorf("policy: want one plain rtmr0 list of lowercase values, found %d", n)
	}
	if n := len(syncedOn.FindAll(policy, -1)); n != 1 {
		return nil, fmt.Errorf("policy: want one \"# Measurements last synced on\" line, found %d", n)
	}
	loc := rtmr0Block.FindSubmatchIndex(policy)
	block := string(policy[loc[2]:loc[3]])
	values := strings.Fields(strings.ReplaceAll(block, "- ", ""))
	if !slices.Equal(values, pinned) {
		return nil, errors.New("policy: the rtmr0 list as text differs from the list as YAML")
	}
	for _, a := range added {
		at := slices.IndexFunc(values, func(v string) bool { return v > a.Value })
		if at < 0 {
			at = len(values)
		}
		values = slices.Insert(values, at, a.Value)
	}
	var edited bytes.Buffer
	edited.Write(policy[:loc[2]])
	for _, v := range values {
		edited.WriteString("    - " + v + "\n")
	}
	edited.Write(policy[loc[3]:])
	out := syncedOn.ReplaceAll(edited.Bytes(), []byte("${1}"+today+"${2}"))
	parsed, err := egress.LoadPolicy(bytes.NewReader(out))
	if err != nil {
		return nil, fmt.Errorf("policy: edit broke it: %w", err)
	}
	if !slices.Equal(parsed.Upstream.TDX.RTMR0, values) {
		return nil, errors.New("policy: edit did not produce the expected rtmr0 list")
	}
	return out, nil
}
