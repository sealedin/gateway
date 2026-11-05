package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
)

// fakeSecurity stands in for the real tool, so no test can touch a Keychain: it records stdin and its arguments.
func fakeSecurity(t *testing.T, exists bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if exists {
		require.NoError(t, os.WriteFile(state, nil, 0o600))
	}
	script := `#!/bin/sh
echo "$@" >> "` + dir + `/args"
if [ "$1" = -i ]; then cat > "` + state + `"; echo "noise from the tool $(cat "` + state + `")"; exit 0; fi
[ -e "` + state + `" ]
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, securityTool), []byte(script), 0o700))
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return dir, state
}

func TestKeygenPrintsOnlyTheAddress(t *testing.T) {
	dir, state := fakeSecurity(t, false)
	var out bytes.Buffer
	require.NoError(t, run(&out))

	stored, err := os.ReadFile(state)
	require.NoError(t, err)
	fields := strings.Fields(string(stored))
	require.Equal(t, []string{"add-generic-password", "-s", keychainItem, "-a", keychainAccount, "-w"}, fields[:6])
	private, err := base58.Decode(fields[6])
	require.NoError(t, err)
	require.Len(t, private, 64)

	address := strings.TrimSpace(out.String())
	require.Equal(t, base58.Encode(private[32:]), address)
	require.NotContains(t, out.String(), fields[6], "the secret is never printed")
	args, err := os.ReadFile(filepath.Join(dir, "args"))
	require.NoError(t, err)
	require.NotContains(t, string(args), fields[6], "the secret never reaches an argument")
}

func TestKeygenRefusesToOverwrite(t *testing.T) {
	_, state := fakeSecurity(t, true)
	var out bytes.Buffer
	require.ErrorContains(t, run(&out), "already exists")
	require.Empty(t, out.String())
	stored, err := os.ReadFile(state)
	require.NoError(t, err)
	require.Empty(t, stored, "the existing item is untouched")
}
