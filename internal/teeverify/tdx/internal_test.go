package tdx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPinnedRoots(t *testing.T) {
	roots, err := pinnedRoots()
	require.NoError(t, err)
	require.NotNil(t, roots)

	saved := rootCAPEM
	t.Cleanup(func() { rootCAPEM = saved })
	for _, tt := range []struct {
		name    string
		pem     []byte
		wantErr string
	}{
		{"not PEM", []byte("junk"), "not PEM"},
		{"wrong certificate", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "fingerprint"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rootCAPEM = tt.pem
			_, bad := pinnedRoots()
			require.ErrorContains(t, bad, tt.wantErr)
		})
	}
}
