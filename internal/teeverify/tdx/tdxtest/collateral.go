// Package tdxtest replays recorded Intel PCS collateral for offline DCAP tests.
package tdxtest

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-tdx-guest/verify/trust"
)

// CollateralFiles replays recorded PCS collateral keyed by URL; <path>.headers.json carries the issuer chains.
func CollateralFiles(files map[string]string) trust.HTTPSGetter {
	return collateralFiles(files)
}

type collateralFiles map[string]string

func (g collateralFiles) Get(url string) (map[string][]string, []byte, error) {
	path, ok := g[url]
	if !ok {
		return nil, nil, fmt.Errorf("no recorded collateral for %s", url)
	}
	body, err := os.ReadFile(path) //nolint:gosec // test support replaying its own fixture paths
	if err != nil {
		return nil, nil, err
	}
	rawHeaders, err := os.ReadFile(path + ".headers.json") //nolint:gosec // same fixture map
	if err != nil {
		return nil, nil, err
	}
	headers := map[string][]string{}
	if err = json.Unmarshal(rawHeaders, &headers); err != nil {
		return nil, nil, fmt.Errorf("recorded headers for %s: %w", url, err)
	}
	return headers, body, nil
}
