package gateway_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/gateway"
)

// The baked catalog is the measured price sheet: a config edit must not silently change what users are charged.
func TestBakedCatalogMatchesPriceSheet(t *testing.T) {
	t.Parallel()

	f, err := os.Open(filepath.Join("..", "..", "gateway", "config.yaml"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	list, err := gateway.ParseModelList(f)
	require.NoError(t, err)
	require.NoError(t, list.ValidatePricing())
}

func TestCanonicalModel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		model string
		want  string
	}{
		{model: "hosted_vllm/zai-org/GLM-5.2-TEE", want: "zai-org/GLM-5.2-TEE"},
		{model: "nebius/zai-org/GLM-5.2", want: "zai-org/GLM-5.2"}, // any provider prefix strips
		{model: "hosted_vllm/*", want: "*"},
		{model: "bare-model", want: "bare-model"},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, gateway.CanonicalModel(tt.model))
		})
	}
}

func TestValidatePricing(t *testing.T) {
	t.Parallel()

	prices := map[string]gateway.Price{
		"org/priced": {InputMicroUSDPerMTok: 1_000_000, OutputMicroUSDPerMTok: 2_000_000},
	}
	newEntry := func(name, model, in, out string) gateway.ModelListEntry {
		var e gateway.ModelListEntry
		e.ModelName = name
		e.Params.Model = model
		e.Params.InputCostPerToken = in
		e.Params.OutputCostPerToken = out
		return e
	}

	tests := []struct {
		name    string
		entries []gateway.ModelListEntry
		wantErr string
	}{
		{
			name: "exact price on every provider entry passes",
			entries: []gateway.ModelListEntry{
				newEntry("hosted_vllm/org/priced", "hosted_vllm/org/priced", "1e-6", "2e-6"),
				newEntry("mirror/priced", "otherprov/org/priced", "1e-6", "2e-6"),
			},
		},
		{
			name: "unpriced entry rejected, a $0 model would meter nothing",
			entries: []gateway.ModelListEntry{
				newEntry("hosted_vllm/org/priced", "hosted_vllm/org/priced", "1e-6", "2e-6"),
				newEntry("hosted_vllm/org/free", "hosted_vllm/org/free", "0", "0"),
			},
			wantErr: "not on the price sheet",
		},
		{
			name: "diverging price rejected",
			entries: []gateway.ModelListEntry{
				newEntry("hosted_vllm/org/priced", "hosted_vllm/org/priced", "1e-6", "2e-6"),
				newEntry("mirror/priced", "otherprov/org/priced", "1e-6", "9e-6"),
			},
			wantErr: "differs from price sheet",
		},
		{
			name: "priced model with missing cost rejected",
			entries: []gateway.ModelListEntry{
				newEntry("hosted_vllm/org/priced", "hosted_vllm/org/priced", "1e-6", ""),
			},
			wantErr: "output cost",
		},
		{
			name: "cost literal on an off-sheet model rejected",
			entries: []gateway.ModelListEntry{
				newEntry("hosted_vllm/org/priced", "hosted_vllm/org/priced", "1e-6", "2e-6"),
				newEntry("rogue", "hosted_vllm/org/rogue", "5e-6", "5e-6"),
			},
			wantErr: `not on the price sheet`,
		},
		{
			name: "literal not whole in micro-USD rejected",
			entries: []gateway.ModelListEntry{
				newEntry("hosted_vllm/org/priced", "hosted_vllm/org/priced", "1.0000000000001e-6", "2e-6"),
			},
			wantErr: "not a whole number",
		},
		{
			name:    "priced model absent from catalog rejected",
			entries: []gateway.ModelListEntry{},
			wantErr: "missing from the catalog",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := gateway.ModelList{ModelList: tt.entries}.ValidatePricingAgainst(prices)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Offenders are reported sorted and joined by "; ", matching Validate's contract.
func TestValidatePricingReportsAllOffendersSorted(t *testing.T) {
	t.Parallel()

	var rogue gateway.ModelListEntry
	rogue.ModelName = "zz-rogue"
	rogue.Params.Model = "hosted_vllm/org/rogue"
	rogue.Params.InputCostPerToken = "5e-6"

	err := gateway.ModelList{ModelList: []gateway.ModelListEntry{rogue}}.ValidatePricingAgainst(map[string]gateway.Price{
		"org/priced": {InputMicroUSDPerMTok: 1_000_000, OutputMicroUSDPerMTok: 2_000_000},
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "org/priced: priced model missing from the catalog; zz-rogue:")
}

// The treasury is measured: this pin moves only with the literal, in a commit a reviewer can see.
func TestTreasuryIsPinned(t *testing.T) {
	t.Parallel()
	require.Equal(t, "CfYWUgC78FTM7gnt9nwGTRRRadK6ZME9ctMdmqpxCzBT", gateway.Treasury)
	require.True(t, gateway.TreasuryConfigured())
	require.False(t, gateway.AddressSet(gateway.TreasuryPlaceholder), "the placeholder must never count as configured")
}

func TestPaymentTermsAreMeasured(t *testing.T) {
	t.Parallel()
	require.Equal(t, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", gateway.PaymentNetwork)
	require.Equal(t, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", gateway.PaymentAsset)
	catalog := gateway.MeasuredCatalog()
	require.Equal(t, gateway.Treasury, catalog.PayTo)
	require.Equal(t, []string{gateway.PaymentNetwork}, catalog.Networks)
	require.Equal(t, gateway.PaymentAsset, catalog.Asset)
}
