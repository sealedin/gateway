package gateway

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

// gateway/chutes-prices.yaml mirrors these; the sheet is list × (100 + MarkupPercent) / 100, exact, per the list test.
// MarkupPercent is the one markup parameter: listPrices() carries the upstream list, CanonicalModelPrices() applies it.
const (
	ListSource    = "https://chutes.ai/app"
	ListAsOf      = "2026-11-03"
	MarkupPercent = 0
	percent       = 100
)

const (
	maxOutputGLM      = 65535
	maxOutputKimi     = 65535
	maxOutputDeepSeek = 131072
	maxOutputQwen     = 65536
)

// MaxOutputTokens is each model's output limit, max_output_length in the catalog gateway/chutes-prices.yaml names with its
// date. LiteLLM reserves against it, and the egress clamps every request to it, so a larger max_tokens cannot overrun.
func MaxOutputTokens() map[string]int {
	return map[string]int{
		"zai-org/GLM-5.2-TEE":                    maxOutputGLM,
		"moonshotai/Kimi-K3-TEE":                 maxOutputKimi,
		"deepseek-ai/DeepSeek-V4-Flash-0731-TEE": maxOutputDeepSeek,
		"Qwen/Qwen3.5-397B-A17B-TEE":             maxOutputQwen,
		"Qwen/Qwen3.8-27B-TEE":                   maxOutputQwen,
	}
}

const (
	microPerUSD   = 1_000_000
	tokensPerMTok = 1_000_000
	// microPerMTokPerToken scales USD per token to micro-USD per million tokens.
	microPerMTokPerToken = microPerUSD * tokensPerMTok
)

var errNotWholeMicroUSD = errors.New("not a whole number of micro-USD per million tokens")

// Price is micro-USD per million tokens: an exact integer the catalog prints and the config literals must equal.
type Price struct {
	InputMicroUSDPerMTok  uint64
	OutputMicroUSDPerMTok uint64
}

// USDPerMTok is the (input, output) price as exact decimal strings, the form the signed catalog serves.
func (p Price) USDPerMTok() (string, string) {
	return formatMicroUSD(p.InputMicroUSDPerMTok), formatMicroUSD(p.OutputMicroUSDPerMTok)
}

// formatMicroUSD prints micro-USD as USD without exponent or trailing zeros: 1312500 is "1.3125".
func formatMicroUSD(micro uint64) string {
	whole := strconv.FormatUint(micro/microPerUSD, 10)
	frac := micro % microPerUSD
	if frac == 0 {
		return whole
	}
	return whole + "." + strings.TrimRight(fmt.Sprintf("%06d", frac), "0")
}

// microUSDPerMTok converts a cost_per_token literal exactly; a value not whole in micro-USD per 1M tokens is off-sheet.
func microUSDPerMTok(costPerToken string) (uint64, error) {
	r, ok := new(big.Rat).SetString(costPerToken)
	if !ok {
		return 0, fmt.Errorf("%q is not a decimal", costPerToken)
	}
	r.Mul(r, new(big.Rat).SetInt64(microPerMTokPerToken))
	if !r.IsInt() || !r.Num().IsUint64() {
		return 0, fmt.Errorf("%q: %w", costPerToken, errNotWholeMicroUSD)
	}
	return r.Num().Uint64(), nil
}

// listPrices is the ListAsOf Chutes list in micro-USD per million tokens, the models of gateway/chutes-prices.yaml.
//
//nolint:mnd // price sheet: the literals are the data
func listPrices() map[string]Price {
	return map[string]Price{
		"zai-org/GLM-5.2-TEE":                    {InputMicroUSDPerMTok: 1_250_000, OutputMicroUSDPerMTok: 3_950_000},
		"moonshotai/Kimi-K3-TEE":                 {InputMicroUSDPerMTok: 1_850_000, OutputMicroUSDPerMTok: 9_500_000},
		"deepseek-ai/DeepSeek-V4-Flash-0731-TEE": {InputMicroUSDPerMTok: 440_000, OutputMicroUSDPerMTok: 1_320_000},
		"Qwen/Qwen3.5-397B-A17B-TEE":             {InputMicroUSDPerMTok: 450_000, OutputMicroUSDPerMTok: 3_000_000},
		"Qwen/Qwen3.8-27B-TEE":                   {InputMicroUSDPerMTok: 39_000, OutputMicroUSDPerMTok: 1_250_000},
	}
}

// CanonicalModelPrices is the price sheet gateway/config.yaml must mirror: listPrices() plus MarkupPercent. The list test
// recomputes it with exact arithmetic from gateway/chutes-prices.yaml, so a markup the list does not divide by whole
// micro-USD fails there, not here.
func CanonicalModelPrices() map[string]Price {
	list := listPrices()
	prices := make(map[string]Price, len(list))
	for model, price := range list {
		prices[model] = Price{InputMicroUSDPerMTok: markedUp(price.InputMicroUSDPerMTok),
			OutputMicroUSDPerMTok: markedUp(price.OutputMicroUSDPerMTok)}
	}
	return prices
}

// markedUp is micro × (100 + MarkupPercent) / 100 in integer arithmetic.
func markedUp(micro uint64) uint64 {
	return micro * (percent + MarkupPercent) / percent
}

// CanonicalModel strips the LiteLLM provider prefix so providers serving the same weights key the same price.
func CanonicalModel(model string) string {
	if _, rest, ok := strings.Cut(model, "/"); ok {
		return rest
	}
	return model
}

// ValidatePricing fails unless the model list carries exactly the price sheet: no entry off it, none missing, no drift.
func (m ModelList) ValidatePricing() error {
	return m.validatePricing(CanonicalModelPrices())
}

func (m ModelList) validatePricing(prices map[string]Price) error {
	var bad []string
	used := make(map[string]bool, len(prices))
	for _, e := range m.ModelList {
		canonical := CanonicalModel(e.Params.Model)
		want, priced := prices[canonical]
		if !priced {
			bad = append(bad, fmt.Sprintf("%s: %q is not on the price sheet", e.ModelName, canonical))
			continue
		}
		used[canonical] = true
		got, err := e.price()
		switch {
		case err != nil:
			bad = append(bad, e.ModelName+": "+err.Error())
		case got != want:
			bad = append(bad, fmt.Sprintf("%s: cost %s/%s differs from price sheet %s/%s", e.ModelName,
				e.Params.InputCostPerToken, e.Params.OutputCostPerToken, formatMicroUSD(want.InputMicroUSDPerMTok),
				formatMicroUSD(want.OutputMicroUSDPerMTok)))
		}
	}
	for canonical := range prices {
		if !used[canonical] {
			bad = append(bad, canonical+": priced model missing from the catalog")
		}
	}
	if len(bad) > 0 {
		slices.Sort(bad)
		return fmt.Errorf("catalog pricing mismatch: %s", strings.Join(bad, "; "))
	}
	return nil
}

// price is the entry's cost literals in whole micro-USD per 1M tokens; a missing literal is not a decimal and fails.
func (e ModelListEntry) price() (Price, error) {
	in, err := microUSDPerMTok(e.Params.InputCostPerToken)
	if err != nil {
		return Price{}, fmt.Errorf("input cost %w", err)
	}
	out, err := microUSDPerMTok(e.Params.OutputCostPerToken)
	if err != nil {
		return Price{}, fmt.Errorf("output cost %w", err)
	}
	return Price{InputMicroUSDPerMTok: in, OutputMicroUSDPerMTok: out}, nil
}
