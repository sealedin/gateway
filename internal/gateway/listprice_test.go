package gateway_test

import (
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/sealedin/gateway/internal/gateway"
)

const (
	microPerUSD = 1_000_000
	percent     = 100
)

// listSheet is gateway/chutes-prices.yaml, every price kept as its decimal text so the arithmetic below stays exact.
type listSheet struct {
	AsOf          string `yaml:"as_of"`
	Source        string `yaml:"source"`
	MarkupPercent uint64 `yaml:"markup_percent"`
	Models        map[string]struct {
		Input   string `yaml:"input_usd_per_mtok"`
		Output  string `yaml:"output_usd_per_mtok"`
		Max     int    `yaml:"max_output_tokens"`
		Context int    `yaml:"max_input_tokens"`
	} `yaml:"models"`
}

func decodeYAML(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "gateway", name))
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, into))
}

// exactInt scales the decimal text by den and requires the result to be a whole number.
func exactInt(t *testing.T, decimal string, den int64) uint64 {
	t.Helper()
	r, ok := new(big.Rat).SetString(decimal)
	require.True(t, ok, "not a decimal: %q", decimal)
	r.Mul(r, new(big.Rat).SetInt64(den))
	require.True(t, r.IsInt(), "%s * %d is not whole", decimal, den)
	require.True(t, r.Num().IsUint64())
	return r.Num().Uint64()
}

// markedUp is list × (100 + markup) / 100 in micro-USD, refusing a markup that does not divide evenly.
func markedUp(t *testing.T, listUSD string, markup uint64) uint64 {
	t.Helper()
	scaled := exactInt(t, listUSD, microPerUSD) * (percent + markup)
	require.Zero(t, scaled%percent, "%s with %d%% markup is not whole in micro-USD", listUSD, markup)
	return scaled / percent
}

// The price sheet is the upstream list plus the markup, exactly: a list change without a config change, or a markup
// drift between the list file and the code, fails here before it changes what users are charged.
func TestPriceSheetIsListPlusMarkup(t *testing.T) {
	t.Parallel()
	var list listSheet
	decodeYAML(t, "chutes-prices.yaml", &list)
	require.Equal(t, gateway.ListAsOf, list.AsOf)
	require.Equal(t, gateway.ListSource, list.Source)
	require.Equal(t, uint64(gateway.MarkupPercent), list.MarkupPercent)

	prices := gateway.CanonicalModelPrices()
	require.Len(t, list.Models, len(prices), "every priced model is on the list and vice versa")
	for id, entry := range list.Models {
		want, ok := prices[id]
		require.True(t, ok, "%s is on the list but not on the price sheet", id)
		require.Equal(t, want.InputMicroUSDPerMTok, markedUp(t, entry.Input, list.MarkupPercent), "%s input", id)
		require.Equal(t, want.OutputMicroUSDPerMTok, markedUp(t, entry.Output, list.MarkupPercent), "%s output", id)
	}
}

// The served decimal is the exact micro-USD value, no exponent, no trailing zeros.
func TestPriceUSDPerMTok(t *testing.T) {
	t.Parallel()
	tests := []struct {
		micro uint64
		want  string
	}{
		{1_312_500, "1.3125"},
		{40_950, "0.04095"},
		{3_150_000, "3.15"},
		{9_975_000, "9.975"},
		{2_000_000, "2"},
		{1, "0.000001"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			in, out := gateway.Price{InputMicroUSDPerMTok: tt.micro, OutputMicroUSDPerMTok: tt.micro}.USDPerMTok()
			require.Equal(t, tt.want, in)
			require.Equal(t, tt.want, out)
		})
	}
}

// The signed catalog is the price sheet and nothing else: every priced model under its served id, prices as the exact
// decimals, the list provenance, sorted by id.
func TestMeasuredCatalogEqualsPriceSheet(t *testing.T) {
	t.Parallel()
	catalog := gateway.MeasuredCatalog()
	require.Equal(t, gateway.ListAsOf, catalog.ListAsOf)
	require.Equal(t, gateway.ListSource, catalog.ListSource)
	require.Equal(t, uint(gateway.MarkupPercent), catalog.MarkupPercent)

	prices := gateway.CanonicalModelPrices()
	require.Len(t, catalog.Models, len(prices))
	ids := make([]string, 0, len(catalog.Models))
	for _, m := range catalog.Models {
		price, ok := prices[m.UpstreamID]
		require.True(t, ok, "%s is not on the price sheet", m.UpstreamID)
		in, out := price.USDPerMTok()
		require.Equal(t, gateway.CatalogModel{ID: gateway.ServedModel(m.UpstreamID), InputUSDPerMTok: in,
			OutputUSDPerMTok: out, Provider: gateway.Provider, Tier: gateway.Tier, UpstreamID: m.UpstreamID}, m)
		ids = append(ids, m.ID)
	}
	require.Equal(t, gateway.CatalogModels(), ids, "sorted by id, exactly the models a key is scoped to")
}

// Every catalog string is printable ASCII, so no JSON escape, no Unicode form and no parser quirk can make two
// verifiers rebuild different preimages from the same reply.
func TestMeasuredCatalogIsPrintableASCII(t *testing.T) {
	t.Parallel()
	catalog := gateway.MeasuredCatalog()
	strs := []string{catalog.ListAsOf, catalog.ListSource}
	for _, m := range catalog.Models {
		strs = append(strs, m.ID, m.InputUSDPerMTok, m.OutputUSDPerMTok, m.Provider, m.Tier, m.UpstreamID)
	}
	for _, s := range strs {
		require.NotEmpty(t, s)
		for _, r := range s {
			require.True(t, r >= ' ' && r <= '~' && r != '"' && r != '\\', "%q carries %q", s, r)
		}
	}
}

// Three records of one limit: the list, the code the egress clamps with, the config LiteLLM reserves against.
func TestMaxOutputTokensAgree(t *testing.T) {
	t.Parallel()
	var list listSheet
	decodeYAML(t, "chutes-prices.yaml", &list)
	var config struct {
		ModelList []struct {
			Params struct {
				Model string `yaml:"model"`
			} `yaml:"litellm_params"`
			Info struct {
				MaxOutputTokens int `yaml:"max_output_tokens"`
				MaxInputTokens  int `yaml:"max_input_tokens"`
			} `yaml:"model_info"`
		} `yaml:"model_list"`
	}
	decodeYAML(t, "config.yaml", &config)
	limits := gateway.MaxOutputTokens()
	require.Len(t, limits, len(gateway.ConfidentialModels()), "every served model has a limit")
	require.Len(t, config.ModelList, len(limits))
	for _, entry := range config.ModelList {
		upstream := strings.TrimPrefix(entry.Params.Model, "hosted_vllm/")
		require.Positive(t, limits[upstream], upstream)
		require.Equal(t, limits[upstream], entry.Info.MaxOutputTokens, upstream)
		require.Equal(t, limits[upstream], list.Models[upstream].Max, upstream)
		require.Positive(t, entry.Info.MaxInputTokens, upstream)
		require.Equal(t, list.Models[upstream].Context, entry.Info.MaxInputTokens, upstream)
		require.Contains(t, gateway.ConfidentialModels(), upstream)
	}
}

// gateway/request_guard_test.py computes with Kimi-K3's figures, without YAML on the runner: they are the measured ones.
func TestGuardArithmeticUsesTheMeasuredConfig(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "gateway", "request_guard_test.py"))
	require.NoError(t, err)
	var config struct {
		ModelList []struct {
			Name   string `yaml:"model_name"`
			Params struct {
				Input  float64 `yaml:"input_cost_per_token"`
				Output float64 `yaml:"output_cost_per_token"`
			} `yaml:"litellm_params"`
			Info struct {
				MaxOutputTokens int `yaml:"max_output_tokens"`
				MaxInputTokens  int `yaml:"max_input_tokens"`
			} `yaml:"model_info"`
		} `yaml:"model_list"`
	}
	decodeYAML(t, "config.yaml", &config)
	for _, entry := range config.ModelList {
		if entry.Name != "chutes/moonshotai/Kimi-K3-TEE" {
			continue
		}
		pattern := regexp.MustCompile(`KIMI = \{"input_usd": ([0-9.e-]+), "output_usd": ([0-9.e-]+), "max_input": (\d+), "max_output": (\d+)\}`)
		got := pattern.FindStringSubmatch(string(raw))
		require.Len(t, got, 5)
		input, parseErr := strconv.ParseFloat(got[1], 64)
		require.NoError(t, parseErr)
		output, parseErr := strconv.ParseFloat(got[2], 64)
		require.NoError(t, parseErr)
		require.Equal(t, entry.Params.Input, input)   //nolint:testifylint // literals, not arithmetic
		require.Equal(t, entry.Params.Output, output) //nolint:testifylint // literals, not arithmetic
		require.Equal(t, strconv.Itoa(entry.Info.MaxInputTokens), got[3])
		require.Equal(t, strconv.Itoa(entry.Info.MaxOutputTokens), got[4])
		return
	}
	t.Fatal("Kimi-K3 is gone from the config")
}
