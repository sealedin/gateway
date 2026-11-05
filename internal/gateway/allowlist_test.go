package gateway_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/gateway"
)

// The baked catalog and the dev catalog are locked to the allowlist so a PR cannot slip an api_base past review.
func TestBakedCatalogStaysWithinAllowlist(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"config.yaml", "config.dev.yaml"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f, err := os.Open(filepath.Join("..", "..", "gateway", name))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })

			list, err := gateway.ParseModelList(f)
			require.NoError(t, err)
			require.NotEmpty(t, list.ModelList, "catalog must list at least one model")
			require.NoError(t, list.Validate())
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	newList := func(name, apiBase, model string) gateway.ModelList {
		var e gateway.ModelListEntry
		e.ModelName = name
		e.Params.APIBase = apiBase
		e.Params.Model = model
		return gateway.ModelList{ModelList: []gateway.ModelListEntry{e}}
	}

	tests := []struct {
		name    string
		list    gateway.ModelList
		wantErr string
	}{
		{
			name: "egress-routed confidential model passes",
			list: newList("chutes/zai-org/GLM-5.2-TEE", gateway.EgressBase, "hosted_vllm/zai-org/GLM-5.2-TEE"),
		},
		{
			name:    "missing api_base rejected",
			list:    newList("chutes/no-base", "", "hosted_vllm/zai-org/GLM-5.2-TEE"),
			wantErr: "missing api_base",
		},
		{
			name:    "off-list endpoint rejected",
			list:    newList("rogue", "https://cheaperinference.example/v1", "hosted_vllm/zai-org/GLM-5.2-TEE"),
			wantErr: "not in allowlist",
		},
		{
			name:    "direct chutes host rejected even for a confidential id",
			list:    newList("direct", "https://llm.chutes.ai/v1", "hosted_vllm/zai-org/GLM-5.2-TEE"),
			wantErr: "not in allowlist",
		},
		{
			name:    "non-confidential id rejected",
			list:    newList("plain", gateway.EgressBase, "hosted_vllm/zai-org/GLM-5.2"),
			wantErr: "not an egress-routed confidential id",
		},
		{
			name:    "wildcard rejected",
			list:    newList("any", gateway.EgressBase, "hosted_vllm/*"),
			wantErr: "not an egress-routed confidential id",
		},
		{
			name:    "other provider prefix rejected",
			list:    newList("native", gateway.EgressBase, "chutes/zai-org/GLM-5.2-TEE"),
			wantErr: "not an egress-routed confidential id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.list.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Multiple offenders are all reported, sorted, and joined by "; ".
func TestValidateReportsAllOffendersSorted(t *testing.T) {
	t.Parallel()

	var zeta, alpha gateway.ModelListEntry
	zeta.ModelName = "zeta"
	zeta.Params.APIBase = "https://rogue.example/v1"
	zeta.Params.Model = "hosted_vllm/zai-org/GLM-5.2-TEE"
	alpha.ModelName = "alpha"
	alpha.Params.APIBase = ""
	alpha.Params.Model = "hosted_vllm/zai-org/GLM-5.2-TEE"

	err := gateway.ModelList{ModelList: []gateway.ModelListEntry{zeta, alpha}}.Validate()
	require.Error(t, err)
	require.ErrorContains(t, err, "alpha: missing api_base")
	require.ErrorContains(t, err, "zeta: https://rogue.example/v1 not in allowlist")
	require.Less(t, strings.Index(err.Error(), "alpha"), strings.Index(err.Error(), "zeta"),
		"offenders must be sorted, so alpha precedes zeta")
}

// The baked config shares its egress block through a YAML merge key, so merged entries must validate as written.
func TestParseCatalogResolvesMergeKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "merged entry inherits allowlisted api_base",
			yaml: `model_list:
  - model_name: "chutes/zai-org/GLM-5.2-TEE"
    litellm_params: &egress
      model: "hosted_vllm/zai-org/GLM-5.2-TEE"
      api_base: http://egress:8474/v1
  - model_name: "chutes/moonshotai/Kimi-K3-TEE"
    litellm_params:
      <<: *egress
      model: "hosted_vllm/moonshotai/Kimi-K3-TEE"
`,
		},
		{
			name: "merged entry inheriting an off-list base is rejected",
			yaml: `model_list:
  - model_name: "rogue/base"
    litellm_params: &rogue
      model: "hosted_vllm/zai-org/GLM-5.2-TEE"
      api_base: https://rogue.example/v1
  - model_name: "rogue/alias"
    litellm_params:
      <<: *rogue
`,
			wantErr: "not in allowlist",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			list, err := gateway.ParseModelList(strings.NewReader(tt.yaml))
			require.NoError(t, err)
			require.NotEmpty(t, list.ModelList)

			err = list.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestParseModelListRejectsInvalidYAML(t *testing.T) {
	t.Parallel()

	_, err := gateway.ParseModelList(strings.NewReader("model_list: [unterminated"))
	require.ErrorContains(t, err, "decode model list")
}

// The key issuer scopes every virtual key to exactly the served model names of the baked catalog, never a wildcard.
func TestCatalogModelsMatchBakedCatalog(t *testing.T) {
	t.Parallel()

	f, err := os.Open(filepath.Join("..", "..", "gateway", "config.yaml"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	list, err := gateway.ParseModelList(f)
	require.NoError(t, err)
	served := make([]string, 0, len(list.ModelList))
	for _, e := range list.ModelList {
		served = append(served, e.ModelName)
	}

	models := gateway.CatalogModels()
	require.ElementsMatch(t, served, models)
	require.True(t, slices.IsSorted(models), "a stable order keeps the issued key's model list reproducible")
	for _, m := range models {
		require.NotContains(t, m, "*")
	}
}
