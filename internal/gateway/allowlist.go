// Package gateway holds the governance constants of the baked LiteLLM catalog (endpoint allowlist, confidential
// model set, price sheet) and the checkers that keep gateway/config.yaml within them. Endpoint integrity assumes
// LiteLLM honours a configured api_base over OPENAI_BASE_URL; re-verify that before trusting a LiteLLM bump.
package gateway

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// EgressBase is the only upstream the gateway may talk to; the egress pins the real hosts in its measured policy.
const EgressBase = "http://egress:8474/v1"

// egressProvider is the LiteLLM provider prefix the egress is addressed under; LiteLLM strips it. It is an
// OpenAI-compatible provider that is not "openai/": for that one LiteLLM (1.92) serves /v1/messages through the OpenAI
// Responses API, which the egress does not speak; every other provider is bridged to /v1/chat/completions.
const egressProvider = "hosted_vllm/"

// AllowedAPIBases returns a fresh map of the approved upstream endpoints.
func AllowedAPIBases() map[string]struct{} {
	return map[string]struct{}{EgressBase: {}}
}

// ConfidentialModels is the served Chutes ids, each confidential_compute on llm.chutes.ai/v1/models on 2026-10-27.
func ConfidentialModels() map[string]struct{} {
	models := make(map[string]struct{})
	for model := range MaxOutputTokens() {
		models[model] = struct{}{}
	}
	return models
}

// servedPrefix is the model_name prefix under which gateway/config.yaml serves each confidential id.
const servedPrefix = Provider + "/"

// ServedModel is the model name gateway/config.yaml serves a confidential id under.
func ServedModel(id string) string {
	return servedPrefix + id
}

// CatalogModels is the served model names a virtual key is scoped to: the measured catalog, sorted, no wildcard.
func CatalogModels() []string {
	models := make([]string, 0, len(ConfidentialModels()))
	for id := range ConfidentialModels() {
		models = append(models, ServedModel(id))
	}
	slices.Sort(models)
	return models
}

// ModelList is the subset of the LiteLLM proxy config this guardrail inspects.
type ModelList struct {
	ModelList []ModelListEntry `yaml:"model_list"`
}

// ModelListEntry is one model_list row, only the keys the guardrails inspect; cost literals stay text for the exact
// price check.
type ModelListEntry struct {
	ModelName string `yaml:"model_name"`
	Params    struct {
		Model              string `yaml:"model"`
		APIBase            string `yaml:"api_base"`
		InputCostPerToken  string `yaml:"input_cost_per_token"`
		OutputCostPerToken string `yaml:"output_cost_per_token"`
	} `yaml:"litellm_params"`
}

// ParseModelList decodes a LiteLLM proxy config, merge keys resolved.
func ParseModelList(r io.Reader) (ModelList, error) {
	var m ModelList
	if err := yaml.NewDecoder(r).Decode(&m); err != nil {
		return ModelList{}, fmt.Errorf("decode model list: %w", err)
	}
	return m, nil
}

// Validate fails on a missing or unlisted api_base (LiteLLM would fall back to a provider default) or a model that is
// not an egress-routed confidential id.
func (m ModelList) Validate() error {
	allowed := AllowedAPIBases()
	confidential := ConfidentialModels()
	var bad []string
	for _, e := range m.ModelList {
		_, ok := allowed[e.Params.APIBase]
		switch {
		case e.Params.APIBase == "":
			bad = append(bad, e.ModelName+": missing api_base")
		case !ok:
			bad = append(bad, e.ModelName+": "+e.Params.APIBase+" not in allowlist")
		}
		id, egress := strings.CutPrefix(e.Params.Model, egressProvider)
		if _, confidentialID := confidential[id]; !egress || !confidentialID {
			bad = append(bad, e.ModelName+": model "+e.Params.Model+" is not an egress-routed confidential id")
		}
	}
	if len(bad) > 0 {
		slices.Sort(bad)
		return fmt.Errorf("catalog outside policy: %s", strings.Join(bad, "; "))
	}
	return nil
}
