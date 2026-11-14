package egress_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/egress"
	"github.com/sealedin/gateway/internal/egress/upstream"
)

// nearBlock is a second-family block as the policy file carries it.
const nearBlock = `
near:
  models: [Qwen/Qwen3.8-27B]
  api: https://cloud-api.near.ai
  guests:
    - mrtd: 7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173
      rtmr0: d090162bff4b1d1dc74dc59dc548838efc4b811b173da8536efa8e2a9c045da70ee092301293ad90afebee448bcd0211
      rtmr1: 4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec
      rtmr2: 764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d
  td_attributes: "0000001000000000"
  xfam: e702060000000000
  app_ids: [f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae]
  key_providers: [7b7d]
`

func TestLoadPolicyWithASecondFamily(t *testing.T) {
	base := string(measuredPolicy(t))

	p, err := egress.LoadPolicy(strings.NewReader(base + nearBlock))

	require.NoError(t, err)
	require.Equal(t, []string{"Qwen/Qwen3.8-27B"}, p.Near.Models)
	require.Equal(t, "https://cloud-api.near.ai", p.Near.API)

	for name, tt := range map[string]struct{ old, replacement, wantErr string }{
		"no model":       {"models: [Qwen/Qwen3.8-27B]", "models: []", "routes no model"},
		"http origin":    {"https://cloud-api.near.ai", "http://cloud-api.near.ai", "https"},
		"no app id":      {"app_ids: [f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae]", "app_ids: []", "app id"},
		"misspelled key": {"key_providers:", "key_provider:", "key_provider"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err = egress.LoadPolicy(strings.NewReader(base + strings.Replace(nearBlock, tt.old, tt.replacement, 1)))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

type namedProvider string

func (n namedProvider) Invoke(_ context.Context, _, _ string, _ bool, _ []byte, call *upstream.Call) (*upstream.Reply, error) {
	call.Chute = string(n)
	return &upstream.Reply{}, nil
}

func TestDispatcherRoutesByModel(t *testing.T) {
	dispatcher := egress.Dispatcher{Default: namedProvider("first"),
		ByModel: map[string]upstream.Provider{"Qwen/Qwen3.8-27B": namedProvider("second")}}

	for model, want := range map[string]string{"Qwen/Qwen3.8-27B": "second", "Qwen/Qwen3.8-27B-TEE": "first"} {
		call := &upstream.Call{}
		_, err := dispatcher.Invoke(t.Context(), model, "/v1/chat/completions", false, nil, call)
		require.NoError(t, err)
		require.Equal(t, want, call.Chute, model)
	}
}
