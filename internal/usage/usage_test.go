package usage_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sealedin/gateway/internal/limits"
	"github.com/sealedin/gateway/internal/testsupport"
	"github.com/sealedin/gateway/internal/usage"
)

const masterKey = "sk-master"

func TestFormatMasterKey(t *testing.T) {
	t.Parallel()
	var raw [32]byte
	raw[0], raw[31] = 0xab, 0xcd
	require.Equal(t, "sk-ab"+strings.Repeat("00", 30)+"cd", usage.FormatMasterKey(raw))
}

func TestIssueScopesKeyAndReturnsIt(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey}
	bounds := usage.KeyLimits{MaxBudgetUSD: 20, Models: []string{"chutes/a", "chutes/b"}, RPMLimit: 60}
	issued, err := fake.Client(t).Issue(t.Context(), "alice", bounds)
	require.NoError(t, err)
	require.Equal(t, "alice", issued.Alias)
	require.NotEmpty(t, issued.Key)
	require.InEpsilon(t, 20.0, issued.MaxBudgetUSD, 1e-12)
	require.Equal(t, 60, issued.RPMLimit)
	require.Equal(t, bounds.Models, issued.Models)
	calls := fake.Generated()
	require.Len(t, calls, 1)
	require.Equal(t, "alice", calls[0].Alias)
	require.Nil(t, calls[0].BudgetDuration, "credits are prepaid: no budget_duration, spend never resets")
	require.Equal(t, limits.ParallelRequests, calls[0].MaxParallelRequests, "every issued key carries the limit")
}

func TestLookupAliasReportsSpend(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey, SpendUSD: 1.5}
	gw := fake.Client(t)
	_, err := gw.Issue(t.Context(), "alice", usage.KeyLimits{MaxBudgetUSD: 20, RPMLimit: 60})
	require.NoError(t, err)
	info, err := gw.LookupAlias(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", info.Alias)
	require.InEpsilon(t, 1.5, info.SpendUSD, 1e-12)
	require.InEpsilon(t, 20.0, info.MaxBudgetUSD, 1e-12)

	_, err = gw.LookupAlias(t.Context(), "nobody")
	require.ErrorIs(t, err, usage.ErrKeyUnknown)
}

func TestTokenHashIsLiteLLMsLookupKey(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("sk-abc"))
	require.Equal(t, hex.EncodeToString(sum[:]), usage.TokenHash("sk-abc"))
	require.Equal(t, "already-hashed", usage.TokenHash("already-hashed"), "only sk- keys are hashed, as LiteLLM does")
}

func TestLookupKey(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey, SpendUSD: 2}
	gw := fake.Client(t)
	issued, err := gw.Issue(t.Context(), "alice", usage.KeyLimits{MaxBudgetUSD: 20, RPMLimit: 60, Models: []string{"m"},
		Metadata: map[string]any{"k": "v"}})
	require.NoError(t, err)

	for name, key := range map[string]string{"raw key": issued.Key, "hashed token": usage.TokenHash(issued.Key)} {
		info, lookupErr := gw.LookupKey(t.Context(), key)
		require.NoError(t, lookupErr, name)
		require.Equal(t, "alice", info.Alias, name)
		require.InEpsilon(t, 2.0, info.SpendUSD, 1e-12, name)
		require.InEpsilon(t, 20.0, info.MaxBudgetUSD, 1e-12, name)
		require.Equal(t, 60, info.RPMLimit, name)
		require.Equal(t, []string{"m"}, info.Models, name)
		require.Equal(t, map[string]any{"k": "v"}, info.Metadata, name)
		require.Equal(t, usage.TokenHash(issued.Key), info.Token, name)
	}

	_, err = gw.LookupKey(t.Context(), "sk-nobody")
	require.ErrorIs(t, err, usage.ErrKeyUnknown)
}

func TestLookupAliasReadsTheWholeRow(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey}
	gw := fake.Client(t)
	issued, err := gw.Issue(t.Context(), "alice", usage.KeyLimits{MaxBudgetUSD: 20, RPMLimit: 7, Models: []string{"m"},
		Metadata: map[string]any{"k": "v"}})
	require.NoError(t, err)
	info, err := gw.LookupAlias(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, usage.TokenHash(issued.Key), info.Token)
	require.Equal(t, 7, info.RPMLimit)
	require.Equal(t, []string{"m"}, info.Models)
	require.Equal(t, map[string]any{"k": "v"}, info.Metadata)
}

func TestSetBudgetChangesTheBudgetAndMetadataTogether(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey}
	gw := fake.Client(t)
	issued, err := gw.Issue(t.Context(), "alice", usage.KeyLimits{MaxBudgetUSD: 20, RPMLimit: 60})
	require.NoError(t, err)
	require.NoError(t, gw.SetBudget(t.Context(), issued.Key, 45.5, map[string]any{"a": "b"}))
	info, err := gw.LookupKey(t.Context(), issued.Key)
	require.NoError(t, err)
	require.InEpsilon(t, 45.5, info.MaxBudgetUSD, 1e-12)
	require.Equal(t, map[string]any{"a": "b"}, info.Metadata)
	require.Equal(t, "alice", info.Alias)
	require.Error(t, gw.SetBudget(t.Context(), "sk-nobody", 1, nil))
}

// A second key under one alias is refused at the gateway when the first is already there.
func TestIssueRefusesADuplicateAlias(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey}
	gw := fake.Client(t)
	_, err := gw.Issue(t.Context(), "alice", usage.KeyLimits{MaxBudgetUSD: 20, RPMLimit: 60})
	require.NoError(t, err)
	_, err = gw.Issue(t.Context(), "alice", usage.KeyLimits{MaxBudgetUSD: 20, RPMLimit: 60})
	require.Error(t, err)
}

// A raw key never travels in a query string nor reaches an error, or a stalled gateway would write it to the log.
func TestLookupKeyKeepsTheRawKeyOutOfQueriesAndErrors(t *testing.T) {
	t.Parallel()
	const raw = "sk-secret"
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.WriteHeader(http.StatusInternalServerError)
	}))
	gw := &usage.Gateway{BaseURL: srv.URL, MasterKey: masterKey, HTTP: srv.Client()}
	_, err := gw.LookupKey(t.Context(), raw)
	require.Error(t, err)
	require.NotContains(t, err.Error(), raw)
	require.Contains(t, query, usage.TokenHash(raw))
	require.NotContains(t, err.Error(), usage.TokenHash(raw))
	srv.Close()
	_, err = gw.LookupKey(t.Context(), raw)
	require.Error(t, err)
	require.NotContains(t, err.Error(), usage.TokenHash(raw), "a transport error quotes no URL")
}

func TestIssueNamesTheKeyAndBlocksItWhenAsked(t *testing.T) {
	t.Parallel()
	fake := &testsupport.FakeGateway{MasterKey: masterKey}
	gw := fake.Client(t)
	issued, err := gw.Issue(t.Context(), "alice", usage.KeyLimits{Key: "sk-chosen", Blocked: true})
	require.NoError(t, err)
	require.Equal(t, "sk-chosen", issued.Key)
	info, err := gw.LookupKey(t.Context(), "sk-chosen")
	require.NoError(t, err)
	require.True(t, info.Blocked)
	_, err = gw.Issue(t.Context(), "bob", usage.KeyLimits{Key: "sk-chosen", MaxBudgetUSD: 500})
	require.NoError(t, err, "the pinned LiteLLM upserts on the token with an empty update: a success that changes nothing")
	info, err = gw.LookupKey(t.Context(), "sk-chosen")
	require.NoError(t, err)
	require.Equal(t, "alice", info.Alias)
	require.Zero(t, info.MaxBudgetUSD, "the first row stands: no second budget")
}
