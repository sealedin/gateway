package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/sealedin/gateway/internal/drain"
	"github.com/sealedin/gateway/internal/enclave"
	"github.com/sealedin/gateway/internal/gateway"
	"github.com/sealedin/gateway/internal/keys"
	"github.com/sealedin/gateway/internal/testvectors"
	"github.com/sealedin/gateway/internal/usage"
)

// demoIdentity is the unattested demo identity; not parallel-safe (env var).
func demoIdentity(t *testing.T) *enclave.Identity {
	t.Helper()
	t.Setenv("SEALEDIN_ENCLAVE_SEED", testvectors.DemoSeed)
	id, err := enclave.NewIdentity()
	require.NoError(t, err)
	return id
}

func runAsync(ctx context.Context, args ...string) <-chan int {
	done := make(chan int, 1)
	go func() { done <- run(ctx, args, io.Discard) }()
	return done
}

func waitExit(t *testing.T, done <-chan int, want int) {
	t.Helper()
	select {
	case code := <-done:
		require.Equal(t, want, code)
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit")
	}
}

func TestRunRejectsBadFlag(t *testing.T) {
	t.Parallel()
	require.Equal(t, exitUsage, run(context.Background(), []string{"-nope"}, io.Discard))
}

func TestRunShutsDownOnContextCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, "-listen", "127.0.0.1:0", "-private-listen", "127.0.0.1:0")
	time.Sleep(200 * time.Millisecond)
	cancel()
	waitExit(t, done, exitOK)
}

// The plaintext bootstrap mux must never grow the private surface: only the private listener serves it.
func TestPublicMuxServesOnlyBootstrap(t *testing.T) {
	id := demoIdentity(t)
	public := enclave.NewMux(id, nil)
	private := privateMux(id, gateway.MeasuredCatalog(), &keys.Service{}, func() string { return "" })
	// No positive bootstrap rows: unattested /v1/quote 404s itself, and the enclave package tests cover it.
	tests := []struct {
		name     string
		mux      *http.ServeMux
		path     string
		wantCode int
	}{
		{"public has no catalog", public, "/v1/catalog", http.StatusNotFound},
		{"private listener serves catalog", private, "/v1/catalog", http.StatusOK},
		{"public has no key issuance", public, "/v1/keys/alice", http.StatusNotFound},
		{"private listener guards key issuance", private, "/v1/keys/alice", http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			require.Equal(t, tc.wantCode, rec.Code)
		})
	}
}

// caddyRoute is one reverse_proxy line of the edge table with the paths its named matcher lists.
type caddyRoute struct {
	upstream string
	paths    []string
}

// caddyRoutes parses the named path matchers and reverse_proxy lines of one Caddyfile block, in order.
func caddyRoutes(block string) []caddyRoute {
	matchers := map[string][]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(@\w+) path ((?:/\S+\s*)+)$`).FindAllStringSubmatch(block, -1) {
		matchers[m[1]] = strings.Fields(m[2])
	}
	var routes []caddyRoute
	for _, p := range regexp.MustCompile(`(?m)^\s*reverse_proxy\s+(@\w+)\s+(\S+)$`).FindAllStringSubmatch(block, -1) {
		routes = append(routes, caddyRoute{upstream: p[2], paths: matchers[p[1]]})
	}
	return routes
}

// caddyBlock returns the text of the top-level block that starts with header.
func caddyBlock(t *testing.T, text, header string) string {
	t.Helper()
	start := strings.Index(text, header+" {")
	require.NotEqual(t, -1, start, "edge/Caddyfile lacks the %s block", header)
	end := strings.Index(text[start:], "\n}\n")
	require.NotEqual(t, -1, end)
	return text[start : start+end]
}

// The edge routing table, the two muxes and the measured compose state one invariant in three files; pin them together.
func TestMeasuredTopologyStaysInSync(t *testing.T) {
	id := demoIdentity(t)
	caddyfile, err := os.ReadFile(filepath.Join("..", "..", "edge", "Caddyfile"))
	require.NoError(t, err)
	text := string(caddyfile)
	require.Contains(t, text, "admin off", "the edge admin API could rewrite the measured routing table")

	// The public table is self-authenticating payloads and the liveness probe: all a platform-terminated name may carry.
	wantPublic := []caddyRoute{
		{"identity:8471", []string{"/v1/quote", "/v1/tls"}},
		{"identity:8473", []string{"/v1/catalog"}},
		{"gateway:4000", []string{"/health/liveliness"}},
	}
	require.Equal(t, wantPublic, caddyRoutes(caddyBlock(t, text, "(public)")), "no catch-all, every reverse_proxy names a matcher")
	// Inference and a key's own info carry a client key, so they ride only the end-to-end TLS site. Inference goes through
	// the drain, or a client hanging up gets what it read for free, and the drain's own table is the same list.
	wantInference := []caddyRoute{{"drain:8477", drain.Routes()}, {"gateway:4000", []string{"/key/info"}}}
	require.Equal(t, wantInference, caddyRoutes(caddyBlock(t, text, "(inference)")))
	require.NotContains(t, text, "reverse_proxy gateway:4000", "the gateway must never be a catch-all")

	// Purchases and key issuance ride only the end-to-end TLS site, never the platform-terminated 8080 listener. Purchases
	// go to the service holding the fee payer, ahead of the prefix that would send them to the identity.
	wantKeys := []caddyRoute{
		{"sales:8476", []string{"/v1/keys/buy", "/v1/keys/recover", "/v1/keys/claim"}},
		{"identity:8473", []string{"/v1/keys", "/v1/keys/*"}},
	}
	site := caddyBlock(t, text, "{$EDGE_DOMAIN}")
	require.Equal(t, wantKeys, caddyRoutes(site))
	require.Contains(t, site, "import public")
	require.Contains(t, site, "import inference")
	plain := caddyBlock(t, text, "http://:8080")
	require.Empty(t, caddyRoutes(plain))
	require.Contains(t, plain, "import public")
	require.NotContains(t, plain, "import inference", "inference never rides the platform-terminated listener")
	require.NotContains(t, plain, "keys")
	for name, block := range map[string]string{"{$EDGE_DOMAIN}": site, "http://:8080": plain} {
		require.Less(t, strings.Index(block, "import noncanonical"), strings.Index(block, "import public"),
			"%s must refuse non-canonical paths before any table", name)
		require.Regexp(t, `(?m)^\s*respond 404\s*$`, block, "%s: everything off the allowlist is a bare 404", name)
	}

	// Every path routed to the private listener must be served there, and nothing else may be.
	private := privateMux(id, gateway.MeasuredCatalog(), &keys.Service{}, func() string { return "" })
	for _, route := range slices.Concat(wantPublic, wantInference, wantKeys) {
		for _, matcher := range route.paths {
			rec := httptest.NewRecorder()
			private.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, strings.ReplaceAll(matcher, "*", "x"), nil))
			if route.upstream == "sales:8476" {
				continue // the identity has no purchase route; TestIdentityServesNoPurchaseRoute pins it
			}
			if route.upstream == "identity:8473" {
				require.NotEqual(t, http.StatusNotFound, rec.Code, "%s routed to the private listener but not served there", matcher)
			} else {
				require.Equal(t, http.StatusNotFound, rec.Code, "%s must not be served by the private listener", matcher)
			}
		}
	}
}

// The raw-path refusal in edge/Caddyfile is pinned here against what a cleaner could fold into an allowlisted route.
func TestEdgeRefusesNonCanonicalPaths(t *testing.T) {
	t.Parallel()
	caddyfile, err := os.ReadFile(filepath.Join("..", "..", "edge", "Caddyfile"))
	require.NoError(t, err)
	m := regexp.MustCompile(`(?m)^\s*@noncanonical path_regexp (\S+)$`).FindStringSubmatch(string(caddyfile))
	require.Len(t, m, 2, "edge/Caddyfile must define @noncanonical as a path_regexp")
	refused := regexp.MustCompile(m[1])
	require.Regexp(t, `(?m)^\s*respond @noncanonical 404\s*$`, string(caddyfile))

	tests := []struct {
		path string
		want bool
	}{
		{"/v1/keys/alice", false},
		{"/v1/messages", false},
		{"/v1/chat/completions", false},
		{"/key/info", false},
		{"/v1/keys/a.b", false},
		{"/v1/keys/../price", true},
		{"/v1/keys/..", true},
		{"/v1/keys/.", true},
		{"/v1/./keys", true},
		{"/v1/%2e%2e/keys", true},
		{"/v1/%2E%2E/keys", true},
		{"/v1%2fkeys", true},
		{"/v1%5ckeys", true},
		{"/v1//keys", true},
		{"/v1\\keys", true},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, refused.MatchString(tc.path))
		})
	}
}

// The measured compose quotes through the agent socket, publishes only the edge, has no per-operator value.
func TestMeasuredComposeStaysInSync(t *testing.T) {
	compose, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	text := string(compose)
	published := regexp.MustCompile(`(?m)^\s*-\s*"?(\d+):(\d+)"?\s*$`).FindAllStringSubmatch(text, -1)
	require.NotEmpty(t, published)
	// Port 80 never passes through the platform gateway, so HTTP-01 is off and no port 80 is published; the private
	// listener is never published.
	var ports []string
	for _, mapping := range published {
		require.Equal(t, mapping[1], mapping[2], "ports are published under their own number")
		ports = append(ports, mapping[1])
	}
	require.ElementsMatch(t, []string{"443", "8080"}, ports)
	require.Regexp(t, `- /var/run/dstack\.sock:/var/run/dstack\.sock`, text, "identity quotes through the guest agent socket")
	require.NotContains(t, text, "- ./", "the measured compose must not bind-mount anything else")
	for _, forbidden := range []string{"devices:", "security_opt", `user: "0:0"`, "privileged"} {
		require.NotContains(t, text, forbidden, "the host rejects %s and the agent path needs none of it", forbidden)
	}
	require.Contains(t, text, `"-private-listen"`, "the explicit flag is the fail-closed guard against a pre-split identity image")
	require.Regexp(t, `EDGE_DOMAIN: &domain "\$\{SEALEDIN_EDGE_DOMAIN:\?`, text, "the domain must be a required env interpolation")
	require.Regexp(t, `"-edge-sni",\s*\*domain`, text, "the identity must take the domain from the edge anchor")
	require.Len(t, regexp.MustCompile(`ghcr\.io/sealedin/[a-z-]+@sha256:[0-9a-f]{64}`).FindAllString(text, -1), 7,
		"every image of ours is pinned by digest")
}

// composeService is the subset of a compose service the isolation pins inspect.
type composeService struct {
	Ports     []string `yaml:"ports"`
	Networks  []string `yaml:"networks"`
	Volumes   []string `yaml:"volumes"`
	DependsOn []string `yaml:"depends_on"`
}

// measuredCompose is the subset of docker-compose.phala.yml the isolation pins inspect.
type measuredCompose struct {
	Services map[string]composeService `yaml:"services"`
	Networks map[string]struct {
		Internal bool `yaml:"internal"`
	} `yaml:"networks"`
	Volumes map[string]struct {
		DriverOpts map[string]string `yaml:"driver_opts"`
	} `yaml:"volumes"`
}

func loadMeasuredCompose(t *testing.T) measuredCompose {
	t.Helper()
	compose, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	var parsed measuredCompose
	require.NoError(t, yaml.Unmarshal(compose, &parsed))
	return parsed
}

// Only the identity talks to the guest agent: a compromised gateway or sales service must not be able to quote or derive
// keys. The master key reaches the gateway and the sales service through a tmpfs volume the identity writes and they only
// read; the secret behind sold keys has its own, which the gateway does not mount, and the fee payer's public address comes
// back on a third.
func TestMeasuredComposeKeepsTheAgentSocketToIdentity(t *testing.T) {
	parsed := loadMeasuredCompose(t)
	const socket = "/var/run/dstack.sock:/var/run/dstack.sock"
	for name, svc := range parsed.Services {
		if name == "identity" {
			require.Contains(t, svc.Volumes, socket, "the identity quotes and derives keys through the agent socket")
			continue
		}
		for _, v := range svc.Volumes {
			require.NotContains(t, v, "dstack.sock", "%s must not mount the guest agent socket", name)
		}
	}
	require.Contains(t, parsed.Services["identity"].Volumes, "masterkey:/run/sealedin")
	require.Contains(t, parsed.Services["gateway"].Volumes, "masterkey:/run/sealedin:ro")
	require.Contains(t, parsed.Services["gateway"].DependsOn, "identity", "the gateway waits for the key file")
	require.Contains(t, parsed.Services["sales"].Volumes, "masterkey:/run/sealedin:ro")
	require.Contains(t, parsed.Services["identity"].Volumes, "virtualkey:/run/sealedin-virtualkey")
	require.Contains(t, parsed.Services["sales"].Volumes, "virtualkey:/run/sealedin-virtualkey:ro")
	require.Contains(t, parsed.Services["sales"].Volumes, "feepayeraddress:/run/sealedin-feepayer-address")
	require.Contains(t, parsed.Services["identity"].Volumes, "feepayeraddress:/run/sealedin-feepayer-address:ro")
	for name, svc := range parsed.Services {
		if name == "identity" || name == "sales" {
			continue
		}
		for _, v := range svc.Volumes {
			require.NotContains(t, v, "virtualkey", "%s must not mount the secret behind sold keys", name)
			require.NotContains(t, v, "feepayer", "%s has no business with the fee payer", name)
		}
	}
	for _, volume := range []string{"masterkey", "virtualkey", "feepayeraddress"} {
		opts := parsed.Volumes[volume].DriverOpts
		require.Equal(t, "tmpfs", opts["type"], "%s never touches a disk", volume)
		require.Equal(t, "tmpfs", opts["device"])
		require.Contains(t, opts["o"], "uid=65532", "the identity's nonroot user must own the volume to write there")
	}
}

// reachable is who a service can talk to: every service sharing a network with it.
func reachable(parsed measuredCompose, service string) []string {
	var peers []string
	for name, svc := range parsed.Services {
		if name != service && slices.ContainsFunc(svc.Networks, func(n string) bool {
			return slices.Contains(parsed.Services[service].Networks, n)
		}) {
			peers = append(peers, name)
		}
	}
	return peers
}

// LiteLLM, Postgres, the identity and the sales service get no path to the internet; only the edge (ACME, inbound), the
// egress (Chutes) and the rpcproxy (Solana) do, and of the services with no route of their own only the sales service can
// talk to the rpcproxy, whose params reach external hosts: anything else there could use it to carry data out.
func TestMeasuredComposeIsolatesNetworks(t *testing.T) {
	parsed := loadMeasuredCompose(t)
	require.True(t, parsed.Networks["internal"].Internal, "the internal network must carry internal: true")
	require.True(t, parsed.Networks["solana"].Internal, "the solana network must carry internal: true")
	internalPeersOfProxy := []string{}
	for _, peer := range reachable(parsed, "rpcproxy") {
		if !slices.Contains(parsed.Services[peer].Networks, "egress") {
			internalPeersOfProxy = append(internalPeersOfProxy, peer)
		}
	}
	require.Equal(t, []string{"sales"}, internalPeersOfProxy, "only the sales service may reach the rpcproxy from inside")
	require.NotContains(t, reachable(parsed, "gateway"), "rpcproxy", "LiteLLM must have no way out through the proxy")
	require.False(t, parsed.Networks["egress"].Internal, "the egress network must route out")

	tests := []struct {
		service      string
		wantNetworks []string
		wantPorts    bool
	}{
		{"edge", []string{"internal", "egress"}, true},
		{"egress", []string{"internal", "egress"}, false},
		{"rpcproxy", []string{"solana", "egress"}, false},
		{"sales", []string{"internal", "solana"}, false},
		{"drain", []string{"internal"}, false},
		{"gateway", []string{"internal"}, false},
		{"db", []string{"internal"}, false},
		{"identity", []string{"internal"}, false},
	}
	require.Len(t, parsed.Services, len(tests), "every service must be pinned to its networks")
	for _, tc := range tests {
		t.Run(tc.service, func(t *testing.T) {
			svc, ok := parsed.Services[tc.service]
			require.True(t, ok, "service %s missing", tc.service)
			require.ElementsMatch(t, tc.wantNetworks, svc.Networks)
			require.Equal(t, tc.wantPorts, len(svc.Ports) > 0, "ports: %v", svc.Ports)
		})
	}
}

// keyIssuer's three startup branches: attested derives, publishes and demands the operator bearer; a failing agent
// is fatal; no agent falls back to the environment.
func TestKeyIssuerBranches(t *testing.T) {
	var fixed [enclave.KeySize]byte
	fixed[0] = 0xab
	attested := func(_ context.Context, path, purpose string) ([enclave.KeySize]byte, error) {
		if path != usage.MasterKeyPath || purpose != usage.MasterKeyPurpose {
			return fixed, errors.New("wrong derivation request")
		}
		return fixed, nil
	}
	broken := func(context.Context, string, string) ([enclave.KeySize]byte, error) {
		return fixed, errors.New("kms down")
	}
	dev := func(context.Context, string, string) ([enclave.KeySize]byte, error) {
		return fixed, enclave.ErrNotAttested
	}
	logger := slog.New(slog.DiscardHandler)

	t.Run("attested publishes and requires operator", func(t *testing.T) {
		t.Setenv(operatorKeyEnv, "")
		file := filepath.Join(t.TempDir(), "key")
		_, err := keyIssuer(t.Context(), "http://gw", file, attested, logger)
		require.ErrorContains(t, err, operatorKeyEnv)
		require.NoFileExists(t, file)

		t.Setenv(operatorKeyEnv, "op")
		svc, err := keyIssuer(t.Context(), "http://gw", file, attested, logger)
		require.NoError(t, err)
		require.Equal(t, usage.FormatMasterKey(fixed), svc.Gateway.MasterKey)
		require.Equal(t, "op", svc.Operator)
		require.Equal(t, gateway.CatalogModels(), svc.Models)
		published, err := os.ReadFile(file)
		require.NoError(t, err)
		require.Equal(t, usage.FormatMasterKey(fixed)+"\n", string(published))
	})
	t.Run("broken agent is fatal", func(t *testing.T) {
		t.Setenv(operatorKeyEnv, "op")
		_, err := keyIssuer(t.Context(), "http://gw", filepath.Join(t.TempDir(), "key"), broken, logger)
		require.ErrorContains(t, err, "kms down")
	})
	t.Run("no agent falls back to the environment", func(t *testing.T) {
		t.Setenv(operatorKeyEnv, "op")
		t.Setenv(devMasterKeyEnv, "sk-dev")
		file := filepath.Join(t.TempDir(), "key")
		svc, err := keyIssuer(t.Context(), "http://gw", file, dev, logger)
		require.NoError(t, err)
		require.Equal(t, "sk-dev", svc.Gateway.MasterKey)
		require.NoFileExists(t, file, "dev mode publishes nothing")
	})
}

// The gateway wrapper reads the file the identity writes: the path is the one constant shared across the two images.
func TestEntrypointReadsThePublishedKeyPath(t *testing.T) {
	t.Parallel()
	wrapper, err := os.ReadFile(filepath.Join("..", "..", "gateway", "entrypoint.py"))
	require.NoError(t, err)
	dir, file := filepath.Split(defaultMasterKeyFile)
	require.Contains(t, string(wrapper), `KEY_DIR = "`+strings.TrimSuffix(dir, "/")+`"`)
	require.Contains(t, string(wrapper), `KEY_FILE = KEY_DIR + "/`+file+`"`)
}

// The published key file is owner-read-only, replaces a stale copy, and never leaves a partial file behind.
func TestPublishSecret(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "litellm-master-key")
	require.NoError(t, publishSecret(path, "sk-old"))
	require.NoError(t, publishSecret(path, "sk-new"))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "sk-new\n", string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(masterKeyFileMode), info.Mode().Perm())
	require.NoFileExists(t, path+".tmp")
}

// reserveAddr picks a free loopback address by binding and releasing it; the tiny reuse race is acceptable in tests.
func reserveAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// run brings the private listener up next to the public one and still shuts down cleanly.
func TestRunStartsPrivateListener(t *testing.T) {
	demoIdentity(t)
	addr := reserveAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, "-listen", "127.0.0.1:0", "-private-listen", addr)
	require.Eventually(t, func() bool {
		conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		return dialErr == nil && conn.Close() == nil
	}, 5*time.Second, 50*time.Millisecond, "private listener never came up on %s", addr)
	cancel()
	waitExit(t, done, exitOK)
}

// A private listener that cannot bind must take the whole process down, not leave the public half running.
func TestRunFailsWhenPrivatePortBusy(t *testing.T) {
	demoIdentity(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { require.NoError(t, listener.Close()) }()
	done := runAsync(context.Background(), "-listen", "127.0.0.1:0", "-private-listen", listener.Addr().String())
	waitExit(t, done, exitError)
}

// The private listener serves the measured catalog signed by this identity's key.
func TestPrivateListenerServesMeasuredCatalog(t *testing.T) {
	id := demoIdentity(t)
	rec := httptest.NewRecorder()
	private := privateMux(id, gateway.MeasuredCatalog(), &keys.Service{}, func() string { return "" })
	private.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/catalog", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var got enclave.SignedCatalog
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, gateway.MeasuredCatalog(), got.Catalog.Catalog)
	require.Equal(t, id.PublicKeyHex(), got.Pubkey)
	sig, err := hex.DecodeString(got.Signature)
	require.NoError(t, err)
	msg, err := got.Message()
	require.NoError(t, err)
	require.True(t, ed25519.Verify(id.PublicKey(), msg, sig))
}

// Purchases live on the sales service: the identity's private listener has no POST route for them.
func TestIdentityServesNoPurchaseRoute(t *testing.T) {
	id := demoIdentity(t)
	private := privateMux(id, gateway.MeasuredCatalog(), &keys.Service{}, func() string { return "" })
	for _, path := range []string{"/v1/keys/buy", "/v1/keys/recover", "/v1/keys/claim"} {
		rec := httptest.NewRecorder()
		private.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code, path)
		rec = httptest.NewRecorder()
		enclave.NewMux(id, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		require.Equal(t, http.StatusNotFound, rec.Code, path)
	}
}

func notAttested(context.Context, string, string) ([enclave.KeySize]byte, error) {
	return [enclave.KeySize]byte{}, enclave.ErrNotAttested
}

const devTreasury = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"

func setDevPayment(t *testing.T) {
	t.Helper()
	t.Setenv(gateway.DevFeePayerSeedEnv, strings.Repeat("07", enclave.KeySize))
	t.Setenv("SEALEDIN_DEV_PAYMENT_NETWORK", "solana:test")
	t.Setenv("SEALEDIN_DEV_TREASURY", devTreasury)
	t.Setenv("SEALEDIN_DEV_PAYMENT_ASSET", gateway.PaymentAsset)
}

// setUpPurchases' branches: the dev settings fire only unattested, and attested they cannot change a thing.
func TestSetUpPurchasesBranches(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	setUp := func(t *testing.T, derive keySource) (gateway.Terms, func() string, error) {
		t.Helper()
		dir := t.TempDir()
		return setUpPurchases(t.Context(), filepath.Join(dir, "secret"), filepath.Join(dir, "address"), derive, logger)
	}
	t.Run("a broken agent is fatal, and it asks for the virtual key path, never a fee payer path", func(t *testing.T) {
		var path, purpose string
		broken := func(_ context.Context, p, q string) ([enclave.KeySize]byte, error) {
			path, purpose = p, q
			return [enclave.KeySize]byte{}, errors.New("kms down")
		}
		_, _, err := setUp(t, broken)
		require.ErrorContains(t, err, "kms down")
		require.Equal(t, "sealedin/virtual-key/v1", path)
		require.NotEmpty(t, purpose)
	})
	t.Run("attested publishes the derived secret, and the catalog reads the address sales published", func(t *testing.T) {
		dir := t.TempDir()
		secretFile, addressFile := filepath.Join(dir, "secret"), filepath.Join(dir, "address")
		derived := func(context.Context, string, string) ([enclave.KeySize]byte, error) {
			return [enclave.KeySize]byte{0xab}, nil
		}
		terms, feePayer, err := setUpPurchases(t.Context(), secretFile, addressFile, derived, logger)
		require.NoError(t, err)
		require.Equal(t, gateway.MeasuredTerms(), terms)
		secret, err := os.ReadFile(secretFile)
		require.NoError(t, err)
		require.Equal(t, "ab"+strings.Repeat("00", enclave.KeySize-1)+"\n", string(secret))
		require.Empty(t, feePayer(), "before sales publishes, purchases read as off")
		require.NoError(t, os.WriteFile(addressFile, []byte("not an address\n"), 0o600))
		require.Empty(t, feePayer())
		require.NoError(t, os.WriteFile(addressFile, []byte(devTreasury+"\n"), 0o600))
		require.Equal(t, devTreasury, feePayer())
	})
	t.Run("off without a dev seed", func(t *testing.T) {
		t.Setenv(gateway.DevFeePayerSeedEnv, "")
		terms, feePayer, err := setUp(t, notAttested)
		require.NoError(t, err)
		require.Empty(t, feePayer())
		require.Equal(t, gateway.MeasuredTerms(), terms)
	})
	t.Run("the dev seed gives the catalog its address and its terms, and publishes nothing", func(t *testing.T) {
		setDevPayment(t)
		dir := t.TempDir()
		file := filepath.Join(dir, "secret")
		terms, feePayer, err := setUpPurchases(t.Context(), file, filepath.Join(dir, "address"), notAttested, logger)
		require.NoError(t, err)
		var seed [enclave.KeySize]byte
		for i := range seed {
			seed[i] = 7
		}
		require.Equal(t, feePayerAddress(seed), feePayer())
		require.Equal(t, gateway.DevTerms(), terms)
		require.Equal(t, devTreasury, gateway.CatalogFor(terms).PayTo, "catalog and challenge read the same terms")
		require.NoFileExists(t, file)
	})
	t.Run("a bad dev seed is a startup error", func(t *testing.T) {
		t.Setenv(gateway.DevFeePayerSeedEnv, "zz")
		_, _, err := setUp(t, notAttested)
		require.ErrorContains(t, err, gateway.DevFeePayerSeedEnv)
	})
}

// The sponsor's address is the Solana form of the public key of the seed the sales service will load.
func TestFeePayerAddressIsBase58OfThePublicKey(t *testing.T) {
	t.Parallel()
	var seed [enclave.KeySize]byte
	seed[0] = 1
	raw, err := base58.Decode(feePayerAddress(seed))
	require.NoError(t, err)
	require.Equal(t, []byte(ed25519.NewKeyFromSeed(seed[:])[ed25519.SeedSize:]), raw)
}

// Root access goes with the dev image and only with it, and these refusals come before any secret or platform call.
func TestDeployTiesTheRootKeyToTheDevImage(t *testing.T) {
	t.Parallel()
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "deploy-phala.sh"))
	require.NoError(t, err)
	const goodKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []struct {
		name, image, key, want string
	}{
		{"default dev image without a key", "", "", "needs SEALEDIN_ROOT_SSH_PUBKEY"},
		{"dev image without a key", "dstack-dev-0.5.12", "", "needs SEALEDIN_ROOT_SSH_PUBKEY"},
		{"production image with a key", "dstack-0.6.1", goodKey, "has no root access"},
		{"not a public key", "dstack-dev-0.5.12", "-----BEGIN OPENSSH PRIVATE KEY-----", "one ssh-ed25519 public key"},
		{"a second line", "dstack-dev-0.5.12", goodKey + "\nEVIL=1", "one ssh-ed25519 public key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), script, "create", "x")
			cmd.Env = append(os.Environ(), "SEALEDIN_EDGE_DOMAIN=api.example.com", "SEALEDIN_PHALA_IMAGE="+tc.image,
				"SEALEDIN_ROOT_SSH_PUBKEY="+tc.key)
			out, runErr := cmd.CombinedOutput()
			require.Error(t, runErr)
			require.Contains(t, string(out), tc.want)
		})
	}
}

// The refusal the deploy runs first; the check is safe to execute here, it has no side effects. It is read against fixtures
// so it never stops testing once the real values are set.
func TestReleasePinsRefusePlaceholders(t *testing.T) {
	t.Parallel()
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "check-release-pins.sh"))
	require.NoError(t, err)
	deploy, err := os.ReadFile(filepath.Join("..", "..", "scripts", "deploy-phala.sh"))
	require.NoError(t, err)
	require.Less(t, strings.Index(string(deploy), "./scripts/check-release-pins.sh"), strings.Index(string(deploy), "envfile=$(mktemp)"),
		"the refusal runs before any secret is materialized")

	const placeholderTreasury, realTreasury = "\tTreasury = TreasuryPlaceholder\n", "\tTreasury = \"" + devTreasury + "\"\n"
	const placeholderHost, realHost = "primary:\n  url: https://x.invalid/\n", "primary:\n  url: https://rpc.test/\n"
	tests := []struct {
		name, treasury, policy string
		want                   []string
	}{
		{"both placeholders", placeholderTreasury, placeholderHost, []string{"placeholder treasury", "placeholder RPC host"}},
		{"treasury only", placeholderTreasury, realHost, []string{"placeholder treasury"}},
		{"host only", realTreasury, placeholderHost, []string{"placeholder RPC host"}},
		{"both set", realTreasury, realHost, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(root, "internal", "gateway"), 0o700))
			require.NoError(t, os.MkdirAll(filepath.Join(root, "rpcproxy"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "internal", "gateway", "payment.go"), []byte(tc.treasury), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(root, "rpcproxy", "policy.yaml"), []byte(tc.policy), 0o600))
			cmd := exec.CommandContext(t.Context(), script, root)
			out, runErr := cmd.CombinedOutput()
			if tc.want == nil {
				require.NoError(t, runErr, string(out))
				return
			}
			require.Error(t, runErr)
			for _, message := range tc.want {
				require.Contains(t, string(out), message)
			}
		})
	}
}

// The measured sales service takes its secrets from the identity's files, and that is what keeps it off the dev branch.
func TestMeasuredComposeRunsSalesAttested(t *testing.T) {
	compose, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	secretDir, _ := filepath.Split(defaultVirtualKeySecretFile)
	keyDir, _ := filepath.Split(defaultMasterKeyFile)
	require.Contains(t, string(compose), `"-virtual-key-secret-file", "`+defaultVirtualKeySecretFile+`"`)
	require.Contains(t, string(compose), `"-fee-payer-address-file", "`+defaultFeePayerAddressFile+`"`)
	require.Contains(t, string(compose), `"-master-key-file", "`+defaultMasterKeyFile+`"`)
	require.Contains(t, string(compose), "virtualkey:"+strings.TrimSuffix(secretDir, "/")+":ro")
	require.Contains(t, string(compose), "masterkey:"+strings.TrimSuffix(keyDir, "/")+":ro")
	require.NotContains(t, string(compose), "SEALEDIN_DEV_", "no dev setting is measured")
	require.NotContains(t, string(compose), "fee-payer/v1")
}

// The compose carries the rpcproxy's key by a required interpolation, and only the rpcproxy sees it.
func TestMeasuredComposeKeepsTheRPCKeyToTheProxy(t *testing.T) {
	compose, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	require.Regexp(t, `SOLANA_RPC_API_KEY: \$\{SOLANA_RPC_API_KEY:\?`, string(compose))
	var parsed struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(compose, &parsed))
	for name, svc := range parsed.Services {
		_, has := svc.Environment["SOLANA_RPC_API_KEY"]
		require.Equal(t, name == "rpcproxy", has, "%s and SOLANA_RPC_API_KEY", name)
		_, has = svc.Environment["SEALEDIN_FEE_PAYER_KEY"]
		require.Equal(t, name == "sales", has, "%s and SEALEDIN_FEE_PAYER_KEY", name)
	}
}

// The drain sees every prompt and reply, so it gets nothing else: no volume, no environment, no way out.
func TestMeasuredComposeGivesTheDrainNothing(t *testing.T) {
	compose, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	var parsed struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(compose, &parsed))
	svc, ok := parsed.Services["drain"]
	require.True(t, ok)
	for _, field := range []string{"volumes", "environment", "ports", "command", "env_file"} {
		require.NotContains(t, svc, field, "the drain must have no %s", field)
	}
	require.Equal(t, []any{"internal"}, svc["networks"])
}

// The end-to-end test must run against what is measured, or a LiteLLM bump would keep testing the old image.
func TestEndToEndUsesTheMeasuredImages(t *testing.T) {
	t.Parallel()
	e2e, err := os.ReadFile(filepath.Join("..", "..", "scripts", "e2e", "stream-billing", "compose.yml"))
	require.NoError(t, err)
	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "gateway", "Dockerfile"))
	require.NoError(t, err)
	edge, err := os.ReadFile(filepath.Join("..", "..", "edge", "Dockerfile"))
	require.NoError(t, err)
	compose, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.phala.yml"))
	require.NoError(t, err)
	pin := regexp.MustCompile(`[a-z./]+@sha256:[0-9a-f]{64}`)
	measured := pin.FindAllString(string(dockerfile)+string(edge)+string(compose), -1)
	used := pin.FindAllString(string(e2e), -1)
	require.NotEmpty(t, used)
	for _, image := range used {
		require.Contains(t, measured, image)
	}
}

// Two measured settings a hang-up or one bad route would otherwise turn into a leak or an outage.
func TestMeasuredSettingsStayInPlace(t *testing.T) {
	t.Parallel()
	caddyfile, err := os.ReadFile(filepath.Join("..", "..", "edge", "Caddyfile"))
	require.NoError(t, err)
	require.Contains(t, string(caddyfile), "exclude http.handlers.reverse_proxy http.log.error", "keys and queries stay out of the edge log")
	require.Equal(t, 2, strings.Count(string(caddyfile), "import bodylimit"), "both sites cap a body before any table")
	config, err := os.ReadFile(filepath.Join("..", "..", "gateway", "config.yaml"))
	require.NoError(t, err)
	require.Regexp(t, `(?m)^router_settings:\n  disable_cooldowns: true$`, string(config))
	require.Regexp(t, `(?m)^  disable_token_counter: true$`, string(config), "one prompt can otherwise freeze every request")
	require.Regexp(t, `(?m)^  callbacks: request_guard\.guard$`, string(config), "a client can otherwise set fields behind the price")
}
