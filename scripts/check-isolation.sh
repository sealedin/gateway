#!/usr/bin/env bash
# One place for the import-isolation rules; make lint and CI both call it.
set -euo pipefail
check() {
  local pkg=$1 forbidden=$2 why=$3
  deps=$(go list -deps "./$pkg")
  if grep -qE "$forbidden" <<<"$deps"; then
    echo "$pkg $why" >&2
    exit 1
  fi
}
check cmd/egress '/internal/enclave(/|$)' 'holds no enclave key: it must not depend on internal/enclave'
check cmd/identity '/internal/(egress|teeverify)(/|$)' 'holds the enclave key: it must not depend on the egress or upstream verification'
check internal/keys '/internal/enclave(/|$)' 'issues keys for the gateway: it must not reach the enclave key or the agent socket'
check internal/usage '/internal/enclave(/|$)' 'is the gateway admin client: it must not reach the enclave key or the agent socket'
check cmd/identity 'gagliardetto|/internal/(x402|sales|rpcproxy|solanarpc)(/|$)|testsupport' 'holds the quote-bound key and only derives the secret behind sold keys: it must not parse client transactions or link the Solana library'
check cmd/rpcproxy '/internal/(enclave|x402|sales|keys|usage)(/|$)|gagliardetto' 'holds a provider API key and no other: it must not reach any signing key or the gateway admin API'
check cmd/egress '/internal/(x402|sales|keys|rpcproxy)(/|$)|gagliardetto' 'is the upstream path only: it must not reach the fee payer or key issuance'
check cmd/sales '/internal/(enclave|egress|teeverify|rpcproxy)(/|$)|solana-go/rpc|solana-go/programs/token|x402client|x402test|testsupport' 'holds the fee payer key: it must not reach the agent socket, and links only what parsing a transaction needs'
# An allowlist, read from a variable: a pipe into grep -q reads as a pass under pipefail once the list outgrows the buffer.
drain_deps=$(go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./cmd/drain)
if grep -vE '^github.com/sealedin/gateway/(cmd/drain|internal/drain|internal/limits)$' <<<"$drain_deps" | grep -E '.' >&2; then
  echo 'cmd/drain sees every prompt and reply: it must link only its own code and internal/limits' >&2
  exit 1
fi
check internal/x402 '/internal/enclave(/|$)' 'holds the fee payer key it is handed: it must not reach the enclave key or the agent socket'
# The operators' fee payer key: cmd/sales alone reads the variable, and internal/x402 must never derive a gateway key from it.
readers=$(grep -rlE 'SEALEDIN_FEE_PAYER_KEY' --include='*.go' cmd internal | grep -v '_test.go$' || true)
if [ "$readers" != "cmd/sales/main.go" ]; then
  echo "only cmd/sales may read SEALEDIN_FEE_PAYER_KEY; found: $readers" >&2
  exit 1
fi
