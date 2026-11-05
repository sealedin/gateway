#!/usr/bin/env bash
# Refuses a release with a payment placeholder left in it; deploy-phala.sh calls it before anything else happens, and a
# test runs it against fixtures through the optional root argument, so it must stay free of side effects.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"
bad=0
if grep -qE '^\s*Treasury = TreasuryPlaceholder' internal/gateway/payment.go; then
  echo "placeholder treasury in internal/gateway/payment.go: set the operator's address and its pin first" >&2; bad=1
fi
if grep -qE '^\s*url: https://[^/]*\.invalid/' rpcproxy/policy.yaml; then
  echo "placeholder RPC host in rpcproxy/policy.yaml: set the provider first" >&2; bad=1
fi
exit "$bad"
