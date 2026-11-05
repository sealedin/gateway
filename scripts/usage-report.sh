#!/usr/bin/env bash
# Spend of one virtual key by alias through the identity's key issuance (/v1/keys/<alias> behind the edge), with the
# operator token from the macOS Keychain item `sealedin-operator`; no master key ever leaves the CVM. Spend is USD
# computed from the measured price sheet (gateway/config.yaml).
#
# Usage: usage-report.sh <alias>
# Example: usage-report.sh alice
set -euo pipefail

alias_name=${1:?usage: usage-report.sh <alias>}
gateway_url=${SEALEDIN_GATEWAY_URL:?set SEALEDIN_GATEWAY_URL to the public https URL of the gateway}
# The operator token is sent as a Bearer header to this URL; refuse plaintext transports outright.
[[ "$gateway_url" == https://* ]] || { echo "SEALEDIN_GATEWAY_URL must be https://" >&2; exit 1; }
# Key issuance rides only the end-to-end TLS site: the platform-terminated -8080. name would expose the bearer.
[[ "$gateway_url" != *-8080.* ]] || { echo "SEALEDIN_GATEWAY_URL must be the custom edge domain, not the -8080. platform name" >&2; exit 1; }
# The bearer goes only to the server key /v1/tls endorsed in a passing verify-gateway.sh run (it prints the export line):
# WebPKI alone cannot rule out a certificate issued to someone else for the name.
spki_b64=${SEALEDIN_EDGE_SPKI_B64:?run verify-gateway.sh and export the endorsed SPKI it prints}
[[ "$alias_name" =~ ^[a-z0-9-]{1,64}$ ]] || { echo "alias must match ^[a-z0-9-]{1,64}$" >&2; exit 1; }

operator_key=$(security find-generic-password -w -s sealedin-operator 2>/dev/null || true)
[ -n "$operator_key" ] || { echo "no operator token: add Keychain item sealedin-operator" >&2; exit 1; }

# Auth header arrives via stdin (-H @-), keeping the token out of the process argv other local users can read.
printf 'Authorization: Bearer %s\n' "$operator_key" \
  | curl -s --fail-with-body --pinnedpubkey "sha256//$spki_b64" --connect-timeout 5 --max-time 15 -H @- "$gateway_url/v1/keys/$alias_name" \
  | jq -r '"\(.alias)\tspend_usd=\(.spend_usd)\tmax_budget_usd=\(.max_budget_usd)"'
