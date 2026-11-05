#!/usr/bin/env bash
# Issue a virtual key for a team member through the identity's key issuance (/v1/keys behind the edge). The bearer is
# the operator token from the macOS Keychain item `sealedin-operator`; no master key ever leaves the CVM. The key is
# scoped by the identity to the measured model catalog; budget is prepaid USD and never resets.
#
# Usage: issue-key.sh <alias> [max_budget_usd] [rpm_limit]
# Example: issue-key.sh alice 20 60
set -euo pipefail

alias_name=${1:?usage: issue-key.sh <alias> [max_budget_usd] [rpm_limit]}
max_budget=${2:-20}
rpm_limit=${3:-60}
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
# --max-time 15 sits above the identity's 10 s write timeout, which sits above its 8 s gateway call.
printf 'Authorization: Bearer %s\n' "$operator_key" \
  | curl -s --fail-with-body --pinnedpubkey "sha256//$spki_b64" --connect-timeout 5 --max-time 15 -H @- -H "Content-Type: application/json" \
      -d "$(jq -n --arg a "$alias_name" --argjson b "$max_budget" --argjson r "$rpm_limit" \
        '{alias: $a, max_budget_usd: $b, rpm_limit: $r}')" \
      "$gateway_url/v1/keys"
echo
