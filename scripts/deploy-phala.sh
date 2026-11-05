#!/usr/bin/env bash
# Deploy or update the gateway on Phala Cloud (dstack). Secrets go from the macOS Keychain
# (env-from-keychain.sh) into a mktemp file that lives only for the CLI call (never the repo's .env); the CLI encrypts
# it to the CVM's KMS key, so only the attested guest reads it. The per-deployment value (the custom edge domain,
# docs/domain.md) rides in the same sealed env, so the measured compose, and with it the compose hash in RTMR3, is
# identical for every deployment of a release. The env variable names are measured too (allowed_envs).
#
# Usage:
#   SEALEDIN_EDGE_DOMAIN=api.sealedin.ai deploy-phala.sh create <cvm-name>   # first deployment
#   SEALEDIN_EDGE_DOMAIN=api.sealedin.ai deploy-phala.sh update <cvm-id>     # roll out a compose change in place
#
# Environment: SEALEDIN_EDGE_DOMAIN (required: the custom domain the edge obtains its certificate for; the DNS records
# it needs are printed after the deploy), SEALEDIN_PHALA_INSTANCE (default tdx.medium), SEALEDIN_PHALA_IMAGE (default
# dstack-dev-0.5.12 for the beta), SEALEDIN_ROOT_SSH_PUBKEY (the operator's emergency root login: required on a dev image,
# refused on any other, and kept out of the repo), and PHALA_CLOUD_API_KEY or a prior `phala login`.
#
# Beta only: whoever holds that key reads every prompt and secret in the CVM. The quote shows the dev image through its
# guest OS measurements and the variable's name through allowed_envs, but not the key itself, since env values are not measured.
set -euo pipefail
cd "$(dirname "$0")/.."

usage="usage: SEALEDIN_EDGE_DOMAIN=<domain> deploy-phala.sh create <cvm-name> | update <cvm-id>"
mode=${1:?$usage}
target=${2:?$usage}
domain=${SEALEDIN_EDGE_DOMAIN:?$usage}
instance=${SEALEDIN_PHALA_INSTANCE:-tdx.medium}
image=${SEALEDIN_PHALA_IMAGE:-dstack-dev-0.5.12}
root_key=${SEALEDIN_ROOT_SSH_PUBKEY:-}
compose=docker-compose.phala.yml
if [[ $image == dstack-dev-* ]]; then
  if [[ -z $root_key ]]; then
    echo "$image needs SEALEDIN_ROOT_SSH_PUBKEY" >&2; exit 1
  fi
  if ! [[ $root_key =~ ^ssh-ed25519\ [A-Za-z0-9+/]+={0,2}(\ [^[:cntrl:]]*)?$ ]]; then
    echo "SEALEDIN_ROOT_SSH_PUBKEY must be one ssh-ed25519 public key" >&2; exit 1
  fi
elif [[ -n $root_key ]]; then
  echo "$image has no root access: unset SEALEDIN_ROOT_SSH_PUBKEY" >&2; exit 1
fi
# The edge requests a certificate for this name, so it must be a hostname we control; the platform's own names admit
# only the platform's ACME account (CAA), so a certificate there is impossible.
if ! [[ $domain =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
  echo "SEALEDIN_EDGE_DOMAIN must be a lowercase hostname, got '$domain'" >&2; exit 1
fi
if [[ $domain == *.phala.network ]]; then
  echo "SEALEDIN_EDGE_DOMAIN must be our own domain: the platform's names cannot carry our certificate" >&2; exit 1
fi
./scripts/check-release-pins.sh
# Placeholder digests must fail here, not half-up on the CVM.
if grep -qE '@sha256:0{64}' "$compose"; then
  echo "placeholder image digest in $compose: build and pin the image first" >&2; exit 1
fi
if grep -q 'STALE DIGEST' "$compose"; then
  echo "stale image digest in $compose: rebuild and pin the image first" >&2; exit 1
fi

envfile=$(mktemp)
trap 'rm -f "$envfile"' EXIT
./scripts/env-from-keychain.sh "$envfile"
printf 'SEALEDIN_EDGE_DOMAIN=%s\n' "$domain" >> "$envfile"
if [[ -n $root_key ]]; then
  printf 'DSTACK_ROOT_PUBLIC_KEY=%s\nDSTACK_AUTHORIZED_KEYS=%s\n' "$root_key" "$root_key" >> "$envfile"
fi

# Every CLI call is checked by its JSON `success`; on failure only known error fields are echoed, never the whole
# response, in case one ever carried request fields.
checked() {
  local out
  if ! out=$("$@" --json) || [ "$(printf '%s' "$out" | jq -r .success 2>/dev/null)" != "true" ]; then
    printf '%s\n' "$out" | jq -c '{success, error, message, detail}' 2>/dev/null >&2 || echo "phala $2 failed" >&2
    exit 1
  fi
  printf '%s' "$out"
}
# The compose-hash is the release's workload pin (verify-gateway.sh compares against it); the app id and the cluster's
# gateway domain are what the domain's DNS must name (docs/domain.md).
print_pins_and_dns() {
  local info
  info=$(checked phala cvms get "$1")
  local app_id base
  app_id=$(jq -re .app_id <<<"$info")
  base=$(jq -re .gateway.base_domain <<<"$info")
  if ! [[ $app_id =~ ^[0-9a-f]{40}$ && $base =~ ^[a-z0-9.-]+$ ]]; then
    echo "unexpected app id or gateway domain: $app_id $base" >&2; exit 1
  fi
  echo "compose-hash $(jq -r .compose_hash <<<"$info")"
  echo "app id $app_id, gateway domain $base"
  echo "DNS records for $domain (confirm the gateway domain against the CVM's platform page):"
  echo "  A     $domain -> each of: $(dig +short A "gateway.$base" | paste -sd' ' -) (the addresses of gateway.$base today, never a CNAME)"
  echo "  TXT   _dstack-app-address.$domain \"$app_id:443\""
}

case "$mode" in
  create)
    created=$(checked phala deploy -n "$target" -c "$compose" -e "$envfile" -t "$instance" --image "$image" \
      --disk-size 20G --kms phala --no-public-logs --no-public-sysinfo)
    cvm_id=$(jq -re .vm_uuid <<<"$created")
    echo "created $cvm_id for $domain"
    print_pins_and_dns "$cvm_id"
    ;;
  update)
    checked phala deploy --cvm-id "$target" -c "$compose" -e "$envfile" > /dev/null
    echo "updated $target for $domain"
    print_pins_and_dns "$target"
    ;;
  *) echo "unknown mode: $mode" >&2; exit 1 ;;
esac
