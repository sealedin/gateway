#!/usr/bin/env bash
# Verify the gateway's enclave identity end to end on a dstack host (Phala Cloud): fetch quote, pubkey and boot event log
# from the bootstrap, check report_data[32:64] equals the pubkey (v2 layout: block id in [0:32], key in [32:64]),
# fetch a second quote with a known block_id and check the identity binds it into report_data[0:32], check the quote is
# Intel-signed with an OK TCB (the platform's DCAP verifier today; any DCAP verifier works), then tie the quote to
# this workload: recompute every RTMR3 event digest from its fields, fold the digests and require the quote's RTMR3,
# require the authenticated compose-hash event to equal the expected release hash, and pin the guest OS registers
# (MRTD, RTMR0-2) to the expected dstack image for this VM shape. A debug TD is rejected.
#
# Then check the TLS binding (/v1/tls): the endorsed SPKI must match the cert the public edge presents, catching a
# MITM with a merely CA-valid cert; on the custom domain the chain must be Let's Encrypt's (never Caddy's internal CA).
#
# Usage: verify-gateway.sh <domain> [fixture-dir]
# <domain> is the custom edge domain (docs/domain.md: its TXT record names the app id, its A record the cluster gateway)
# or the platform passthrough name <app-id>-443s.<gateway-domain>.
# Environment (required): SEALEDIN_EXPECTED_COMPOSE_HASH, the compose-hash of the release (deploy-phala.sh prints it);
# SEALEDIN_EXPECTED_MRS, a JSON file with the expected mrtd, rtmr0, rtmr1, rtmr2 of the pinned dstack image and VM
# shape (see attestation/README.md); for a custom domain also SEALEDIN_EXPECTED_APP_ID and SEALEDIN_EXPECTED_GATEWAY, which
# deploy-phala.sh printed, and SEALEDIN_EXPECTED_ACME_ACCOUNT (DNS never supplies an expected value, it is only checked
# against it). fixture-dir saves the verified
# artifacts as one bundle; SEALEDIN_VM_ID sets meta.json's vm_id. A passing run ends with the export line the
# operator scripts need (SEALEDIN_EDGE_SPKI_B64, the endorsed server key they pin).
set -euo pipefail

domain=${1:?usage: verify-gateway.sh <domain> [fixture-dir]}
fixture_dir=${2:-}
expected_compose_hash=${SEALEDIN_EXPECTED_COMPOSE_HASH:?set SEALEDIN_EXPECTED_COMPOSE_HASH to the release compose-hash}
expected_mrs=${SEALEDIN_EXPECTED_MRS:?set SEALEDIN_EXPECTED_MRS to the pinned guest OS measurements file}
compose_file=docker-compose.phala.yml
# Quote offsets (TDX v4, 48-byte header then the TD10 body): td_attributes 168, mrtd 184, rtmr0 376, rtmr3 520,
# report_data 568.
tdattr_offset=168
mrtd_offset=184
rtmr0_offset=376
rtmr3_offset=520
rd_offset=568
pk_offset=$((rd_offset + 32))
# dstack runtime events carry this type; v1 digests are sha384(type_le32 || ":" || event || ":" || payload).
dstack_event_type_le=01000008

# Gateway- and DNS-controlled strings are printed only through this filter: no C0 or C1 control bytes reach the terminal.
clean() { LC_ALL=C tr -d '\000-\010\013-\037\177-\237'; }
# The app id and the cluster gateway come from the name itself (platform form) or from the operator (custom form);
# DNS is trusted only to find the CVM, the quote and the app-id event prove what answers.
case "$domain" in
  *-443s.*)
    app_id=${domain%%-443s.*}; gateway=${domain#*-443s.}; custom=false
    # The bootstrap rides the edge's plain listener (8080) through the platform gateway's TLS: the identity publishes no port.
    bootstrap="https://$app_id-8080.$gateway"
    ;;
  *)
    custom=true
    app_id=${SEALEDIN_EXPECTED_APP_ID:?set SEALEDIN_EXPECTED_APP_ID to the app id deploy-phala.sh printed}
    gateway=${SEALEDIN_EXPECTED_GATEWAY:?set SEALEDIN_EXPECTED_GATEWAY to the gateway domain deploy-phala.sh printed}
    "$(dirname "$0")/check-domain-dns.sh" "$domain"
    bootstrap="https://$domain"
    ;;
esac
if ! [[ $app_id =~ ^[0-9a-f]{40}$ && $gateway =~ ^[a-z0-9.-]+$ ]]; then
  echo "unexpected app id or gateway domain for $domain: $app_id $gateway" >&2; exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
field() { cut -c $(($1 * 2 + 1))-$((($1 + $2) * 2)) "$tmp/quote.hex"; }

curl -sf --max-time 15 "$bootstrap/v1/quote" > "$tmp/quote.json"
pubkey=$(jq -r .pubkey "$tmp/quote.json" | clean)
[[ $pubkey =~ ^[0-9a-f]{64}$ ]] || { echo "FAIL: pubkey is not 32 hex bytes" >&2; exit 1; }
jq -r .quote "$tmp/quote.json" | base64 -d | xxd -p -c 256 | tr -d '\n' > "$tmp/quote.hex"
[ "$(wc -c < "$tmp/quote.hex")" -ge $(((rd_offset + 64) * 2)) ] || { echo "FAIL: quote too short" >&2; exit 1; }

if [ "$(field "$pk_offset" 32)" != "$pubkey" ]; then
  echo "FAIL: report_data[32:64] $(field "$pk_offset" 32) does not match pubkey $pubkey" >&2
  exit 1
fi
echo "OK: report_data binds pubkey $pubkey"

# Fresh-quote path: the identity must bind the requested block_id into report_data[0:32], not silently ignore it.
probe_id=$(printf 'a1%.0s' $(seq 1 32))
curl -sf --max-time 30 "$bootstrap/v1/quote?block_id=$probe_id" > "$tmp/fresh.json"
if [ "$(jq -r .block_id "$tmp/fresh.json")" != "$probe_id" ]; then
  echo "FAIL: identity did not echo block_id $probe_id" >&2
  exit 1
fi
fresh_hex=$(jq -r .quote "$tmp/fresh.json" | base64 -d | xxd -p -c 256 | tr -d '\n')
fresh_bid=$(printf '%s' "$fresh_hex" | cut -c $((rd_offset * 2 + 1))-$(((rd_offset + 32) * 2)))
fresh_key=$(printf '%s' "$fresh_hex" | cut -c $((pk_offset * 2 + 1))-$(((pk_offset + 32) * 2)))
if [ "$fresh_bid" != "$probe_id" ] || [ "$fresh_key" != "$pubkey" ]; then
  echo "FAIL: fresh quote report_data is $fresh_bid ++ $fresh_key, want $probe_id ++ $pubkey" >&2
  exit 1
fi
echo "OK: fresh quote binds requested block_id and pubkey"

# The private listener must never be published. The gateway answers every port name itself, so only an answer
# that is identity's (a JSON body) counts as a leak.
if curl -s --max-time 5 "https://$app_id-8473.$gateway/v1/catalog" 2>/dev/null | jq -e . >/dev/null 2>&1; then
  echo "FAIL: $app_id-8473.$gateway serves the private listener; it must stay behind the edge" >&2
  exit 1
fi
# The rpcproxy forwards to external hosts, the sales service holds the fee payer, the drain sees every prompt: none may answer from outside.
for port_path in 8475/primary 8476/v1/keys/buy 8477/v1/models; do
  if curl -s --max-time 5 -X POST -d '{}' "https://$app_id-${port_path%%/*}.$gateway/${port_path#*/}" 2>/dev/null | jq -e . >/dev/null 2>&1; then
    echo "FAIL: $app_id-${port_path%%/*}.$gateway answers; it must stay behind the edge" >&2
    exit 1
  fi
done
echo "OK: private listener, rpcproxy, sales service and drain are not publicly reachable"

# DCAP: signature chain and TCB through the platform's verifier (an independent local DCAP check is the follow-up).
verdict=$(jq -n --rawfile h "$tmp/quote.hex" '{hex: ($h | rtrimstr("\n"))}' \
  | curl -sf --max-time 60 -X POST https://cloud-api.phala.com/api/v1/attestations/verify \
      -H 'Content-Type: application/json' -d @-) || { echo "FAIL: DCAP verifier unreachable" >&2; exit 1; }
if [ "$(jq -r '.quote.verified' <<<"$verdict")" != "true" ]; then
  echo "FAIL: quote did not verify: $(jq -c '{verified: .quote.verified, error}' <<<"$verdict" | clean)" >&2; exit 1
fi
echo "OK: DCAP verified"

# Guest OS pin: a debug TD or a different dstack image could extend RTMR3 with any digest, so the registers the
# image determines must match the expected ones before the event log means anything.
tdattr=$(field "$tdattr_offset" 8)
if [ "$((16#${tdattr:0:2} & 1))" -ne 0 ]; then
  echo "FAIL: TD attributes $tdattr have the DEBUG bit set" >&2; exit 1
fi
mr_td=$(field "$mrtd_offset" 48)
for reg in mrtd rtmr0 rtmr1 rtmr2; do
  case "$reg" in
    mrtd) got=$mr_td ;;
    rtmr0) got=$(field "$rtmr0_offset" 48) ;;
    rtmr1) got=$(field $((rtmr0_offset + 48)) 48) ;;
    rtmr2) got=$(field $((rtmr0_offset + 96)) 48) ;;
  esac
  want=$(jq -r --arg r "$reg" '.[$r]' "$expected_mrs")
  if [ "$got" != "$want" ]; then
    echo "FAIL: $reg is $got, expected $want (guest OS image or VM shape differs from the pin)" >&2; exit 1
  fi
done
echo "OK: MRTD and RTMR0-2 match the pinned guest OS image"

# RTMR3: recompute each runtime event's digest from its fields (so a payload cannot be rewritten under a genuine
# digest), fold the digests from 48 zero bytes with sha384(rtmr || digest), and require the quote's register.
if [ "$(jq -r 'has("event_log")' "$tmp/quote.json")" != "true" ]; then
  echo "FAIL: identity serves no event log" >&2; exit 1
fi
quoted_rtmr3=$(field "$rtmr3_offset" 48)
fold=$(printf '%096d' 0)
count=0
while IFS=$'\t' read -r digest event payload; do
  [[ $digest == - || $digest =~ ^[0-9a-f]{96}$ ]] || { echo "FAIL: event digest is not sha384 hex" >&2; exit 1; }
  v1=$( { printf '%s' "$dstack_event_type_le" | xxd -r -p; printf ':%s:' "$event"
          printf '%s' "$payload" | xxd -r -p; } | openssl dgst -sha384 | sed 's/^.*= //')
  v2=$(printf '{"name":"%s","payload":"%s","type":134217729}' "$event" "$payload" \
    | openssl dgst -sha384 | sed 's/^.*= //')
  # dstack-dev images serve no digest; the v1 one recomputed from the fields must then fold into the register.
  [ "$digest" = - ] && digest=$v1
  if [ "$digest" != "$v1" ] && [ "$digest" != "$v2" ]; then
    echo "FAIL: event '$(printf '%s' "$event" | clean)' digest does not match its fields" >&2; exit 1
  fi
  fold=$(printf '%s%s' "$fold" "$digest" | xxd -r -p | openssl dgst -sha384 | sed 's/^.*= //')
  count=$((count + 1))
done < <(jq -r '.event_log[] | select(.imr == 3)
  | [(.digest // "" | if . == "" then "-" else . end), .event, .event_payload] | @tsv' "$tmp/quote.json")
if [ "$count" -eq 0 ] || [ "$fold" != "$quoted_rtmr3" ]; then
  echo "FAIL: $count RTMR3 events replay to $fold, quote carries RTMR3 $quoted_rtmr3" >&2
  exit 1
fi
echo "OK: $count authenticated RTMR3 events replay to the quote's register"
compose_hash=$(jq -r '[.event_log[] | select(.imr == 3 and .event == "compose-hash") | .event_payload]
  | if length == 1 then .[0] else error("expected exactly one compose-hash event") end' "$tmp/quote.json")
if [ "$compose_hash" != "$expected_compose_hash" ]; then
  echo "FAIL: compose-hash $compose_hash is not the expected $expected_compose_hash" >&2
  exit 1
fi
echo "OK: compose-hash $compose_hash is the expected release"
app_id_event=$(jq -r '.event_log[] | select(.imr == 3 and .event == "app-id") | .event_payload' "$tmp/quote.json" \
  | clean)
if [ "$app_id_event" != "$app_id" ]; then
  echo "FAIL: app-id event $app_id_event is not the domain's app id $app_id" >&2
  exit 1
fi
echo "OK: app-id event matches the domain"
jq -r '.event_log[] | select(.imr == 3) | "  \(.event): \(.event_payload)"' "$tmp/quote.json" | clean

# Ed25519 verify needs OpenSSL 3 (LibreSSL lacks pkeyutl -rawin); fail closed, the signature is the only binding to
# the attested key.
ossl="openssl"
for candidate in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
  [ -x "$candidate" ] && ossl="$candidate" && break
done
if ! "$ossl" pkeyutl -help 2>&1 | grep -q rawin; then
  echo "FAIL: no Ed25519-capable openssl found (need OpenSSL 3: brew install openssl@3);" \
       "refusing to skip the signature check" >&2
  exit 1
fi

if ! curl -sf --max-time 15 "$bootstrap/v1/tls" > "$tmp/tls.json"; then
  echo "FAIL: identity does not serve /v1/tls (endorsement not deployed?)" >&2
  exit 1
fi
spki=$(jq -r .spki_sha256 "$tmp/tls.json" | clean)
not_after=$(jq -r .not_after "$tmp/tls.json" | clean)
[[ $spki =~ ^[0-9a-f]{64}$ && $not_after =~ ^[0-9]+$ ]] || { echo "FAIL: malformed /v1/tls" >&2; exit 1; }
if [ "$(jq -r .pubkey "$tmp/tls.json")" != "$pubkey" ]; then
  echo "FAIL: /v1/tls pubkey differs from /v1/quote" >&2; exit 1
fi

# The handshake must verify as WebPKI for the name (chain and hostname), not merely present a leaf; openssl re-encodes
# the pubkey, identical to the raw SPKI hash for canonical ACME/Caddy DER.
"$ossl" s_client -connect "$domain:443" -servername "$domain" -verify_hostname "$domain" -verify_return_error \
  </dev/null 2>/dev/null | "$ossl" x509 > "$tmp/live.pem" || true
live_spki=$("$ossl" x509 -in "$tmp/live.pem" -pubkey -noout 2>/dev/null | "$ossl" pkey -pubin -outform DER 2>/dev/null \
  | shasum -a 256 | cut -d' ' -f1 || true)
if ! [ -s "$tmp/live.pem" ] || [ -z "$live_spki" ]; then
  echo "FAIL: no verified certificate chain for $domain:443 (network, DNS, or not a WebPKI-valid chain for the name)" >&2
  exit 1
fi
# On our domain the issuer must be the CA the CAA record pins; Caddy's internal CA or any other issuer means issuance
# did not happen inside the TD as documented. The organizationName is parsed, not substring-matched.
if [ "$custom" = true ]; then
  issuer_org=$("$ossl" x509 -in "$tmp/live.pem" -noout -issuer -nameopt multiline | sed -n 's/^ *organizationName *= *//p' | clean)
  if [ "$issuer_org" != "Let's Encrypt" ]; then
    echo "FAIL: $domain certificate issuer organizationName is '$issuer_org', not Let's Encrypt" >&2; exit 1
  fi
  echo "OK: $domain certificate issued by Let's Encrypt"
fi
if [ "$live_spki" != "$spki" ]; then
  echo "FAIL: endorsed SPKI $spki does not match live :443 cert SPKI $live_spki (possible MITM;" \
       "if the cert rotated within the identity's 60s endorsement cache, re-running in a minute clears it)" >&2
  exit 1
fi
if [ "$not_after" -le "$(date +%s)" ]; then
  echo "FAIL: endorsement covers an expired certificate (not_after $not_after)" >&2
  exit 1
fi
echo "OK: endorsed SPKI matches the live :443 certificate"

{
  printf 'sealedin-tls-endorsement-v1'
  printf '\0'
  printf '%s' "$spki" | xxd -r -p
  printf '%016x' "$not_after" | xxd -r -p
} > "$tmp/msg.bin"
jq -r .signature "$tmp/tls.json" | xxd -r -p > "$tmp/sig.bin"
printf '302a300506032b6570032100%s' "$pubkey" | xxd -r -p > "$tmp/pub.der"
if "$ossl" pkeyutl -verify -pubin -inkey "$tmp/pub.der" -keyform DER -rawin \
     -in "$tmp/msg.bin" -sigfile "$tmp/sig.bin" >/dev/null 2>&1; then
  echo "OK: endorsement signature verifies against the attested pubkey"
else
  echo "FAIL: endorsement signature INVALID" >&2
  exit 1
fi

# The signed catalog: the price sheet a client is metered at, under the same attested key. The preimage is the tag,
# a NUL and the reply without its signature as canonical JSON (keys sorted, no whitespace), which jq -cjS rebuilds.
curl -sf --max-time 15 "$bootstrap/v1/catalog" > "$tmp/catalog.json" || { echo "FAIL: no /v1/catalog" >&2; exit 1; }
if [ "$(jq -r .pubkey "$tmp/catalog.json")" != "$pubkey" ]; then
  echo "FAIL: /v1/catalog pubkey differs from /v1/quote" >&2; exit 1
fi
{ printf 'sealedin-catalog-v1'; printf '\0'; jq -cjS 'del(.signature)' "$tmp/catalog.json"; } > "$tmp/catalog.msg"
jq -r .signature "$tmp/catalog.json" | xxd -r -p > "$tmp/catalog.sig"
if ! "$ossl" pkeyutl -verify -pubin -inkey "$tmp/pub.der" -keyform DER -rawin \
     -in "$tmp/catalog.msg" -sigfile "$tmp/catalog.sig" >/dev/null 2>&1; then
  echo "FAIL: catalog signature INVALID" >&2
  exit 1
fi
echo "OK: catalog signature verifies: $(jq -r '"\(.models | length) models, \(.markup_percent)% over the list of \(.list_as_of)"' \
  "$tmp/catalog.json" | clean)"
jq -r '.models[] | "  \(.id): \(.input_usd_per_mtok) / \(.output_usd_per_mtok) USD per 1M tokens"' "$tmp/catalog.json" | clean
# Purchases pay these signed terms; a client compares the 402 challenge with them (docs/x402.md).
jq -r '"  purchases pay \(.asset) to \(.pay_to) on \(.networks | join(",")), fees by \(.fee_payer // "nobody: purchases are off")"' \
  "$tmp/catalog.json" | clean
if jq -e '.pay_to | startswith("TREASURY-PLACEHOLDER")' "$tmp/catalog.json" >/dev/null; then
  echo "FAIL: the catalog names the placeholder treasury" >&2; exit 1
fi
if [ -n "$fixture_dir" ]; then
  repo_root=$(cd "$(dirname "$0")/.." && pwd)
  mkdir -p "$fixture_dir"
  cp "$tmp/quote.json" "$tmp/tls.json" "$fixture_dir/"
  printf '%s\n' "$(cat "$tmp/quote.hex")" > "$fixture_dir/quote.hex"
  printf '%s\n' "$verdict" > "$fixture_dir/verdict.json"
  jq -n --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg vm_id "${SEALEDIN_VM_ID:-}" --arg domain "$domain" \
    --arg commit "$(git -C "$repo_root" log -1 --format=%H -- "$compose_file")" \
    --arg pubkey "$pubkey" --arg mr_td "$mr_td" --arg rtmr3 "$quoted_rtmr3" --arg compose_hash "$compose_hash" \
    --arg compose_sha "$(shasum -a 256 "$repo_root/$compose_file" | cut -d' ' -f1)" \
    '{captured_at:$ts, vm_id:$vm_id, domain:$domain, platform:"phala", compose_commit:$commit, pubkey:$pubkey,
      mr_td:$mr_td, rtmr3:$rtmr3, compose_hash:$compose_hash, compose_sha256:$compose_sha, report_data_layout:"v2"}' \
    > "$fixture_dir/meta.json"
  echo "Fixture bundle saved to $fixture_dir"
fi
echo "The compose-hash pins the upstream policy too: the gateway config (baked into the measured gateway image)"
echo "routes only internal/gateway.ConfidentialModels() through the egress, whose measured policy (egress/policy.yaml)"
echo "pins the Chutes hosts and the TEE measurements it accepts. The API keys in the sealed env are the operator's only knobs."
# The operator scripts send a bearer only to the key this run endorsed (curl --pinnedpubkey takes base64 of the hash).
echo "Pin the endorsed server key before issue-key.sh or usage-report.sh:"
echo "  export SEALEDIN_EDGE_SPKI_B64=$(printf '%s' "$spki" | xxd -r -p | base64)"
