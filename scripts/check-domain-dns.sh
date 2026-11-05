#!/usr/bin/env bash
# Check the custom domain's DNS records (docs/domain.md): TXT names the app, no CNAME, addresses are the gateway's, CAA pins us.
# Every expected value comes from the operator; DNS is only checked against it.
set -euo pipefail

domain=${1:?usage: check-domain-dns.sh <domain>}
app_id=${SEALEDIN_EXPECTED_APP_ID:?set SEALEDIN_EXPECTED_APP_ID to the app id deploy-phala.sh printed}
gateway=${SEALEDIN_EXPECTED_GATEWAY:?set SEALEDIN_EXPECTED_GATEWAY to the gateway domain deploy-phala.sh printed}
account=${SEALEDIN_EXPECTED_ACME_ACCOUNT:?set SEALEDIN_EXPECTED_ACME_ACCOUNT to the edge ACME account URI (docs/domain.md)}
command -v dig >/dev/null || { echo "dig is required to check the custom domain's records" >&2; exit 1; }

clean() { LC_ALL=C tr -d '\000-\010\013-\037\177-\237'; }
fail() { echo "FAIL: $*" >&2; exit 1; }
# dig +short reads the same for SERVFAIL and for no such record, and here no record is what passes the CNAME check.
lookup() {
  local status
  status=$(dig +noall +comments "$1" "$2" | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
  case "$status" in NOERROR | NXDOMAIN) ;; *) fail "lookup of $1 $2 answered '$status'" ;; esac
  dig +short "$1" "$2" | clean
}

txt=$(lookup TXT "_dstack-app-address.$domain" | tr -d '"')
[ "$txt" = "$app_id:443" ] || fail "TXT _dstack-app-address.$domain is '$txt', expected '$app_id:443'"

# A CAA query follows a CNAME (RFC 8659 section 3), so a CNAME would hand the answer to the target's zone: the platform's.
cname=$(lookup CNAME "$domain")
[ -z "$cname" ] || fail "$domain is a CNAME to '$cname'; it must carry A records (docs/domain.md)"

# Membership, not equality: a platform that adds an address has not broken us. A stale address is an outage, so it fails here.
addresses=$(lookup A "$domain")
[ -n "$addresses" ] || fail "$domain has no A record"
for rtype in A AAAA; do
  served=$(lookup "$rtype" "gateway.$gateway")
  listed=$(lookup "$rtype" "$domain")
  for address in $listed; do
    grep -qxF "$address" <<<"$served" || fail "$domain $rtype $address is not an address of gateway.$gateway ('$served')"
  done
done
echo "OK: $domain points at gateway.$gateway: $addresses"

# CAA records add up, so one more issue record is a second way in: every one must be ours, and wildcards stay refused.
want="letsencrypt.org;validationmethods=tls-alpn-01;accounturi=$account"
caa=$(lookup CAA "$domain")
pins=0
while read -r _ tag value; do
  value=$(tr -d '" ' <<<"$value")
  tag=$(tr '[:upper:]' '[:lower:]' <<<"$tag") # RFC 8659 tags ignore case
  case "$tag" in
    issue)
      [ "$value" = "$want" ] || fail "CAA $domain admits '$value', expected only '$want'"
      pins=$((pins + 1))
      ;;
    issuewild)
      [ "$value" = ";" ] || fail "CAA $domain admits wildcards: '$value'"
      ;;
  esac
done <<<"$caa"
[ "$pins" -gt 0 ] || fail "CAA $domain must pin letsencrypt.org, tls-alpn-01 and our account (docs/domain.md); got '$caa'"
echo "OK: CAA pins issuance to our ACME account: $account"
