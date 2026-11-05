---
purpose: The custom domain the edge serves (api.sealedin.ai): the DNS records, the order of operations, how to check, the limits and what stays trusted
---

# Custom domain

The platform gateway publishes every CVM as `https://<app-id>-<port>.<cluster>.phala.network`. A port with the suffix `s` (`-443s`) is passed through by SNI to the app's port 443, but the CAA record on the platform's zone admits only Let's Encrypt DNS-01 under the platform's own ACME account, so our edge (Caddy, inside the TD) can never obtain a certificate for such a name, and `/v1/tls` has nothing to endorse there. The edge therefore serves our own domain, `api.sealedin.ai`, which the platform gateway also routes by SNI as TLS passthrough once the domain's DNS names the app. The certificate is then issued to the edge inside the TD through the TLS-ALPN-01 challenge over that passthrough (HTTP-01 is disabled in `edge/Caddyfile`: port 80 does not pass through the platform gateway), and `/v1/tls` endorses it. The sealed env's `SEALEDIN_EDGE_DOMAIN` carries the name; the compose and its measurement are the same for every deployment.

## DNS records

| Record | Name | Value |
|--------|------|-------|
| A | `api.sealedin.ai` | each address of `gateway.<cluster>.phala.network` today, TTL 300 |
| TXT | `_dstack-app-address.api.sealedin.ai` | `"<app-id>:443"` |
| CAA (required) | `api.sealedin.ai` | `0 issue "letsencrypt.org; validationmethods=tls-alpn-01; accounturi=<our ACME account URI>"` |

For a CVM published at `<app-id>-8080.dstack-pha-prod9.phala.network` the gateway name is `gateway.dstack-pha-prod9.phala.network`. `scripts/deploy-phala.sh` prints it and its addresses from the CVM's gateway base domain; confirm it against the CVM's platform page at deploy time. The platform gateway routes on the TLS SNI and this TXT record alone, whichever way the client's DNS reached it, so the address record carries no routing. The CAA record pins issuance to Let's Encrypt, to the TLS-ALPN-01 method and to our ACME account, and it is required: the platform gateway sees every ClientHello for the name and could pass the TLS-ALPN-01 challenge itself under its own ACME account, so without the `accounturi` pin a WebPKI-valid certificate for `api.sealedin.ai` does not prove the TD. The endorsement in `/v1/tls` is what a verifying client trusts; the CAA record is what makes WebPKI alone, as non-verifying clients and the operator scripts' pinning bootstrap see it, mean the same thing.

**Why not a CNAME.** The platform's guide uses one, and it cannot carry the pin. A CNAME admits no other data at its name (RFC 1034 section 3.6.2), so a compliant DNS host refuses the CAA beside it. A pin higher up does not help either: a CAA query at the name follows the alias to the target (RFC 8659 section 3), and only an empty answer climbs on to the parent of the name, so the platform could publish a CAA at its gateway name admitting its own account and overrule ours, and that is the party the pin exists to stop. A host that serves the two side by side anyway leaves the answer to a resolver's cache, which may answer from the CNAME alone. Apart from that, a pin at the apex would refuse the site's own certificate. `scripts/check-domain-dns.sh` fails on a CNAME here.

**The apex is free.** A CAA search stops at the first name with a record, so this one governs `api.sealedin.ai` only, and the site on the apex keeps its own certificate from its own ACME account.

## Order of operations

The pin goes up before any address, or the platform gateway could pass the challenge in the window between them, under its own account.

1. Create the CVM with the domain already in the sealed env: `SEALEDIN_EDGE_DOMAIN=api.sealedin.ai scripts/deploy-phala.sh create sealedin-gateway-01`. The stack starts, and the edge registers its ACME account and begins attempts that fail until DNS exists; that is expected.
2. Read the ACME account URI (`https://acme-v02.api.letsencrypt.org/acme/acct/<id>`) from the `location` field of the account file Caddy stores in the `caddyacme` volume (`acme-v02.api.letsencrypt.org-directory/users/`) or from the edge's log, and create the CAA record with it. Check it against the edge's own output: nothing attests this value yet, so a platform relaying the log could substitute its own account.
3. Read the app id, the gateway domain and its addresses the script prints (or the CVM's platform page) and create the A and the TXT records above.
4. Wait for the edge's next ACME attempt (Caddy retries with backoff) or restart the CVM for an immediate one. The certificate is held in the edge's tmpfs; the ACME account key is in the `caddyacme` volume and persists.
5. Run `SEALEDIN_EXPECTED_APP_ID=<app-id> SEALEDIN_EXPECTED_GATEWAY=<gateway-domain> SEALEDIN_EXPECTED_ACME_ACCOUNT=<uri> SEALEDIN_EXPECTED_COMPOSE_HASH=<hash> SEALEDIN_EXPECTED_MRS=<file> scripts/verify-gateway.sh api.sealedin.ai` and export the `SEALEDIN_EDGE_SPKI_B64` line it prints; `scripts/issue-key.sh` and `scripts/usage-report.sh` send the operator bearer only to that pinned server key. No key is issued before this passes. Then look up the name in a Certificate Transparency log: any certificate whose key `/v1/tls` never endorsed means the pin did not hold.

## How to check

```bash
dig +short CNAME api.sealedin.ai                        # empty
dig +short A api.sealedin.ai                            # among: dig +short A gateway.<cluster>.phala.network
dig +short TXT _dstack-app-address.api.sealedin.ai      # "<app-id>:443"
dig +short CAA api.sealedin.ai
openssl s_client -servername api.sealedin.ai -connect api.sealedin.ai:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -dates                  # a Let's Encrypt issuer, dates inside the last reissue
SEALEDIN_EXPECTED_APP_ID=<app-id> SEALEDIN_EXPECTED_GATEWAY=<gateway-domain> SEALEDIN_EXPECTED_ACME_ACCOUNT=<uri> \
SEALEDIN_EXPECTED_COMPOSE_HASH=<hash> SEALEDIN_EXPECTED_MRS=attestation/<image>-<shape>.json \
  scripts/verify-gateway.sh api.sealedin.ai             # checks the TXT, A and CAA records, then the quote
```

`scripts/verify-gateway.sh api.sealedin.ai` must pass every step: the TXT record names the expected app id (never taken from DNS), the name is no CNAME, its addresses are among the expected gateway's, every `issue` value in the CAA set is exactly our pin and no `issuewild` admits anything, since CAA values add up and one more would be a second way in, the handshake verifies as WebPKI for the name with a Let's Encrypt issuer, and the SPKI `/v1/tls` endorses equals the one served on `:443`. The platform passthrough name `<app-id>-443s.<gateway-domain>` still passes the script's earlier steps for a CVM without DNS, but its `/v1/tls` step cannot pass (no certificate of ours exists there).

## Limits

- The address is a copy. The platform promises nothing about it that we could find, and a gateway that moves takes the endpoint down until the A record is changed by hand, as nothing in the TD holds a DNS credential. That costs availability only: the old address cannot get a certificate for the name past the CAA pin, so clients see a failed handshake. Run `scripts/check-domain-dns.sh` on a schedule; it fails on a stale address.
- The edge keeps its TLS keys on tmpfs, so every CVM restart reissues the certificate. Let's Encrypt allows 5 duplicate certificates per week per name set, so at most about 5 restarts a week; a sixth restart in the window leaves the edge without a certificate until the window moves. The ACME account key persists in the `caddyacme` volume, so no account is re-registered on restart.
- A certificate lives about 90 days and Caddy renews at about day 60; `/v1/tls` is cached for 60 s in the identity, so a client that sees a mismatch right after a reissue re-fetches it a minute later.
- Only one domain is served; a second name means a second site in `edge/Caddyfile` and a new image digest.

## What stays trusted

- The registrar and the DNS zone: whoever controls them can point the name at another host, change the CAA record and obtain a certificate there, and a non-verifying client sees valid WebPKI TLS. A verifying client is not fooled: it ties the served SPKI to the quote-bound key through `/v1/tls`, and the quote to the measured compose. The CAA record narrows what the zone's controller can do but is itself a zone record.
- The platform gateway: it routes by SNI and sees only ciphertext of the end-to-end TLS session. It sees every ClientHello for the name, so it could pass a TLS-ALPN-01 challenge itself and then terminate `api.sealedin.ai`; only the CAA record with our `accounturi` rules that out, and a verifying client catches it anyway through `/v1/tls`. It terminates the `-8080` platform name itself, which is why that listener serves only the self-authenticating routes (`/v1/quote`, `/v1/tls`, `/v1/catalog`, `/health/liveliness`): inference, a key's own info and key issuance are served only on the custom domain.
- Let's Encrypt: it issues on a passed TLS-ALPN-01 challenge; a mis-issued certificate elsewhere would fail the SPKI check in `/v1/tls` for verifying clients.
