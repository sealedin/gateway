---
purpose: Buying a key by a Solana Pay transfer from a wallet: the request, the claim route, how a transaction is checked, what happens to money that does not fit, abuse limits and what only a real wallet can show
---

# Buying with Solana Pay

People buy with a [Solana Pay](https://docs.solanapay.com/spec) transfer request, a QR code or a wallet link. Agents stay on [x402](x402.md). The buyer pays the network fee, and the fee payer signs nothing on this path.

## Flow

1. The page generates a random 32-byte `code` and never sends it anywhere yet. `reference` is the SHA-256 of `sealedin-pay-reference-v1`, one NUL and the code, as a base58 address.
2. It shows `solana:<pay_to>?amount=<usd>&spl-token=<asset>&reference=<reference>&label=SealedIn&message=...`, with `pay_to` and `asset` from the signed `GET /v1/catalog`.
3. The wallet pays. Only the reference is public.
4. The page polls `POST /v1/keys/claim` with `{"code": "<base58>"}` over TLS. **Whoever holds the code can take the key**, so it never goes in a log, a URL, a query string or an error here. Keep it only as long as the page must.

## The claim route

Served by `cmd/sales` on the TLS site only. `Authorization: Bearer <existing key>` makes it a top-up, with no key in the reply.

| Status | Body | The page |
|--------|------|----------|
| 200 | as a buy: `key` (absent for a top-up), `alias`, `max_budget_usd`, `rpm_limit`, `models`, `transaction` | done |
| 202 | `{"status": "pending"}`, with `Retry-After` | keeps polling; this covers nothing found yet, so no 404 is used |
| 429, 503 | `{"error": ...}`, with `Retry-After` | keeps polling |
| 502 | `{"error": ...}` | the gateway could not check a bearer: keep polling |
| 400 | `{"error": ..., "reason": "bad_code"}` | final |
| 401 | none | a bad bearer |
| 409 | `{"error": ..., "reason": ..., "transaction": ...}` | final |

The `reason` values on a 409 are `below_minimum` (the text says "below the 20 USD minimum"), `revoked`, `credited_elsewhere` and `target_gone`.

CORS is the edge's, for `POST /v1/keys/claim` and `GET /v1/catalog` only: origin `https://sealedin.ai`, methods GET and POST, headers `content-type` and `authorization`, with `Retry-After` exposed. Any other origin gets no allow header. x402 buy has no CORS.

## What counts as paid

`getSignaturesForAddress(reference)`, then `getTransaction` on the primary and a confirmed status on the second host. The transaction must have succeeded, it must be the listed id's own bytes with its signatures verifying, so one lying host cannot show other contents under a real id, and it must hold a top-level `Transfer` or `TransferChecked` into the treasury's USDC account whose accounts include the reference read-only and unsigned. The amount comes from that instruction. A plain `Transfer` names no mint, and the destination settles it, since that account holds only USDC. Other instructions are allowed, as wallets add compute budget, priority fee, memo and account creation, and neither message nor memo counts. A transfer made inside another program, or whose destination or reference comes from a lookup table, which a node reports unsigned, is not read, and stays uncredited.

## Money that does not fit

The key is derived from the enclave-only secret and the reference, so a repeated claim returns the same key and no wallet signature or recovery route is needed. Each transaction is credited once, as a top-up is: a durable blocked marker per transaction names the key, and the credit records the marker in the same update as the budget. The first marker decides the key, so a later claim for another key moves nothing and gets `credited_elsewhere`.

- **A QR scanned twice:** the second payment adds to the same key on the next claim. **A claim is what credits**, so if the page has stopped polling, the money waits in the treasury until the same code is claimed again.
- **Under 20 USD:** nothing is issued, per transaction, the reply says so and the log says `operator must reconcile` at error level. Two payments of 15 USD do not add up.
- **Over 500 USD:** what was paid is credited.
- **A lost code:** there is no other way in. The payment stays in the treasury and only the operator can reconcile it, from the chain and the buyer's word.

## Abuse

Polling is unauthenticated, and each poll that reaches the chain costs an RPC call. Claims have their own bucket, 2 a second with a burst of 20, apart from buy and recover. A reference with nothing under it is answered from memory for 3 seconds, a poll reads at most 8 transactions and resumes on the next, and readings of confirmed transactions are kept for an hour. Nothing here costs SOL or touches the fee meter.

**The worst griefing.** Random codes hold the bucket, so real buyers wait on 429 for as long as it lasts, and nothing is lost. That is about 170,000 RPC calls a day on the primary's quota, which x402 purchases share: a free tier could run out in days, stopping purchases until the provider resets or is changed. Separately, anyone who sees a reference on chain can tag 1,000 cheap transactions with it, and a payment not claimed by then falls off the list and needs the operator.

## What is checked where

Local tests run the real handlers against a fake chain and gateway. `scripts/x402-devnet-smoke.sh` drives a spec-shaped transfer from a local signer on devnet. **Only a real wallet can show** that it parses the request, derives the account, puts the reference where the spec says and pays its own fee, and that the page's QR scans.
