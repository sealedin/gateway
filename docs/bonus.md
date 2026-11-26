---
purpose: The follower bonus: a one-time key for X accounts that follow ours, how the check works, what it costs, what limits it and how to run it
---

# The follower bonus

`cmd/bonus` gives a key with a small budget, once, to an X account that follows `@sealedinai`. It is the operator's tool and runs **outside the enclave**: it holds the operator token and asks the gateway for a key through `POST /v1/keys`, the route a hand-issued key takes. No measured image, route or compose line knows of it, so turning the promotion on or off changes no measurement.

**What that means for trust.** Whoever runs this service sees each bonus key as it is issued, and so could read that key's traffic by using it. A bought key is derived inside the enclave and no operator sees it. The page that offers the bonus must say so.

## Flow

1. `GET /x/start` puts a random state and a PKCE verifier in a ten-minute cookie and redirects to X (OAuth 2.0, scopes `users.read tweet.read follows.read`).
2. X returns the browser to `GET /x/callback`. The state must match the cookie, which ties the callback to the browser that started.
3. The service exchanges the code, reads `GET /2/users/me` (id, creation date) and `GET /2/users/by/username/<account>?user.fields=connection_status` with the user's token. `following` in `connection_status` is the follow. The token is used for these two calls and dropped.
4. The alias is `bonus-x-` and 128 bits of a SHA-256 over the X account id. If the gateway knows the alias, the bonus was taken. Otherwise the gateway issues the key and the alias goes into the ledger file.
5. Every outcome ends in a redirect to the site's `/bonus` page with `#result=<outcome>` and, once, `&key=<key>`. A fragment reaches no server and no log; the page takes it out of the address before its analytics load and shows the key, once. Outcomes: `issued`, `not_following`, `too_new`, `taken`, `over`, `expired`, `cancelled`, `busy`, `unavailable`.

Nothing is stored per visitor. The gateway holds the alias, so one X account gets one key however often it signs in, and the gateway's records name no account, though anyone holding them can test a known account id against them.

## Limits

| Limit | Default | Flag |
|---|---|---|
| Budget of a bonus key | 10 USD | `-budget` |
| Rate of a bonus key | 20 requests a minute | `-rpm` |
| Keys before the promotion ends | 100 | `-max-keys` |
| Youngest X account served | 30 days | `-min-account-age` |
| Claims reaching X | 1 a second, burst 20 | fixed |

The worst case is `-max-keys` times `-budget`, 1,000 USD by default, spent at the upstream. The count survives a restart through the ledger file (`-ledger-file`, one alias a line). A lost ledger resets the count, not the one-per-account rule.

A follow is checked at the claim only: unfollowing afterwards keeps the key. An aged or bought X account passes, and the cap is what bounds that.

## What X charges

X's API is pay-per-use with prepaid credits and no free tier. A claim that reaches X reads two user objects, about 0.02 USD at the prices of November 2026, so 100 bonuses cost a few dollars with refused attempts included. Listing who an account follows would cost 0.01 USD for each account on the list, which is why the check asks for one object's `connection_status` instead. X served that field to our pay-per-use app on the first real sign-in, 2026-11-23.

## Running it

Needs an X developer app owned by the account being followed, with OAuth 2.0 on, the callback `https://<host>/x/callback` registered, and credits.

```
SEALEDIN_OPERATOR_API_KEY=... SEALEDIN_X_CLIENT_ID=... \
  bonus -public-url https://<host> -gateway https://api.sealedin.ai -ledger-file /var/lib/bonus/ledger
```

`SEALEDIN_X_CLIENT_SECRET` is set only for a confidential client. The service speaks plain HTTP on `-listen` and must sit behind a TLS reverse proxy; it refuses to start unless both URLs are `https`. A payment later tops a bonus key up like any other key, with the key as the bearer on `POST /v1/keys/claim`.
