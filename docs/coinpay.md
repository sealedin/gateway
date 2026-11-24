---
purpose: Coin payments: buying a key with any coin a no-account forwarder takes, how a payment becomes a key, what is trusted, what limits it and how to run it
---

# Coin payments

`cmd/coinpay` sells a key for coins other than USDC on Solana: Bitcoin, Monero, USDT on Tron and whatever else the forwarder lists. It is the operator's tool and runs **outside the enclave**: it holds the operator token and asks the gateway for a key through `POST /v1/keys`, the route a hand-issued key takes. No measured image, route or compose line knows of it, so turning it on or off changes no measurement.

The forwarder is [PayGate.to](https://paygate.to/docs/crypto-payment-api/), which needs no merchant account or API key: it gives each order a fresh address, sends whatever arrives there on to our own address in the same coin, less its 1 percent and the network fee, and requests our callback URL with the payment in the query and an RSA signature in a header.

**What that means for trust.** Three things differ from a key bought over x402 or Solana Pay, and the page that offers this route must say so. Whoever runs this service sees each key as it is issued, and so could read that key's traffic by using it. The proof of payment is the forwarder's signed callback, not chain data read inside the enclave: a forwarder that lies, or loses its signing key, mints credit, up to `-max-usd` a callback. And the money arrives in the buyer's coin at addresses the operators hold, one per kind of chain, not on the one USDC balance.

## Flow

1. `GET /pay/coins` lists the forwarder's coins we hold a payout address for, each with the smallest payment the forwarder will forward, and the purchase range in USD.
2. `POST /pay/orders` with `{"ticker": "xmr", "usd": 20}` prices the purchase at the forwarder's rate, has the forwarder derive an address for the callback `https://<host>/pay/callback?order=<id>`, and answers `201` with `order`, `claim`, `address`, `amount`, `expires_at` and `status`. `claim` is a secret shown this once; only its hash is stored.
3. The buyer sends the coin to `address`.
4. The forwarder requests the callback once the payment confirms. The service verifies the signature over its own registered callback URL and the query exactly as it arrived (SHA-256, PKCS#1 v1.5, the key published by the forwarder and embedded here as `v1`), and checks the coin and the address against the order. It then credits `value_coin` at the order's rate, or at the rate of that moment once `-quote-ttl` has passed, rounded down to the cent and capped at `-max-usd`, and has the gateway issue a key with that budget under the alias `coin-<order>`.
5. `GET /pay/orders/<id>` with `Authorization: Bearer <claim>` shows the order: `pending`, or `paid` with `credited_usd`, `txid` and `key`.

A payment of less than was quoted buys a smaller key, and one of more buys a larger one, up to the cap.

## What it does not do

- It cannot top up a key: the operator's route issues keys and has no way to raise a budget. Each paid order is a new key.
- One order is one key. A second payment to a paid order is logged as an error with its transaction, to be credited by hand.
- A payment below the forwarder's minimum for the coin never leaves the forwarder's address and is never reported.
- A crash between the gateway issuing a key and the order being recorded loses that key. The next callback finds the alias taken and logs it, to be mended by hand.

## Limits

| Limit | Default | Flag |
|---|---|---|
| Smallest purchase | 20 USD | `-min-usd` |
| Largest credit of one payment | 500 USD | `-max-usd` |
| Rate of a bought key | 60 requests a minute | `-rpm` |
| How long an order's price holds | 1 hour | `-quote-ttl` |
| How long a paid order's key stays readable | 7 days | `-keep-keys` |
| How long an unpaid order is remembered | 90 days | `-keep-unpaid` |
| New orders | 1 a second, burst 20 | fixed |

Orders live in `-orders-file`, one JSON record a line, mode 0600. A paid order's key sits there in plaintext until `-keep-keys` has passed, so a buyer who closed the page can still read it; the file is rewritten without expired keys and stale orders at each start. A payment to an order already forgotten is logged with its transaction.

## Payout addresses

`-payouts-file` is a JSON object of our own addresses by kind of chain. A coin is offered only when its kind has an address, so the file is also the list of what is on sale.

```json
{"btc": "bc1q...", "evm": "0x...", "tron": "T...", "sol": "...", "ton": "...", "xmr": "4...", "ltc": "...", "bch": "...", "doge": "...", "zec": "t1...", "xrp": "r..."}
```

`evm` serves ETH and every token on `erc20`, `bep20`, `arbitrum`, `avax-c`, `base`, `bera`, `linea`, `monad`, `optimism` and `polygon`; `tron` serves TRX and `trc20`. A network the forwarder adds is not offered until `Family` in `internal/coinpay/paygate.go` maps it: an address of the wrong kind would lose the payment. The forwarder ties an order's address to the payout address given when the order was made, so changing the file moves new orders only.

## Running it

```
SEALEDIN_OPERATOR_API_KEY=... \
  coinpay -public-url https://<host> -gateway https://api.sealedin.ai -payouts-file /etc/sealedin-coinpay/payouts.json \
  -orders-file /var/lib/coinpay/orders
```

The service speaks plain HTTP on `-listen` and must sit behind a TLS reverse proxy that passes the query string through untouched, since the signature covers its bytes; it refuses to start unless its own URL, the gateway and the forwarder are `https`. The browser routes answer cross-origin requests from `-site` only. A second forwarder of the same model fits behind the `Forwarder` interface.
