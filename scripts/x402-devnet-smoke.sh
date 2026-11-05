#!/usr/bin/env bash
# Try a purchase on Solana devnet with local binaries: never against mainnet, never in a measured deployment. Runs the
# rpcproxy, an unattested identity and the sales service on loopback, then cmd/x402-smoke: challenge against the signed
# catalog, settlement, duplicate refusal and recovery, then a Solana Pay transfer and its claim.
#
# Prerequisites (each costs only devnet tokens):
#   docker compose up db gateway     the dev LiteLLM on localhost:4000, with LITELLM_MASTER_KEY from .env
#   SEALEDIN_LITELLM_MASTER_KEY      that same key
#   SEALEDIN_DEV_FEE_PAYER_SEED      64 hex chars (openssl rand -hex 32); the script prints its address, fund it with devnet SOL
#   SEALEDIN_DEV_TREASURY            a wallet whose devnet USDC associated token account already exists
#   X402_SMOKE_WALLET                Solana CLI keypair file holding at least 40 devnet USDC at its associated token account
#   X402_SMOKE_RPC_CONFIRMATION      a second devnet RPC URL on another host; a confirmation must hold on both
#   X402_SMOKE_RPC_PRIMARY           optional, default the public devnet endpoint
set -euo pipefail
cd "$(dirname "$0")/.."

network=solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 # devnet genesis
devnet_usdc=4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU
primary=${X402_SMOKE_RPC_PRIMARY:-https://api.devnet.solana.com/}
confirmation=${X402_SMOKE_RPC_CONFIRMATION:?set a second devnet RPC URL}
wallet=${X402_SMOKE_WALLET:?set the paying wallet file}
: "${SEALEDIN_LITELLM_MASTER_KEY:?set the dev LiteLLM master key}"
: "${SEALEDIN_DEV_FEE_PAYER_SEED:?set the devnet fee payer seed}"
: "${SEALEDIN_DEV_TREASURY:?set the devnet treasury}"
case "$primary $confirmation" in
  *mainnet*) echo "refusing a mainnet RPC host: this script is devnet only" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$tmp"
}
trap cleanup EXIT
printf 'primary:\n  url: %s\nconfirmation:\n  url: %s\n' "$primary" "$confirmation" > "$tmp/policy.yaml"

go build -o "$tmp/rpcproxy" ./cmd/rpcproxy
go build -o "$tmp/identity" ./cmd/identity
go build -o "$tmp/sales" ./cmd/sales
go build -o "$tmp/smoke" ./cmd/x402-smoke

"$tmp/rpcproxy" -listen 127.0.0.1:18475 -policy "$tmp/policy.yaml" 2> "$tmp/rpcproxy.log" &
pids+=($!)
SEALEDIN_DEV_VIRTUAL_KEY_SECRET=$(openssl rand -hex 32)
export SEALEDIN_DEV_PAYMENT_NETWORK=$network SEALEDIN_DEV_PAYMENT_ASSET=$devnet_usdc SEALEDIN_DEV_FEE_PAYER_SEED SEALEDIN_DEV_TREASURY SEALEDIN_DEV_VIRTUAL_KEY_SECRET
"$tmp/identity" -listen 127.0.0.1:18471 -private-listen 127.0.0.1:18473 -gateway http://127.0.0.1:4000 2> "$tmp/identity.log" &
pids+=($!)
"$tmp/sales" -listen 127.0.0.1:18476 -gateway http://127.0.0.1:4000 -rpcproxy http://127.0.0.1:18475 2> "$tmp/sales.log" &
pids+=($!)
sleep 1
grep -E 'x402 purchases on' "$tmp/sales.log" || { cat "$tmp/sales.log" >&2; exit 1; }

# -solana-pay-rpc also pays by a spec-shaped Solana Pay transfer from the same wallet, so it needs 20 more devnet USDC.
"$tmp/smoke" -url http://127.0.0.1:18476 -catalog-url http://127.0.0.1:18473 -wallet "$wallet" -solana-pay-rpc "$primary" || { tail -n 20 "$tmp/sales.log" >&2; exit 1; }
