#!/usr/bin/env bash
# Generate the fee payer keypair locally, store it in the Keychain item sealedin-fee-payer and print only its public address.
# It refuses an existing item. To recover SOL, import the item's value into any Solana wallet: it is the base58 keypair form.
set -euo pipefail
cd "$(dirname "$0")/.."
go run ./cmd/feepayer-keygen
