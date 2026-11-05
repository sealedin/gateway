#!/usr/bin/env bash
# Materialize an env file from macOS Keychain for a phala deploy run. Writes to the path given as $1, refusing .env so
# the repo-root development file is never clobbered. The plaintext should not persist: use, then delete
# (deploy-phala.sh does both via mktemp/trap).
#
#   ./scripts/env-from-keychain.sh /tmp/sealedin.env
#   phala deploy --cvm-id <id> -c ./docker-compose.phala.yml -e /tmp/sealedin.env
#   rm /tmp/sealedin.env
#
# One-time setup of the Keychain items:
#   security add-generic-password -s sealedin-chutes -a admin -w '<key>'       # Chutes API key (cpk_...) for the egress
#   security add-generic-password -s sealedin-postgres -a admin -w '<password>'
#   security add-generic-password -s sealedin-operator -a admin -w '<key>'   # operator bearer for /v1/keys
#   security add-generic-password -s sealedin-solana-rpc -a admin -w '<key>' # the rpcproxy's Solana RPC provider key
#   scripts/new-fee-payer.sh                                                 # generates sealedin-fee-payer and prints its address
# The LiteLLM master key is no Keychain item: the CVM derives it from the guest agent (never leaves the enclave).
set -euo pipefail

out=${1:?usage: env-from-keychain.sh <output-path>}
case "$(basename "$out")" in
  .env) echo "refusing to write $out: pick a path outside the repo checkout" >&2; exit 1 ;;
esac

get() { security find-generic-password -w -s "$1" || { echo "missing Keychain item $1" >&2; exit 1; }; }

# Capture first: a failing $(...) inside printf's argument list exits only the subshell and writes empty secrets.
chutes=$(get sealedin-chutes)
postgres=$(get sealedin-postgres)
operator=$(get sealedin-operator)
solana_rpc=$(get sealedin-solana-rpc)
fee_payer=$(get sealedin-fee-payer)

umask 177
printf 'CHUTES_API_KEY=%s\nPOSTGRES_PASSWORD=%s\nSEALEDIN_OPERATOR_API_KEY=%s\nSOLANA_RPC_API_KEY=%s\nSEALEDIN_FEE_PAYER_KEY=%s\n' \
  "$chutes" "$postgres" "$operator" "$solana_rpc" "$fee_payer" > "$out"
echo "$out written (mode 600). Delete it after the CLI run."
