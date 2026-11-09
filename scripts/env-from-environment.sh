#!/usr/bin/env bash
# Materialize the deploy env file from the process environment, the counterpart of env-from-keychain.sh for a CI runner
# whose secrets arrive as environment variables (the deploy workflow's production environment). Same five variables,
# same output rules: the path given as $1, never .env, mode 600, deleted by the caller after the CLI run.
set -euo pipefail

out=${1:?usage: env-from-environment.sh <output-path>}
case "$(basename "$out")" in
  .env) echo "refusing to write $out: pick a path outside the repo checkout" >&2; exit 1 ;;
esac

chutes=${CHUTES_API_KEY:?set CHUTES_API_KEY}
postgres=${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}
operator=${SEALEDIN_OPERATOR_API_KEY:?set SEALEDIN_OPERATOR_API_KEY}
solana_rpc=${SOLANA_RPC_API_KEY:?set SOLANA_RPC_API_KEY}
fee_payer=${SEALEDIN_FEE_PAYER_KEY:?set SEALEDIN_FEE_PAYER_KEY}

umask 177
printf 'CHUTES_API_KEY=%s\nPOSTGRES_PASSWORD=%s\nSEALEDIN_OPERATOR_API_KEY=%s\nSOLANA_RPC_API_KEY=%s\nSEALEDIN_FEE_PAYER_KEY=%s\n' \
  "$chutes" "$postgres" "$operator" "$solana_rpc" "$fee_payer" > "$out"
echo "$out written (mode 600). Delete it after the CLI run."
