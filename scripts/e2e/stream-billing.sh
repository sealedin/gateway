#!/usr/bin/env bash
# End-to-end against the pinned LiteLLM with Postgres: a client hanging up or stalling behind the drain is billed in full.
# Needs a Docker daemon and pulls the pinned images; no network beyond that, no secret.
set -euo pipefail
cd "$(dirname "$0")/stream-billing"
down() { docker compose -f compose.yml down -v --remove-orphans >/dev/null 2>&1 || true; rm -f edge.caddyfile; }
trap down EXIT
sed '/^\ttls {$/,/^\t}$/d' ../../../edge/Caddyfile > edge.caddyfile
docker compose -f compose.yml up -d --build --quiet-pull
for _ in $(seq 1 100); do
  curl -sf -m 2 http://127.0.0.1:14000/health/liveliness >/dev/null && break
  sleep 3
done
curl -sf -m 2 http://127.0.0.1:14000/health/liveliness >/dev/null || { docker compose -f compose.yml logs gateway | tail -20; exit 1; }
python3 -I client.py || { docker compose -f compose.yml logs --tail 20 drain edge gateway; exit 1; }
# A variable, not a pipe into grep -q: under pipefail its early exit can read a match as a pass.
logs=$(docker compose -f compose.yml logs edge drain)
if grep -q 'sk-' <<<"$logs"; then
  echo "FAIL: a key reached the edge or drain log" >&2; exit 1
fi
