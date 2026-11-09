#!/usr/bin/env bash
# Lists known vulnerabilities in the pinned LiteLLM image (OS and Python packages) with osv-scanner. Report only: the pin
# moves through docs/litellm-pin.md, never to silence this list, so a finding is an input to the next upgrade.
set -euo pipefail
cd "$(dirname "$0")/.."

osv=ghcr.io/google/osv-scanner@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0 # v2.7.0
image=$(sed -n 's/^FROM \(ghcr\.io\/berriai\/litellm@sha256:[0-9a-f]\{64\}\)$/\1/p' gateway/Dockerfile)
[ -n "$image" ] || { echo "no pinned LiteLLM digest in gateway/Dockerfile" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
docker pull -q "$image" >/dev/null
docker save -o "$work/image.tar" "$image"
code=0
docker run --rm -v "$work:/scan" "$osv" scan image --archive --format table /scan/image.tar || code=$?
# osv-scanner exits 1 when it found something and 127 or more when it could not scan.
[ "$code" -le 1 ] || { echo "osv-scanner failed with exit $code" >&2; exit "$code"; }
