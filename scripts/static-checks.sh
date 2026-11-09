#!/usr/bin/env bash
# Static analysis beyond golangci-lint: shell, Dockerfiles, workflows and Python. Each tool runs from its image pinned by
# index digest, the same in CI and locally (`make static`); bump a digest only to a release at least a week old.
set -euo pipefail
cd "$(dirname "$0")/.."

shellcheck=koalaman/shellcheck@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d       # v0.11.0
hadolint=hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d          # v2.15.1
actionlint=rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667         # 1.7.12
zizmor=ghcr.io/zizmorcore/zizmor@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9     # 1.31.1
ruff=ghcr.io/astral-sh/ruff@sha256:691f37347e1693862ee3d69dbe1d77433fe2d74859339c48c1c52764fda80308          # 0.17.3

run() { docker run --rm --network none -v "$PWD:/mnt:ro" -w /mnt "$@"; }

shell_scripts=(scripts/*.sh scripts/e2e/*.sh)
# The hooks exist only in the private repository.
[ -d .githooks ] && shell_scripts+=(.githooks/*)
echo "== shellcheck"
run "$shellcheck" "${shell_scripts[@]}"
echo "== hadolint"
run "$hadolint" hadolint Dockerfile Dockerfile.* gateway/Dockerfile edge/Dockerfile
echo "== actionlint"
run "$actionlint" -color=false
echo "== zizmor"
run "$zizmor" --offline .github/workflows
echo "== ruff"
run "$ruff" check --no-cache gateway scripts
run "$ruff" format --no-cache --check gateway scripts
