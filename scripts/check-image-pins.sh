#!/usr/bin/env bash
# Every image reference is a digest: `image:` lines in the compose files and `FROM` lines in the Dockerfiles must carry
# @sha256:<64 hex>, never a tag. A FROM may also name an earlier build stage (declared with AS) and carry --flag=value
# options such as --platform. make lint and CI both call it.
set -euo pipefail
cd "$(dirname "$0")/.."
files=$(git ls-files '*Dockerfile*' 'docker-compose*.yml')
[ -n "$files" ] || { echo "no Dockerfile or compose file tracked: the pin check has nothing to check" >&2; exit 1; }
stages=$(echo "$files" | xargs grep -hiE '^\s*FROM\s.*\sAS\s+\S+\s*$' /dev/null | sed -E 's/.*[[:space:]][Aa][Ss][[:space:]]+([^[:space:]]+).*/\1/' || true)
bad=0
while IFS= read -r line; do
  ref=$(printf '%s' "$line" | sed -E 's/^[^:]+:[0-9]+:[[:space:]]*(image:|FROM)[[:space:]]+//; s/[[:space:]]+#.*$//; s/(--[^[:space:]]+[[:space:]]+)+//; s/[[:space:]]+[Aa][Ss][[:space:]].*$//')
  if [[ $ref =~ @sha256:[0-9a-f]{64}$ ]] || grep -qxF "$ref" <<<"$stages"; then
    continue
  fi
  echo "unpinned image reference: $line" >&2; bad=1
done < <(echo "$files" | xargs grep -nE '^\s*(image:|FROM)\s' /dev/null)
exit "$bad"
