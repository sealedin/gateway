---
purpose: Policy for the LiteLLM image pin in gateway/Dockerfile: what the frozen digest is, how it was verified, why it is frozen, and the checklist an upgrade must pass
---

# LiteLLM pin policy

The gateway image (`gateway/Dockerfile`) is built `FROM` a LiteLLM image digest, never a tag. Tags move; a digest names one manifest forever, and that manifest is part of what the measured compose pins and RTMR3 attests. `scripts/check-image-pins.sh` fails `make lint` and CI when any `image:` line in a compose file or any `FROM` in a Dockerfile carries a tag instead of `@sha256:`.

## The current pin

`ghcr.io/berriai/litellm@sha256:d1da6edc025e6a59be6faa50b4e8e42c115e1c99644aa3fc2ac416dd353f41da` resolves to LiteLLM 1.106.2 for linux/amd64, from commit `49943cd52ea46aacf8db2e5cb2b890d580fe9bb4`, built on 2026-10-21. It replaced 1.92.0 (`sha256:237ed94c...`, commit `b3086ccd`), which three advisories name: GHSA-7hp6-4w63-5g45 (high, an internal user escalates to proxy admin, 1.91.0 to 1.100.3), GHSA-3cv6-jpf6-8222 (medium, SSRF, 1.92.0 to 1.92.1 among its ranges) and GHSA-g5ff-637f-6q2m (high, local file read, below 1.95.0).

Verified on 2026-11-06 (`docker buildx imagetools inspect` reads the registry; `make e2e-stream-billing` then ran the image):

- The digest is the linux/amd64 OCI image manifest (`application/vnd.oci.image.manifest.v1+json`, 4869 bytes, 24 layers) of the release index `sha256:7294b90f868c5c38c99b83021c7ba46f9b439e95f8e32964c925c7d2563a03f7`, the index the project's incident report of 2026-10-21 (BerriAI/litellm#47826) names as clean and as the version to pin.
- Its image config carries `org.opencontainers.image.revision: 49943cd52ea46aacf8db2e5cb2b890d580fe9bb4`, `org.opencontainers.image.source: https://github.com/BerriAI/litellm`, `created: 2026-10-21T09:31:57Z` (before the malicious 1.107.0 build at 11:21Z that day), entrypoint `docker/prod_entrypoint.sh`, default command `--port 4000`, working directory `/app`, user root, `PATH` starting with `/app/.venv/bin`.
- On GitHub, the tag `v1.106.2` points at exactly that commit (committed 2026-10-21T08:19:40Z, "fix(proxy): backport LIT-145 spend and cost fixes to stable/1.106"), a GitHub release of the real repository, and `pyproject.toml` there declares `version = "1.106.2"`. The incident report lists every 1.106.2 wheel as checked and clean.
- `docker/prod_entrypoint.sh` at that commit still ends in `exec litellm "$@"` (under `ddtrace-run` when `USE_DDTRACE` is true); a new first branch runs an admin agent only when the first argument is `--admin-agent`, which ours never is (`--config`). The root `Dockerfile` still installs into `/app/.venv` with `uv sync --frozen`, now on `python-3.13`; the venv's `python3` comes first on `PATH`, so `gateway/entrypoint.py` runs as before.
- On 2026-11-09 neither the GitHub advisory database nor OSV lists an advisory against 1.106.2.
- Newer releases (1.106.5 and later, 1.108.x) are less than 14 days old today and fail item 1 below; 1.106.5 qualifies from 2026-11-10.

Not verified: the layer contents were not compared with the lockfile, so the published digest is trusted as the project's release artifact. `make audit-image` lists the known vulnerabilities of its OS and Python packages; that list is an input to the next upgrade, not a reason to move the pin outside this checklist.

## Why the digest is frozen

The LiteLLM project has had two supply-chain incidents. On 2026-03-24, versions 1.82.7 and 1.82.8 were pushed to PyPI with a credential stealer (no matching GitHub release; both quarantined). On 2026-10-21, version 1.107.0 was published to PyPI and to the official Docker image tags with a credential stealer and remote-access payload for about two hours, built from a lookalike repository with stolen maintainer tokens. The pinned 1.106.2 was built two hours before the second, is outside both affected ranges and is the version the project's incident report names as the one to pin; a moving tag such as `main-stable` would have carried the second incident into a rebuild, a digest cannot. The pin is therefore frozen: it changes only through the checklist below, never through a scheduled bump, a dependency bot or a tag resolution at build time.

## Upgrade checklist

An upgrade is a deliberate governance change (new gateway image digest, new compose-hash, new RTMR3 for every deployment). Every item is required:

1. The target is a release from a tagged commit at least 14 days old, so that a compromised release has had time to be reported and pulled.
2. No advisory, issue or vendor notice names the target version or any version between the current pin and it as compromised.
3. The diff between the two commits of `docker/prod_entrypoint.sh`, the root `Dockerfile`, `pyproject.toml` and the lock file has been read; the wrapper's assumptions (entrypoint path, venv location, `python3` on `PATH`, root user) still hold or the wrapper is changed in the same commit.
4. The image config of the candidate digest carries the expected `org.opencontainers.image.revision` and the new digest is recorded here with its `created` date.
5. The gateway image is rebuilt from the new digest, the compose re-pinned, the compose-hash recorded, and `internal/gateway`'s policy assumptions (configured `api_base` over `OPENAI_BASE_URL`, `/v1/messages` bridging for `hosted_vllm/`) re-verified against the new version.
6. The `/key/generate`, `/key/list`, `/key/info` and `/key/update` fields the identity's key issuance and x402 sales use (`internal/usage`) still exist with the same names, `/key/generate` still takes a caller-named `key` with `disable_custom_api_keys` unset and still upserts on the token with an empty update (one row and one budget per payment depend on it; `PrismaClient.insert_data`), and `/key/update` still takes the budget and the whole metadata object in one call (a top-up's exactly-once depends on it).
7. `DEFAULT_MAX_OUTPUT_TOKENS_FALLBACK` is still the egress's `litellmDefaultOutput`, `_estimate_output_tokens` still reserves the lowest of the named figure and `max_output_tokens`, and `disable_token_counter` still keeps tokenizers off the auth path, on every inference route. `async_pre_call_hook` still runs on both inference routes with `proxy_server_request.body` set, and `gateway/request_guard.py`'s list still names every field our clients need. The guard still gets `spend`, `max_budget` and `token` in `user_api_key_dict`, its end-of-request events still carry the `litellm_call_id` it counted under on both routes, the spend still shows within its hold, and one process still serves the proxy (`--num_workers 1`).
8. The facts `cmd/drain` depends on hold: the headers LiteLLM authenticates from (`internal/drain`), the 60-second lapse of `max_parallel_requests` and the spend flush within the drain's stop wait.
9. `make e2e-stream-billing` passes against the candidate, whose digest the test `TestEndToEndUsesTheMeasuredImages` pins in the e2e compose too.

Never automated.
