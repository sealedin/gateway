---
purpose: Policy for the LiteLLM image pin in gateway/Dockerfile: what the frozen digest is, how it was verified, why it is frozen, and the checklist an upgrade must pass
---

# LiteLLM pin policy

The gateway image (`gateway/Dockerfile`) is built `FROM` a LiteLLM image digest, never a tag. Tags move; a digest names one manifest forever, and that manifest is part of what the measured compose pins and RTMR3 attests. `scripts/check-image-pins.sh` fails `make lint` and CI when any `image:` line in a compose file or any `FROM` in a Dockerfile carries a tag instead of `@sha256:`.

## The current pin

`ghcr.io/berriai/litellm@sha256:237ed94c2b4bd821d44f4abd4b57b2ae7b3108a7b4a768d1d8cd7c1b3884c604` resolves to LiteLLM 1.92.0, the stable cut from commit `b3086ccd74553565c9a39716e72303ae985555f9`, built on 2026-07-12.

Verified on 2026-11-03, without pulling or running the image (`docker buildx imagetools inspect` reads the registry only):

- The digest is the OCI image manifest (`application/vnd.oci.image.manifest.v1+json`, 4293 bytes, 21 layers); the saved copy matches what the registry serves for that digest.
- Its image config carries `org.opencontainers.image.revision: b3086ccd74553565c9a39716e72303ae985555f9`, `org.opencontainers.image.source: https://github.com/BerriAI/litellm`, `created: 2026-07-12T01:20:55Z`, entrypoint `docker/prod_entrypoint.sh`, default command `--port 4000`, working directory `/app`, `PATH` starting with `/app/.venv/bin`.
- On GitHub, the tag `v1.92.0` points at exactly that commit (committed 2026-07-11T23:29:55Z, message "chore(release): backport 11 staging PRs onto patch-1.92.0rc2 for the 1.92.0 stable cut"), and `pyproject.toml` at that commit declares `version = "1.92.0"`.
- `docker/prod_entrypoint.sh` at that commit is four lines: it execs `litellm "$@"` (or under `ddtrace-run` when `USE_DDTRACE=true`); the root `Dockerfile` installs the project into `/app/.venv` with `uv sync --frozen` and runs it as root on a wolfi base with `python3` present. The gateway's entrypoint wrapper (`gateway/entrypoint.py`, stdlib only: it reads the identity's key file and execs that entrypoint) relies on exactly those facts.

Not verified: the layer contents were not pulled, so nothing here attests that the wheels in the venv equal the lockfile at that commit; the published digest is trusted as the project's release artifact.

## Why the digest is frozen

The LiteLLM project has had two supply-chain incidents. On 2026-03-24, versions 1.82.7 and 1.82.8 were pushed to PyPI with a credential stealer (no matching GitHub release; both quarantined). On 2026-10-21, version 1.107.0 was published to PyPI and to the official Docker image tags with a credential stealer and remote-access payload for about two hours, built from a lookalike repository with stolen maintainer tokens. The pinned 1.92.0 lies between the two, predates the second and is outside both affected ranges; a moving tag such as `main-stable` would have carried the second incident into a rebuild, a digest cannot. The pin is therefore frozen: it changes only through the checklist below, never through a scheduled bump, a dependency bot or a tag resolution at build time.

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
