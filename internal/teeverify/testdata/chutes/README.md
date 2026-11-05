---
purpose: Provenance and refresh procedure of the recorded Chutes TEE evidence used as offline test vectors
---

# Chutes evidence fixture

Recorded on 2026-10-27 from two public Chutes TEE chutes (see `meta.json` for ids, nonces and hashes): one Blackwell single-GPU instance (`blackwell.json`) and one Hopper 8-GPU protected-PCIe instance (`hopper.json`). Each file holds our random nonce and the `evidence[]` entry exactly as `GET https://api.chutes.ai/chutes/<chute_id>/evidence?nonce=<nonce>` returned it: TDX quote, per-GPU SPDM evidence, the instance TLS certificate, and the signed `attested_body`.

`collateral/` is the Intel PCS v4 collateral go-tdx-guest fetched while verifying these quotes (FMSPC `90c06f000000`), each with the `.headers.json` carrying the issuer-chain headers PCS delivers. `nras/` holds the NRAS v3 verdicts for the same evidence and `jwks.json` the two NVIDIA keys that signed them. Tests pin verification time inside the recorded validity windows, so the vectors stay valid offline; the TCB status was UpToDate at capture.

What these vectors do not contain: the instances' ML-KEM E2EE public keys, which `GET /e2e/instances/<chute_id>` serves only with an API key. The report_data binding to that key is therefore unit-tested on crafted inputs; refresh with a key to add a recorded positive vector.

Refresh: pick a `chute_id` from `https://llm.chutes.ai/v1/models` (`confidential_compute: true`), fetch evidence with `openssl rand -hex 32` as the nonce, post the GPU evidence as an EAT (`{"arch","nonce":<report_data[0:32] hex>,"evidence_list"}`) to `https://nras.attestation.nvidia.com/v3/attest/gpu`, save the JWKS, record the collateral with a go-tdx-guest getter that dumps bodies and headers, and update `meta.json`.
