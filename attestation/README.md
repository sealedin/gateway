---
purpose: Pinned guest OS measurements (MRTD, RTMR0-2) per dstack image and VM shape, the input verify-gateway.sh needs to tell our workload's RTMR3 events from any TD's
---

# Guest OS measurement pins

`verify-gateway.sh` reads one of these files through `SEALEDIN_EXPECTED_MRS`. MRTD is the TDX virtual firmware, RTMR0 the virtual hardware (CPU count, memory, devices), RTMR1 the kernel and RTMR2 the kernel command line plus initrd of the dstack guest image; together they fix which guest OS wrote the RTMR3 events, so the compose-hash check that follows is meaningful. They depend on the dstack image and on the VM shape, so one file exists per pair.

| File | Image | Shape | Source |
|---|---|---|---|
| `dstack-0.6.1-tdx.medium.json` | dstack-0.6.1 (`os_image_hash` ec43cb8c...) | tdx.medium, 2 vCPU, 4 GB | captured from our own CVM's platform attestation on 28 Oct 2026 (trust on first use) |

A captured pin proves consistency, not provenance: the reproducible way is `dstack-mr measure -c <vcpus> -m <memory> <image>/metadata.json` against the published dstack release, which must yield the same four values; do that before relying on a pin for anything a client enforces, and re-capture on every image or shape change.
