"""Gateway entrypoint: take LITELLM_MASTER_KEY from the identity's key file, then exec the stock entrypoint.

In the measured compose the identity derives the master key inside the CVM and writes it to a tmpfs volume mounted
read-only here, so the gateway needs no guest agent socket; this wrapper waits for the file (bounded) and exports it.
Without that volume (dev topology) the key must already be in the environment. Stdlib only.
"""

import os
import sys
import time

KEY_DIR = "/run/sealedin"
KEY_FILE = KEY_DIR + "/litellm-master-key"
STOCK_ENTRYPOINT = "/app/docker/prod_entrypoint.sh"
WAIT_SECONDS = 120
POLL_SECONDS = 0.5
MAX_KEY_FILE_BYTES = 128  # sk- plus 64 hex and a newline; anything bigger is not the identity's file
HEX_DIGITS = frozenset("0123456789abcdef")


def valid_master_key(key):
    """sk- plus exactly 64 hex chars (case folded on read), as the identity formats it."""
    return key.startswith("sk-") and len(key) == 67 and set(key[3:]) <= HEX_DIGITS


def read_master_key(path, wait_seconds=WAIT_SECONDS, sleep=time.sleep):
    """Waits for the identity to publish the key file; a missing or malformed file after the wait is fatal."""
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            with open(path, encoding="ascii") as f:
                raw = f.read(MAX_KEY_FILE_BYTES + 1)
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"no master key at {path} after {wait_seconds}s: is the identity up?") from None
            sleep(POLL_SECONDS)
    if len(raw) > MAX_KEY_FILE_BYTES:
        raise RuntimeError(f"master key file {path} is larger than {MAX_KEY_FILE_BYTES} bytes")
    key = raw.strip().lower()
    if not valid_master_key(key):
        raise RuntimeError(f"master key file {path} is not sk- plus 64 hex chars")
    return key


def key_volume_mounted(key_dir):
    """Only an absent directory is the dev topology; any other stat failure is a broken mount and fatal."""
    try:
        os.stat(key_dir)
    except FileNotFoundError:
        return False
    return True


def main(argv, environ, key_dir=KEY_DIR, key_file=KEY_FILE, execv=os.execv):
    if key_volume_mounted(key_dir):
        environ["LITELLM_MASTER_KEY"] = read_master_key(key_file)
    elif not environ.get("LITELLM_MASTER_KEY"):
        raise SystemExit("LITELLM_MASTER_KEY is unset and no key volume is mounted: refusing to start")
    execv(STOCK_ENTRYPOINT, [STOCK_ENTRYPOINT, *argv])


if __name__ == "__main__":
    main(sys.argv[1:], os.environ)
