"""Asserts against the pinned LiteLLM: through the drain a client that hangs up or stalls is billed for the whole stream, with
or without the pinned Caddy in front, a 404 from the upstream puts no model in cooldown, a prompt built to stall a tokenizer
freezes nothing, the egress's closing chunk bills, and the guard counts each request's worst case, running ones included,
whatever max_tokens says. Prints what a direct connection does, for the record."""

import http.client
import json
import socket
import sys
import threading
import time

MASTER = "sk-e2e-master"
LITELLM = ("127.0.0.1", 14000)
DRAIN = ("127.0.0.1", 14077)
EDGE = ("127.0.0.1", 14080)  # the measured Caddyfile, TLS stripped
FULL_COST = 2.0  # the fake upstream's 1000 + 1000 tokens at the config's 0.001 USD each
RESERVATION = 1.0  # the model's 1000 output tokens at 0.001 USD each
GUARD_HOLD_SECONDS = 25  # past the guard's hold of a finished request
FREEZE_PROMPT = "x" * (1 << 20)  # minutes of tiktoken on the event loop with the counter on
FREEZE_LIMIT_SECONDS = 30  # counter off it took 0.4 s; emulation is slow, a freeze is minutes
SETTLE_SECONDS = 420  # a stream, the drain's 30-second stall limit, LiteLLM's flush, under emulation


def admin(method, path, body=None):
    conn = http.client.HTTPConnection(*LITELLM, timeout=180)
    conn.request(
        method, path, json.dumps(body) if body else None, {"Authorization": "Bearer " + MASTER, "Content-Type": "application/json"}
    )
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, json.loads(raw) if raw else None


def new_key(budget=100):
    status, body = admin("POST", "/key/generate", {"max_budget": budget, "models": ["e2e"], "max_parallel_requests": 10})
    assert status == 200, body
    return body["key"]


def spend(key):
    _, body = admin("GET", "/key/info?key=" + key)
    return body["info"]["spend"]


def request_bytes(key, prompt, path, max_tokens=None):
    if path == "/v1/responses":
        payload = {"model": "e2e", "stream": True, "input": prompt}
    elif path == "/v1/messages":
        payload = {"model": "e2e", "stream": True, "max_tokens": 100, "messages": [{"role": "user", "content": prompt}]}
    else:
        payload = {
            "model": "e2e",
            "stream": True,
            "stream_options": {"include_usage": True},
            "messages": [{"role": "user", "content": prompt}],
        }
    if max_tokens:
        payload["max_tokens"] = max_tokens
    credential = f"x-api-key: {key}" if path == "/v1/messages" else f"Authorization: Bearer {key}"
    body = json.dumps(payload)
    return (
        f"POST {path} HTTP/1.1\r\nHost: e2e\r\n{credential}\r\n"
        f"Content-Type: application/json\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    ).encode()


def open_stream(addr, key, prompt="hi", path="/v1/chat/completions", max_tokens=None):
    sock = socket.create_connection(addr, timeout=120)
    sock.sendall(request_bytes(key, prompt, path, max_tokens))
    reader = sock.makefile("rb")
    return sock, reader, reader.readline()


def read_chunks(reader, count):
    seen = 0
    while seen < count:
        line = reader.readline()
        assert line, "stream ended early"
        if line.startswith(b"data:"):
            seen += 1


def complete(addr, key, prompt="hi"):
    sock, reader, status = open_stream(addr, key, prompt)
    assert b" 200 " in status, status
    while reader.readline():
        pass
    sock.close()


def hang_up(addr, key, path="/v1/chat/completions"):
    sock, reader, status = open_stream(addr, key, path=path)
    assert b" 200 " in status, status
    read_chunks(reader, 5)
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()


def stall(addr, key):
    """Reads a few chunks of a reply far larger than the socket buffers, then holds the socket without reading."""
    sock, reader, status = open_stream(addr, key, prompt="BIG")
    assert b" 200 " in status, status
    read_chunks(reader, 5)
    return sock


def probe_liveliness():
    conn = http.client.HTTPConnection(*LITELLM, timeout=FREEZE_LIMIT_SECONDS)
    started = time.monotonic()
    conn.request("GET", "/health/liveliness")
    conn.getresponse().read()
    conn.close()
    return time.monotonic() - started


def freeze(addr, key, path, liveliness, want=b" 200 "):
    """Probes LiteLLM while the prompt is on its way in: a frozen event loop stops answering both, in auth, before any status."""
    sock = socket.create_connection(addr, timeout=120)
    sock.sendall(request_bytes(key, FREEZE_PROMPT, path))
    time.sleep(1)
    liveliness.append(probe_liveliness())
    reader = sock.makefile("rb")
    status = reader.readline()
    assert want in status, status
    while reader.readline():
        pass
    sock.close()


def admitted(budget):
    """How many streams naming a huge max_tokens one key's budget admits at once: LiteLLM reserves each at most the model's limit."""
    key, held, count = new_key(budget), [], 0
    while count < 5:
        sock, _, status = open_stream(LITELLM, key, max_tokens=10**9)
        held.append(sock)
        if b" 200 " not in status:
            break
        count += 1
    for sock in held:
        sock.close()
    return count


def parallel_full_context(budget):
    key, held, count = new_key(budget), [], 0
    for _ in range(10):
        sock, _, status = open_stream(LITELLM, key, FREEZE_PROMPT, max_tokens=1)
        held.append(sock)
        count += b" 200 " in status
    for sock in held:
        sock.close()
    return count


def freed_after_a_stream(path):
    """3.5 USD holds a stream's 2 USD and one worst case of about 1.1, but not while the finished one is still counted too."""
    key = new_key(3.5)
    sock, reader, status = open_stream(LITELLM, key, path=path, max_tokens=1000)
    assert b" 200 " in status, status
    while reader.readline():
        pass
    sock.close()
    deadline = time.monotonic() + SETTLE_SECONDS
    while spend(key) < FULL_COST and time.monotonic() < deadline:
        time.sleep(1)
    time.sleep(GUARD_HOLD_SECONDS)
    sock, _, status = open_stream(LITELLM, key, path=path, max_tokens=1000)
    sock.close()
    return int(status.split()[1])


def edge_headers(method, path, origin):
    """The edge answers CORS itself, whether or not what is behind it is up; this stack has no sales service or identity."""
    conn = http.client.HTTPConnection(*EDGE, timeout=30)
    conn.request(method, path, b"{}" if method == "POST" else None, {"Origin": origin, "Host": "e2e"})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status, {k.lower(): v for k, v in resp.getheaders()}


def check_cors():
    site = "https://sealedin.ai"
    for method, path in (("POST", "/v1/keys/claim"), ("GET", "/v1/catalog")):
        _, headers = edge_headers(method, path, site)
        if headers.get("access-control-allow-origin") != site or headers.get("access-control-expose-headers") != "Retry-After":
            sys.exit(f"FAIL: no CORS for the site on {path}: {headers}")
        _, headers = edge_headers(method, path, "https://evil.example")
        if any(k.startswith("access-control-") for k in headers):
            sys.exit(f"FAIL: another origin got CORS on {path}")
    status, headers = edge_headers("OPTIONS", "/v1/keys/claim", site)
    if status != 204 or "authorization" not in headers.get("access-control-allow-headers", ""):
        sys.exit(f"FAIL: preflight: {status} {headers}")
    status, headers = edge_headers("OPTIONS", "/v1/keys/claim", "https://evil.example")
    if status == 204 or any(k.startswith("access-control-") for k in headers):
        sys.exit(f"FAIL: another origin's preflight: {status} {headers}")
    _, headers = edge_headers("POST", "/v1/keys/buy", site)
    if any(k.startswith("access-control-") for k in headers):
        sys.exit("FAIL: x402 buy got CORS")


def spoofed_owner(path):
    """Spend must land on the key that paid, whatever a client's metadata says about whose it is."""
    key, victim = new_key(), new_key()
    fields = {
        "model": "e2e",
        "stream": True,
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {"user_api_key": victim, "user_api_key_hash": victim, "user_api_key_alias": "x"},
        "litellm_metadata": {"user_api_key": victim, "user_api_key_hash": victim},
    }
    conn = http.client.HTTPConnection(*LITELLM, timeout=120)
    conn.request("POST", path, json.dumps(fields), {"x-api-key": key, "Content-Type": "application/json"})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    deadline = time.monotonic() + 60
    while spend(key) < FULL_COST and spend(victim) == 0 and time.monotonic() < deadline:
        time.sleep(1)
    time.sleep(GUARD_HOLD_SECONDS)
    return resp.status, spend(key), spend(victim)


def smuggled(path):
    """A field the fake refuses with a 418: extra_body and a client's own drop settings must not carry it to the upstream."""
    fields = {
        "model": "e2e",
        "stream": True,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}],
        "foo": 1,
        "additional_drop_params": [],
        "drop_params": False,
        "allowed_openai_params": ["foo"],
        "extra_body": {"model": "other", "foo": 1},
    }
    conn = http.client.HTTPConnection(*LITELLM, timeout=120)
    conn.request("POST", path, json.dumps(fields), {"x-api-key": new_key(), "Content-Type": "application/json"})
    resp = conn.getresponse()
    status = resp.status
    conn.close()
    return status


def wait_billed(keys):
    deadline = time.monotonic() + SETTLE_SECONDS
    while time.monotonic() < deadline:
        if all(abs(spend(k) - FULL_COST) < 1e-9 for k in keys.values()):
            break
        time.sleep(5)
    return {name: spend(key) for name, key in keys.items()}


def main():
    keys = {
        name: new_key()
        for name in (
            "direct full",
            "direct hang-up",
            "drain full",
            "drain hang-up",
            "edge hang-up",
            "edge messages hang-up",
            "drain stall",
            "closing chunk",
            "one prompt",
            "one prompt, messages",
        )
    }
    liveliness = []
    held = stall(DRAIN, keys["drain stall"])
    threads = [
        threading.Thread(target=f, args=a)
        for f, a in (
            (complete, (LITELLM, keys["direct full"])),
            (hang_up, (LITELLM, keys["direct hang-up"])),
            (complete, (DRAIN, keys["drain full"])),
            (hang_up, (DRAIN, keys["drain hang-up"])),
            (hang_up, (EDGE, keys["edge hang-up"])),
            (hang_up, (EDGE, keys["edge messages hang-up"], "/v1/messages")),
            (complete, (DRAIN, keys["closing chunk"], "CUT")),
            (freeze, (DRAIN, keys["one prompt"], "/v1/chat/completions", liveliness)),
            (freeze, (DRAIN, keys["one prompt, messages"], "/v1/messages", liveliness)),
            (freeze, (DRAIN, "sk-invalid", "/v1/chat/completions", liveliness, b" 401 ")),
        )
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    direct_cut = keys.pop("direct hang-up")
    results = wait_billed(keys)
    held.close()
    print(results)
    print("for the record, a direct hang-up billed", spend(direct_cut), "of", FULL_COST)
    failed = [n for n, v in results.items() if abs(v - FULL_COST) > 1e-9]
    if failed:
        sys.exit(f"FAIL: not billed in full: {failed}")

    if len(liveliness) != 3:
        sys.exit(f"FAIL: one prompt froze LiteLLM past {FREEZE_LIMIT_SECONDS} s: {liveliness}")
    print("liveliness during the 1 MiB prompts: %s s" % [f"{t:.1f}" for t in liveliness])

    check_cors()
    # A claim's row exists at no budget until its credit lands: it must serve nothing meanwhile.
    sock, _, status = open_stream(LITELLM, new_key(0))
    sock.close()
    if b" 200 " in status:
        sys.exit("FAIL: a key with no budget was served")
    for path in ("/v1/chat/completions", "/v1/messages"):
        got = spoofed_owner(path)
        if got != (200, FULL_COST, 0):
            sys.exit(f"FAIL: a client's metadata moved the spend on {path}: status, spend, victim's spend {got}")
        status = smuggled(path)
        if status != 200:
            sys.exit(f"FAIL: a client's field reached the upstream on {path}: {status}")

    # The guard's worst case is the model's limit of 1 USD plus the body, not 10^9 tokens: half that buys nothing, 1.5 one.
    counts = admitted(RESERVATION / 2), admitted(RESERVATION * 1.5)
    if counts != (0, 1):
        sys.exit(f"FAIL: streams admitted on budgets of half and 1.5 worst cases: {counts}, want (0, 1)")
    # Each full-context request naming one output token may cost 2 USD of input: on 5 USD two run, and eight are refused.
    count = parallel_full_context(5)
    if count != 2:
        sys.exit(f"FAIL: {count} of 10 full-context requests admitted on 5 USD, want 2: input overruns the budget")
    for path in ("/v1/chat/completions", "/v1/messages"):
        status = freed_after_a_stream(path)
        if status != 200:
            sys.exit(f"FAIL: the guard did not free a finished request on {path}: {status}")

    sock, _, status = open_stream(DRAIN, new_key(), path="/v1/responses")
    sock.close()
    if b" 404 " not in status:
        sys.exit(f"FAIL: the fake upstream's 404 did not come back: {status!r}")
    sock, _, status = open_stream(DRAIN, new_key())
    sock.close()
    if b" 200 " not in status:
        sys.exit(f"FAIL: one upstream 404 put the model in cooldown: {status!r}")

    # /key/info reaches LiteLLM straight from the edge, so only the edge's own cap can answer: chunked, so no length gives it away.
    sock = socket.create_connection(EDGE, timeout=120)
    sock.sendall(b"GET /key/info HTTP/1.1\r\nHost: e2e\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n")
    chunk = b"%x\r\n%s\r\n" % (1 << 20, b"x" * (1 << 20))
    try:
        for _ in range(40):
            sock.sendall(chunk)
        sock.sendall(b"0\r\n\r\n")
    except OSError:
        pass  # the edge may answer and close before the upload ends
    status = sock.makefile("rb").readline()
    sock.close()
    if b" 413 " not in status:
        sys.exit(f"FAIL: the edge did not cap a body: {status!r}")
    print(
        "OK: billed in full through the drain, no cooldown from an upstream 404, bodies capped at the edge, no freeze, "
        "CORS for the site only, no field smuggled, worst case at the model limit, running requests counted"
    )


main()
