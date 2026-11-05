"""Slow OpenAI-compatible SSE upstream: 60 chunks, 0.25 s apart, or 96 MB at once for a prompt saying BIG, past every socket buffer on the way, with a final usage chunk."""
import http.server, json, socketserver, time
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); body = self.rfile.read(n)
        if self.path.endswith("/responses"):  # as the egress does: only chat completions are served
            self.send_response(404); self.send_header("content-length", "0"); self.end_headers(); return
        if b"CUT" in body:  # the closing chunk the egress writes for a stream cut before its usage
            self.send_response(200); self.send_header("content-type", "text/event-stream"); self.send_header("connection", "close"); self.end_headers()
            for d in ({"choices": [{"index": 0, "delta": {"role": "assistant", "content": "partial"}, "finish_reason": None}]},
                      {"choices": [{"index": 0, "delta": {}, "finish_reason": "length"}], "usage": {"prompt_tokens": 1000, "completion_tokens": 1000, "total_tokens": 2000}}):
                self.wfile.write(b"data: " + json.dumps({"id": "egress-cut", "object": "chat.completion.chunk", "created": 0, "model": "m", **d}).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n"); self.wfile.flush(); self.close_connection = True; return
        fields = json.loads(body)
        if fields["model"] != "m" or "foo" in fields:  # the client's field reached the upstream: the guard failed
            self.send_response(418); self.send_header("content-length", "0"); self.end_headers(); return
        big = b"BIG" in body
        pad = "word " * ((16 << 10) // 5) if big else "word "
        count, delay = (6000, 0) if big else (60, 0.25)
        self.send_response(200); self.send_header("content-type", "text/event-stream"); self.send_header("connection", "close"); self.end_headers()
        def ev(d): self.wfile.write(b"data: " + json.dumps(d).encode() + b"\n\n"); self.wfile.flush()
        base = {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m"}
        sent = 0
        try:
            for i in range(count):
                ev({**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": pad + str(i)}, "finish_reason": None}]}); sent += 1  # LiteLLM cuts a run of identical chunks
                time.sleep(delay)
            ev({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1000, "completion_tokens": 1000, "total_tokens": 2000}})
            self.wfile.write(b"data: [DONE]\n\n"); self.wfile.flush()
            print("upstream finished", sent, flush=True)
        except OSError:
            print("upstream cut after", sent, flush=True)
        self.close_connection = True
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
S(("", 9000), H).serve_forever()
