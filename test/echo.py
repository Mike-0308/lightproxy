import sys, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
tag = sys.argv[2]

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        body = json.dumps({
            "backend": tag,
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host"),
            "xff": self.headers.get("X-Forwarded-For"),
            "xreal": self.headers.get("X-Real-IP"),
            "custom": self.headers.get("X-Test"),
            "body": raw.decode("utf-8", "replace"),
        }, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _send
    do_POST = _send
    do_PUT = _send

    def log_message(self, *a):
        pass

ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
