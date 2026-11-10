"""Tiny target web app that writes an Nginx-style combined access log, for live detection tests.

  python3 tools/demo_web.py --port 8080 --log /tmp/minisiem-access.log
"""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"<!doctype html><title>Demo shop</title><h1>Demo shop</h1><a href='/login'>login</a>"


def q(value) -> str:
    """Quote a log field the way nginx does: '-' when empty, escape double quotes and backslashes."""
    s = str(value or "-")
    return s.replace("\\", "\\x5C").replace('"', "\\x22")


class Handler(BaseHTTPRequestHandler):
    log_path = "access.log"

    def respond(self, code: int, body: bytes = b"") -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._size = len(body)

    def do_GET(self):
        self.respond(200, PAGE) if self.path in ("/", "/index.html") else self.respond(404, b"not found")

    def do_POST(self):
        self.respond(401, b"invalid credentials") if self.path == "/login" else self.respond(404, b"not found")

    def log_request(self, code="-", size="-"):
        ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = (f'{self.client_address[0]} - - [{ts}] "{q(self.requestline)}" {int(code)} {size if size != "-" else 0} '
                f'"{q(self.headers.get("Referer"))}" "{q(self.headers.get("User-Agent"))}"\n')
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)

    def log_message(self, fmt, *args):  # keep stderr quiet; the access log is the record
        pass


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--log", default="access.log")
    a = p.parse_args()
    Handler.log_path = a.log
    print(f"demo web app on http://{a.bind}:{a.port}, logging to {a.log}")
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
