"""Owned loopback forwarding fixture, not an OpenAI control-plane emulator.

The child exposes actual HTTP readiness and forwards bounded MCP POSTs only to
its configured loopback backend. No tunnel credentials are sent anywhere.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import sys
import threading
from urllib.parse import urlsplit

from admin_network_guard import install
install()

args = sys.argv
health_file = Path(args[args.index("--health.url-file")+1])
backend = args[args.index("--mcp.server-url")+1].split("url=", 1)[1]
parsed = urlsplit(backend)
if parsed.hostname not in ("127.0.0.1", "::1") or parsed.scheme != "http":
    raise SystemExit(2)


poll_counts = {200: 0, 401: 0, 503: 0}
poll_lock = threading.Lock()


def mode():
    state = os.environ.get("ADMIN_TRANSPORT_STATE_FILE")
    return Path(state).read_text().strip() if state else "ready"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/readyz":
            self.respond(503 if mode() == "disconnected" else 200, {"ready": mode() != "disconnected"})
        elif self.path == "/metrics":
            category = mode()
            with poll_lock:
                poll_counts[401 if category == "auth-denied" else 503 if category == "provider-unavailable" else 200] += 1
                raw = "\n".join('http_client_request_duration_seconds_count{http_route="/v1/tunnels/synthetic/poll",http_response_status_code="'+str(status)+'"} '+str(count) for status, count in poll_counts.items()).encode()
            self.send_response(200);self.send_header("Content-Length", str(len(raw)));self.end_headers();self.wfile.write(raw)
        elif self.path == "/health?details=true":
            self.respond(404, {})  # Bundled v0.0.10 has no component health JSON.
        else:
            self.respond(404, {})

    def do_POST(self):
        if self.path != "/mcp":
            self.respond(404, {}); return
        size = int(self.headers.get("Content-Length", "0"))
        if size > 131072:
            self.respond(413, {}); return
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=4)
        try:
            connection.request("POST", parsed.path, self.rfile.read(size), {
                "Authorization": os.environ.get("HA_MCP_AUTH_HEADER", ""),
                "Content-Type": "application/json", "Accept": "application/json"})
            response = connection.getresponse()
            raw = response.read(131073)
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
        except OSError:
            self.respond(503, {"error": "fixture_backend_unavailable"})
        finally:
            connection.close()


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
health_file.write_text(f"http://127.0.0.1:{server.server_port}")
server.serve_forever()
