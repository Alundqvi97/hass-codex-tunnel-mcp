"""Representative MCP JSON-RPC authentication CONTRACT tests, loopback-only.

These test a disposable fixture, NOT the installed HA-MCP server or the
proprietary tunnel-client. They prove our staging harness rejects anonymous,
expired, revoked, underscoped, and invalid requests, and expose that a GET
probe cannot prove any of these properties. No real credentials are used.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from custom_components.hass_codex_tunnel_mcp.mcp_url import _probe_mcp_url

TOKENS = {
    "fixture-reader": {"scope": "mcp:read", "active": True},
    "fixture-no-scope": {"scope": "", "active": True},
    "fixture-expired": {"scope": "mcp:read", "active": False},
    "fixture-revoked": {"scope": "mcp:read", "active": False},
}


class MCPFixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, code, result):
        b = json.dumps(result).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        # GET route rejects even authorized and unauthenticated requests alike.
        self._reply(405, {"error": "POST only"})

    def do_POST(self):
        raw = self.headers.get("Authorization", "")
        token = raw.removeprefix("Bearer ") if raw.startswith("Bearer ") else ""
        info = TOKENS.get(token)
        if not info or not info["active"]:
            return self._reply(401, {"error": "unauthorized"})
        if info["scope"] != "mcp:read":
            return self._reply(403, {"error": "insufficient_scope"})
        if self.headers.get("Content-Type") != "application/json":
            return self._reply(415, {"error": "bad_content_type"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size < 2048:
                return self._reply(400, {"error": "invalid_length"})
            obj = json.loads(self.rfile.read(size))
            method = obj.get("method")
            request_id = obj.get("id", 1)
        except (ValueError, json.JSONDecodeError):
            return self._reply(400, {"error": "invalid_payload"})
        if method == "initialize":
            return self._reply(200, {"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "local-fixture", "version": "1.0"}}})
        if method == "tools/list":
            return self._reply(200, {"jsonrpc": "2.0", "id": request_id, "result": {
                "tools": [{"name": "fixture_read_status", "inputSchema": {"type": "object"}}]}})
        if method == "tools/call" and obj.get("params", {}).get("name") == "fixture_read_status":
            return self._reply(200, {"jsonrpc": "2.0", "id": request_id,
                                     "result": {"content": [{"type": "text", "text": "synthetic-ok"}]}})
        return self._reply(403, {"error": "tool_denied"})

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), MCPFixture)
    srv.daemon_threads = True
    thread = Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3)


def post(url, token, method, params=None, content_type="application/json"):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}).encode()
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=2) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.mark.parametrize("method", ["initialize", "tools/list", "tools/call"])
def test_fixture_accepts_valid_read_only_mcp_protocol(server, method):
    code, result = post(server, "fixture-reader", method,
                        {"name": "fixture_read_status"} if method == "tools/call" else {})
    assert code == 200
    assert "result" in result


@pytest.mark.parametrize("token", [None, "", "wrong", "fixture-expired", "fixture-revoked"])
def test_fixture_rejects_missing_bad_expired_revoked_on_each_request(server, token):
    for method in ("initialize", "tools/list", "tools/call"):
        code, _ = post(server, token, method, {"name": "fixture_read_status"})
        assert code == 401, (token, method, code)


def test_fixture_enforces_scope_and_disallows_unlisted_write_tool(server):
    assert post(server, "fixture-no-scope", "tools/list")[0] == 403
    tools = post(server, "fixture-reader", "tools/list")[1]["result"]["tools"]
    assert [t["name"] for t in tools] == ["fixture_read_status"]
    assert post(server, "fixture-reader", "tools/call", {"name": "ha_call_service"})[0] == 403


def test_fixture_rejects_malformed_headers(server):
    assert post(server, "fixture-reader", "initialize", content_type="text/plain")[0] == 415


def test_get_startup_probe_can_pass_despite_invalid_bearer_for_mcp_post(server):
    # This is an explicit INCONCLUSIVE-startup-probe case, not a security pass.
    _probe_mcp_url(server, timeout=2, bearer_token="wrong")
    assert post(server, "wrong", "initialize")[0] == 401
