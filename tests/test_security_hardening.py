"""Deterministic local-only tests for HA-MCP URL and probe security."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest import TestCase
from unittest.mock import patch

from custom_components.hass_codex_tunnel_mcp import mcp_url


class Handler(BaseHTTPRequestHandler):
    calls = []
    redirect_port = 0

    def do_GET(self):
        type(self).calls.append((self.path, self.headers.get("Authorization", "")))
        code = {"/unauthorized": 401, "/forbidden": 403, "/missing": 404,
                "/error": 503, "/method": 405, "/oauth": 401,
                "/redirect": 302, "/redirect-cross": 302, "/ok": 200}.get(self.path, 404)
        self.send_response(code)
        if code == 302:
            port = self.redirect_port if self.path == "/redirect-cross" else self.server.server_address[1]
            self.send_header("Location", f"http://127.0.0.1:{port}/ok")
        self.end_headers()
        self.wfile.write(b"probe")

    def log_message(self, *args):
        pass


class TestProbeSecurity(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Handler.redirect_port = cls.redirect_server.server_address[1]
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.redirect_thread = Thread(target=cls.redirect_server.serve_forever, daemon=True)
        cls.thread.start()
        cls.redirect_thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.fake_token = "test-only-placeholder"

    @classmethod
    def tearDownClass(cls):
        for server, thread in ((cls.server, cls.thread), (cls.redirect_server, cls.redirect_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def setUp(self):
        Handler.calls.clear()

    def test_unauthorized_bearer_fails_closed(self):
        with self.assertRaisesRegex(mcp_url.MCPUrlError, "mcp_auth_rejected"):
            mcp_url._probe_mcp_url(self.url + "/unauthorized", 2, self.fake_token)
        self.assertEqual(Handler.calls[0][1], "Bearer " + self.fake_token)

    def test_forbidden_bearer_fails_closed(self):
        with self.assertRaisesRegex(mcp_url.MCPUrlError, "mcp_auth_rejected"):
            mcp_url._probe_mcp_url(self.url + "/forbidden", 2, self.fake_token)

    def test_oauth_challenge_without_bearer_remains_compatible(self):
        mcp_url._probe_mcp_url(self.url + "/oauth", 2, "")

    def test_cross_origin_redirect_blocks_token(self):
        with self.assertRaisesRegex(mcp_url.MCPUrlError, "mcp_probe_redirect_rejected"):
            mcp_url._probe_mcp_url(self.url + "/redirect-cross", 2, self.fake_token)
        self.assertEqual([path for path, _ in Handler.calls], ["/redirect-cross"])

    def test_same_origin_redirect_rejected(self):
        with self.assertRaisesRegex(mcp_url.MCPUrlError, "mcp_probe_redirect_rejected"):
            mcp_url._probe_mcp_url(self.url + "/redirect", 2, self.fake_token)
        self.assertEqual([path for path, _ in Handler.calls], ["/redirect"])

    def test_redirect_without_bearer_rejected(self):
        with self.assertRaisesRegex(mcp_url.MCPUrlError, "mcp_probe_redirect_rejected"):
            mcp_url._probe_mcp_url(self.url + "/redirect-cross", 2, "")
        self.assertEqual([path for path, _ in Handler.calls], ["/redirect-cross"])

    def test_missing_and_server_error_rejected(self):
        for path in ("/missing", "/error"):
            with self.subTest(path=path), self.assertRaises(mcp_url.MCPUrlError):
                mcp_url._probe_mcp_url(self.url + path, 2, self.fake_token)

    def test_mcp_get_405_keeps_compatibility(self):
        mcp_url._probe_mcp_url(self.url + "/method", 2, self.fake_token)

    def test_private_http_allowed(self):
        self.assertTrue(mcp_url.assess_mcp_url(self.url + "/private").is_local_or_private)

    def test_public_http_denied_when_dns_uncertain(self):
        with patch.object(mcp_url, "_is_private_or_local", return_value=False):
            with self.assertRaisesRegex(mcp_url.MCPUrlError, "insecure_public_mcp_url"):
                mcp_url.assess_mcp_url("http://example.net/path")

    def test_public_https_retains_warning(self):
        with patch.object(mcp_url, "_is_private_or_local", return_value=False):
            self.assertEqual(mcp_url.assess_mcp_url("https://example.net/private").warning, "public_mcp_url")

    def test_redaction_removes_path_and_query(self):
        result = mcp_url.redact_mcp_url(self.url + "/fake-secret?key=fake")
        self.assertNotIn("fake-secret", result)
        self.assertNotIn("key=fake", result)
