"""Loopback control-plane substitute for the unmodified official tunnel client.

Only metadata, bounded poll and correlated responses are substituted. MCP is
real HTTP to the owned Core. No OpenAI/cloud control plane or accounts involved.
"""
import asyncio
from datetime import datetime, UTC
import os
from pathlib import Path
import uuid

from aiohttp import web


class OfficialTransport:
    def __init__(self, fixture, executable):
        self.fixture, self.executable = fixture, executable
        self.commands = asyncio.Queue(maxsize=8)
        self.pending = {}
        self.key = "synthetic-official-control-key"
        self.tunnel = "tunnel_"+"a"*32

    async def start(self):
        app = web.Application(client_max_size=131072)
        app.router.add_get("/v1/tunnels/{tunnel}", self.metadata)
        app.router.add_get("/v1/tunnels/{tunnel}/poll", self.poll)
        app.router.add_post("/v1/tunnels/{tunnel}/response", self.response)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        port = self.site._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        from custom_components.hass_codex_tunnel_mcp.tunnel import TunnelManager
        from custom_components.hass_codex_tunnel_mcp.const import CONF_ADMIN_CONNECTION_ID
        identity = self.fixture.hass.data["hass_codex_admin"]["identity"]
        self.manager = TunnelManager(lambda _: self.executable, self.fixture.root / "official-owner", retry_delays=(.05, .1, .2), poll_interval=.05, terminate_timeout=2, credential_provider=lambda data: identity.transport_credential(data[CONF_ADMIN_CONNECTION_ID]))
        self.entry = {"tunnel_id": self.tunnel, "api_key": self.key, "ha_mcp_url": self.fixture.base+"/api/hass_codex_admin/mcp", "admin_connection_id": identity.caller(self.fixture.bearer).session, "control_plane_base_url": self.base}
        await self.manager.start(self.entry)
        self.fixture.assertTrue(await self.manager.wait_until_healthy(5), self.manager.status)

    def authenticate(self, request):
        if request.match_info["tunnel"] != self.tunnel or request.headers.get("Authorization") != "Bearer "+self.key:
            raise web.HTTPUnauthorized()

    async def metadata(self, request):
        self.authenticate(request)
        return web.json_response({"id": self.tunnel, "name": "Owned loopback fixture", "auth": {"type": "NoOAuth"}})

    async def poll(self, request):
        self.authenticate(request)
        try:
            item = await asyncio.wait_for(self.commands.get(), .2)
        except TimeoutError:
            return web.Response(status=204)
        return web.json_response({"commands": [item]})

    async def response(self, request):
        self.authenticate(request)
        body = await request.json()
        saved = self.pending.get(body.get("request_id"))
        if saved is None or request.headers.get("X-Tunnel-Shard-Token") != saved[0]:
            raise web.HTTPForbidden()
        if not saved[1].done():
            saved[1].set_result(body)
        return web.json_response({})

    async def call(self, method, params=None):
        identifier = uuid.uuid4().hex
        shard = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self.pending[identifier] = (shard, future)
        await self.commands.put({"request_id": identifier, "shard_token": shard, "command_type": "jsonrpc", "channel": "main", "created_at": datetime.now(UTC).isoformat(), "response_timeout": "10s", "jsonrpc": {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}})
        try:
            body = await asyncio.wait_for(future, 12)
            self.fixture.assertEqual(body["resp_code"], 200, body)
            return body["resp_json"]
        finally:
            self.pending.pop(identifier, None)

    async def close(self):
        if hasattr(self, "manager"):
            await self.manager.close()
        if hasattr(self, "runner"):
            await self.runner.cleanup()
