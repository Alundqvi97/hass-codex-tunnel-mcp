"""Narrow credential adapter to Core's maintained stateless MCP implementation.

No OAuth provider, cookie login, proxy routes or native HA bearer acceptance.
Core 2026.10 is pinned and connected tests cover this versioned adapter seam.
"""
import asyncio
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.components.mcp_server.http import _async_handle_streamable_message
from homeassistant.core import Context

from .auth import CONNECTOR_PATH, _connector
from .model import AdminError, decode


class ConnectorView(HomeAssistantView):
    url = CONNECTOR_PATH
    name = "hass_codex_admin:connector"
    requires_auth = False  # This resource verifies its own distinct credentials.

    def __init__(self, identity):
        self.identity = identity
        self.capacity = asyncio.Semaphore(8)

    async def post(self, request):
        header = request.headers.get("Authorization", "")
        try:
            actor = self.identity.caller(header[7:] if header.startswith("Bearer ") else "")
        except AdminError:
            raise web.HTTPUnauthorized(headers={"WWW-Authenticate": 'Bearer realm="hass-codex-admin"'}) from None
        # Do not follow paths/redirects or accept user identity from headers.
        if request.path != CONNECTOR_PATH or request.query_string:
            raise web.HTTPBadRequest()
        try:
            async with asyncio.timeout(2):
                await self.capacity.acquire()
        except TimeoutError:
            raise web.HTTPServiceUnavailable() from None
        token = _connector.set(actor)
        try:
            # Strict bounded JSON validation, including duplicate key rejection.
            async with asyncio.timeout(5):
                raw = await request.content.readexactly(131073)
        except asyncio.IncompleteReadError as exc:
            raw = exc.partial
        except BaseException:
            _connector.reset(token)
            self.capacity.release()
            raise
        try:
            if len(raw) > 131072:
                raise web.HTTPRequestEntityTooLarge(max_size=131072, actual_size=len(raw))
            decode(raw)
            request._read_bytes = raw  # aiohttp cache; Core performs MCP validation.
            return await _async_handle_streamable_message(request, Context(user_id=actor.user), "hass_codex_admin")
        except AdminError:
            raise web.HTTPBadRequest() from None
        finally:
            _connector.reset(token)
            self.capacity.release()
