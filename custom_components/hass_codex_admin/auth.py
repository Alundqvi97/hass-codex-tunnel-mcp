"""Separate connector capabilities from native HA owner credentials.

A connector is a provisioned connection, never proof of a human or OAuth client.
Its opaque token is deliberately not a native HA access token. Native credentials
are minted only for the fixed loopback backend and never leave that adapter.
"""
import asyncio
from contextvars import ContextVar
import hashlib
import secrets
import time
import uuid

from homeassistant.auth.models import TOKEN_TYPE_NORMAL
from homeassistant.helpers.http import current_request

from .model import Actor, AdminError

CONNECTOR_PATH = "/api/hass_codex_admin/mcp"
_connector = ContextVar("verified_admin_connector", default=None)


class NativeIdentity:
    def __init__(self, hass, policy, store, connectors):
        self.hass, self.policy, self.store = hass, policy, store
        self.connectors = {r["digest"]: r for r in connectors}

    def caller(self, bearer):
        if not isinstance(bearer, str) or not bearer.startswith("hca_") or len(bearer) != 47:
            raise AdminError("connector_authentication_required")
        row = self.connectors.get(hashlib.sha256(bearer.encode()).hexdigest())
        if row is None or time.time() >= row["expires"]:
            raise AdminError("connector_revoked_or_expired")
        self.approved_session(row["owner_session"])
        return Actor("connector:"+row["id"], row["id"], bearer)

    def backend_bearer(self, actor):
        self.caller(actor.bearer)
        row = self.connectors[hashlib.sha256(actor.bearer.encode()).hexdigest()]
        # Owner logout/removal is checked on every backend request and dispatch.
        owner = self.approved_session(row["owner_session"])
        token = self.hass.auth.async_get_refresh_token(owner.session)
        return self.hass.auth.async_create_access_token(token)

    def transport_credential(self, identifier):
        """Trusted in-process transport setup only; never an RPC operation."""
        row = next((r for r in self.connectors.values() if r["id"] == identifier), None)
        if row is None:
            raise AdminError("connector_revoked_or_expired")
        self.caller(row["credential"])
        return row["credential"]

    def for_context(self, llm_context):
        request = current_request.get()
        actor = _connector.get()
        if request is None or request.method != "POST" or request.path != CONNECTOR_PATH or actor is None or llm_context.context is None:
            raise AdminError("dedicated_connector_route_required")
        actual = self.caller(actor.bearer)
        if actual != actor or llm_context.context.user_id != actor.user:
            raise AdminError("connector_identity_mismatch")
        return actual

    async def issue(self, owner, label, days):
        self.approved_session(owner.session)
        identifier, bearer = uuid.uuid4().hex, "hca_"+secrets.token_urlsafe(32)
        row = {"id": identifier, "digest": hashlib.sha256(bearer.encode()).hexdigest(), "owner_session": owner.session, "expires": time.time()+days*86400, "label": label}
        try:
            await self.hass.async_add_executor_job(self.store.save_connector, identifier, row["digest"], owner.session, row["expires"], label)
            self.approved_session(owner.session)
            await self.hass.async_add_executor_job(self.store.confirm_connector, identifier)
            self.approved_session(owner.session)
        except BaseException:
            # Shield durable deny from cancellation. The marker remains until
            # boot and defeats executor jobs that commit after this coroutine.
            cleanup = asyncio.ensure_future(self.hass.async_add_executor_job(self.store.revoke_connector, identifier))
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    continue
            try:
                cleanup.result()
            except (AdminError, OSError):
                raise AdminError("connector_issuance_cleanup_incomplete") from None
            raise
        row["credential"] = bearer
        self.connectors[row["digest"]] = row
        return {"id": identifier, "connector_credential": bearer, "expires": row["expires"], "path": CONNECTOR_PATH}

    async def revoke(self, identifier):
        # Revoke memory first: persistence failure must not keep active authority.
        self.connectors = {k:r for k,r in self.connectors.items() if r["id"] != identifier}
        try:
            await self.hass.async_add_executor_job(self.store.revoke_connector, identifier)
        except OSError:
            raise AdminError("connector_revocation_incomplete") from None

    def approver(self, connection):
        return self.approved_session(connection.refresh_token_id)

    def approved_session(self, session):
        token = self.hass.auth.async_get_refresh_token(session)
        if token is None or token.token_type != TOKEN_TYPE_NORMAL or not token.user.is_active or not token.user.is_owner or token.client_id not in self.policy["approver_client_ids"] or token.expire_at is not None and time.time() >= token.expire_at:
            raise AdminError("owner_frontend_session_required")
        return Actor(token.user.id, token.id, "")
