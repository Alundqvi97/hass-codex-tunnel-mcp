"""Use real HA user/refresh-token identities, never caller-supplied claims."""
from homeassistant.auth.models import TOKEN_TYPE_NORMAL
from homeassistant.components.http import KEY_HASS_USER, KEY_HASS_REFRESH_TOKEN_ID
from homeassistant.helpers.http import current_request

from .model import Actor, AdminError


class NativeIdentity:
    def __init__(self, hass, policy):
        self.hass, self.policy = hass, policy

    def caller(self, bearer):
        token = self.hass.auth.async_validate_access_token(bearer)
        if token is None or token.token_type != TOKEN_TYPE_NORMAL or not token.user.is_active or not token.user.is_admin:
            raise AdminError("authenticated_ha_admin_session_required")
        if token.user.id not in self.policy["caller_user_ids"] or token.client_id not in self.policy["caller_client_ids"]:
            raise AdminError("caller_not_allowed")
        return Actor(token.user.id, token.id, bearer)

    def for_context(self, llm_context):
        request = current_request.get()
        if request is None or request.method != "POST" or request.path != "/api/mcp/hass_codex_admin" or llm_context.context is None:
            raise AdminError("dedicated_authenticated_mcp_route_required")
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            raise AdminError("bearer_session_required")
        actor = self.caller(header[7:])
        if actor.user != llm_context.context.user_id or actor.user != request[KEY_HASS_USER].id or actor.session != request[KEY_HASS_REFRESH_TOKEN_ID]:
            raise AdminError("native_identity_mismatch")
        return actor

    def approver(self, connection):
        return self.approved_session(connection.refresh_token_id)

    def approved_session(self, session):
        token = self.hass.auth.async_get_refresh_token(session)
        if token is None or token.token_type != TOKEN_TYPE_NORMAL or not token.user.is_active or not token.user.is_owner or token.client_id not in self.policy["approver_client_ids"]:
            raise AdminError("owner_frontend_session_required")
        # client_id is enrolled OAuth metadata, not proof of human presence.
        # Owner authentication, independent session and explicit UI decision
        # are the authority. The MCP route cannot enroll or approve anything.
        return Actor(token.user.id, token.id, "")
