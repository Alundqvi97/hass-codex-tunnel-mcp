"""Native HA-owner approval channel. Never exported as an MCP tool."""
import probatio as vol
from homeassistant.components import websocket_api

from .model import AdminError, redact


def register_approval_commands(hass, engine, identity):
    @websocket_api.websocket_command({vol.Required("type"): "hass_codex_admin/approval", vol.Required("action"): vol.In(["enroll", "list", "get", "approve", "revoke"]), vol.Optional("task"): str, vol.Optional("plan_hash"): str, vol.Optional("confirm_effects"): bool})
    @websocket_api.async_response
    async def approval(hass, connection, message):
        try:
            actor = identity.approver(connection)
            action = message["action"]
            if action == "enroll":
                await engine.db("enroll", actor)
                value = {"enrolled": True}
            elif action == "list":
                value = [redact(await engine.db("get", task)) for task in await engine.db("list_tasks")]
            elif action == "get":
                value = redact(await engine.db("get", message.get("task", "")))
            else:
                if action == "approve" and message.get("confirm_effects") is not True:
                    raise AdminError("explicit_effect_review_required")
                actor = identity.approver(connection)
                await engine.db("decide", message.get("task", ""), actor, message.get("plan_hash", ""), "approved" if action == "approve" else "revoked")
                value = {"decision": action}
            connection.send_result(message["id"], value)
        except AdminError as exc:
            connection.send_error(message["id"], exc.code, exc.code)
    websocket_api.async_register_command(hass, approval)
