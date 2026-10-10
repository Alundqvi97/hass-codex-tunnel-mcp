"""Suppress native protocol payload logging for this administrator route only."""
import logging

from homeassistant.helpers.http import current_request


class PayloadFilter(logging.Filter):
    def filter(self, record):
        request = current_request.get()
        sensitive = record.name == "homeassistant.components.websocket_api.http.connection" and any(key in record.getMessage() for key in ("access_token", "connector_credential", "hca_", "hass_codex_admin/flow"))
        if sensitive or request is not None and request.path in {"/api/mcp/hass_codex_admin", "/api/hass_codex_admin/mcp"}:
            record.msg = "Administrator protocol diagnostic; payload omitted"
            record.args = ()
            record.exc_info = None
            record.stack_info = None
            record.exc_text = None
        return True


def register():
    guard = PayloadFilter()
    loggers = [logging.getLogger(name) for name in (
        "homeassistant.components.mcp_server.http", "homeassistant.components.mcp_server.server",
        "mcp.server.lowlevel.server", "mcp.shared.session", "homeassistant.components.websocket_api.http.connection")]
    for logger in loggers:
        logger.addFilter(guard)
    def remove():
        for logger in loggers:
            logger.removeFilter(guard)
    return remove
