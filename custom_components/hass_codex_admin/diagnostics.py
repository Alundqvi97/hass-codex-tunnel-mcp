"""Suppress native protocol payload logging for this administrator route only."""
import logging

from homeassistant.helpers.http import current_request


class PayloadFilter(logging.Filter):
    def filter(self, record):
        request = current_request.get()
        if request is not None and request.path == "/api/mcp/hass_codex_admin":
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
        "mcp.server.lowlevel.server", "mcp.shared.session")]
    for logger in loggers:
        logger.addFilter(guard)
    def remove():
        for logger in loggers:
            logger.removeFilter(guard)
    return remove
