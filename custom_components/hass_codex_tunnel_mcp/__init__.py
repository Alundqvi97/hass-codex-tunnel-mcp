"""OpenAI Tunnel for HA-MCP integration."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant, ServiceCall

from .binary import TunnelClientError, UnsupportedPlatformError
from .const import (
    BIN_DIR_NAME,
    CONF_HA_MCP_BEARER_TOKEN,
    CONF_ADMIN_CONNECTION_ID,
    CONF_HA_MCP_URL,
    DOMAIN,
    PLATFORMS,
    RUN_DIR_NAME,
    STORAGE_DIR,
)
from .mcp_url import MCPUrlError, assess_mcp_url, async_probe_mcp_url
from .repairs import create_issue, delete_issue
from .tunnel import TunnelManager
from .updater import TunnelClientUpdater

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: "HomeAssistant", entry: "ConfigEntry") -> bool:
    """Every failed/cancelled activation releases its owned resources."""
    try:
        return await _async_activate_entry(hass, entry)
    except BaseException:
        runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
        if runtime is not None:
            await runtime["tunnel"].close()
            runtime.get("remove_stop", lambda: None)()
            hass.data[DOMAIN].pop(entry.entry_id, None)
        raise


async def _async_activate_entry(hass: "HomeAssistant", entry: "ConfigEntry") -> bool:
    """Set up OpenAI Tunnel for HA-MCP."""
    from homeassistant.exceptions import ConfigEntryNotReady

    hass.data.setdefault(DOMAIN, {})
    storage_dir = Path(hass.config.path(STORAGE_DIR))
    bin_root = storage_dir / BIN_DIR_NAME
    run_dir = storage_dir / RUN_DIR_NAME / entry.entry_id

    def notify() -> None:
        runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
        if runtime is not None:
            for callback in runtime.get("listeners", []):
                callback()

    updater = TunnelClientUpdater(hass, entry, bin_root, notify)
    await updater.async_load()

    async def executable_provider(force: bool):
        return await updater.ensure_active_executable(force=force)

    def credential_provider(data):
        identifier = str(data.get(CONF_ADMIN_CONNECTION_ID) or "")
        if not identifier:
            return str(data.get(CONF_HA_MCP_BEARER_TOKEN) or "").strip()
        from urllib.parse import urlsplit
        if urlsplit(str(data[CONF_HA_MCP_URL])).path != "/api/hass_codex_admin/mcp" or str(data.get(CONF_HA_MCP_BEARER_TOKEN) or "").strip():
            raise MCPUrlError("admin_connection_requires_scoped_route_without_static_token")
        administrator = hass.data.get("hass_codex_admin")
        if administrator is None:
            raise MCPUrlError("native_administrator_not_ready")
        if str(data[CONF_HA_MCP_URL]) != administrator["engine"].backend.base+"/api/hass_codex_admin/mcp":
            raise MCPUrlError("admin_connection_requires_this_loopback_server")
        return administrator["identity"].transport_credential(identifier)

    tunnel = TunnelManager(executable_provider, run_dir, notify, credential_provider=credential_provider)
    hass.data[DOMAIN][entry.entry_id] = {
        "tunnel": tunnel,
        "updater": updater,
        "listeners": [],
        "entry_data": _entry_data_factory(entry),
    }

    from homeassistant.const import EVENT_HOMEASSISTANT_STOP
    async def stop(_event):
        await tunnel.close()
    remove_stop = hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    hass.data[DOMAIN][entry.entry_id]["remove_stop"] = remove_stop
    entry.async_on_unload(remove_stop)

    try:
        try:
            entry_data = {**entry.data, **entry.options}
            assessment = assess_mcp_url(str(entry_data[CONF_HA_MCP_URL]))
            await async_probe_mcp_url(
                assessment.url,
                bearer_token=credential_provider(entry_data),
            )
        except MCPUrlError as err:
            await create_issue(
                hass,
                "mcp_url_unreachable",
                "mcp_url_unreachable",
                {"url": assessment.redacted_url if "assessment" in locals() else ""},
            )
            raise
        if assessment.warning is not None:
            await create_issue(
                hass,
                "mcp_url_warning",
                assessment.warning,
                {"url": assessment.redacted_url},
            )
        else:
            await delete_issue(hass, "mcp_url_warning")

        try:
            await tunnel.start({**entry.data, **entry.options})
        except TunnelClientError as err:
            await create_issue(
                hass,
                "binary_download_failed",
                "binary_download_failed",
                {"error": str(err)},
            )
            raise
    except UnsupportedPlatformError as err:
        await create_issue(
            hass,
            "unsupported_arch",
            "unsupported_arch",
            {"platform": str(err)},
        )
        raise ConfigEntryNotReady(f"unsupported platform for tunnel-client: {err}") from err
    except Exception as err:
        _LOGGER.exception("Failed to start OpenAI Tunnel for HA-MCP")
        await create_issue(
            hass,
            "startup_failed",
            "startup_failed",
            {"error": str(err)},
        )
        raise ConfigEntryNotReady(str(err)) from err

    await delete_issue(hass, "startup_failed")
    await delete_issue(hass, "unsupported_arch")
    await delete_issue(hass, "binary_download_failed")
    await delete_issue(hass, "mcp_url_unreachable")
    await _async_register_services(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    await updater.async_start_auto_update(tunnel, _entry_data_factory(entry))
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: "HomeAssistant", entry: "ConfigEntry") -> bool:
    """Unload the integration."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if not unload_ok:
        return False
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if runtime is not None:
        await runtime["tunnel"].close()
        runtime.get("remove_stop", lambda: None)()
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return True


async def _async_update_listener(hass: "HomeAssistant", entry: "ConfigEntry") -> None:
    """Reload when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def _async_register_services(hass: "HomeAssistant") -> None:
    """Register integration services once."""
    if hass.data[DOMAIN].get("_services_registered"):
        return

    async def restart_tunnel(call: "ServiceCall") -> None:
        for runtime in _matching_runtimes(hass, call):
            await runtime["tunnel"].restart(runtime["entry_data"]())

    async def redownload_tunnel_client(call: "ServiceCall") -> None:
        for runtime in _matching_runtimes(hass, call):
            await runtime["tunnel"].redownload(runtime["entry_data"]())

    async def check_tunnel_client_update(call: "ServiceCall") -> None:
        for runtime in _matching_runtimes(hass, call):
            await runtime["updater"].async_check_for_update()

    async def update_tunnel_client(call: "ServiceCall") -> None:
        for runtime in _matching_runtimes(hass, call):
            await runtime["updater"].async_update_tunnel_client(
                runtime["tunnel"], runtime["entry_data"]()
            )

    async def rollback_tunnel_client(call: "ServiceCall") -> None:
        for runtime in _matching_runtimes(hass, call):
            await runtime["updater"].async_rollback(
                runtime["tunnel"], runtime["entry_data"]()
            )

    from homeassistant.helpers.service import async_register_admin_service
    async_register_admin_service(hass, DOMAIN, "restart_tunnel", restart_tunnel)
    async_register_admin_service(
        hass, DOMAIN, "redownload_tunnel_client", redownload_tunnel_client
    )
    async_register_admin_service(
        hass, DOMAIN, "check_tunnel_client_update", check_tunnel_client_update
    )
    async_register_admin_service(hass, DOMAIN, "update_tunnel_client", update_tunnel_client)
    async_register_admin_service(
        hass, DOMAIN, "rollback_tunnel_client", rollback_tunnel_client
    )
    hass.data[DOMAIN]["_services_registered"] = True


def _matching_runtimes(hass: "HomeAssistant", call: "ServiceCall"):
    entry_id = call.data.get("entry_id")
    for key, runtime in hass.data[DOMAIN].items():
        if key == "_services_registered":
            continue
        if entry_id is None or key == entry_id:
            yield runtime


def _entry_data_factory(entry: "ConfigEntry"):
    return lambda: {**entry.data, **entry.options}
