"""Optional HA-native administrator, disabled unless explicitly configured."""
from __future__ import annotations

import probatio as vol
from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.helpers import config_validation as cv

from .auth import NativeIdentity
from .backend import HABackend, create_session
from .engine import Administrator
from .model import DOMAIN, AdminError
from .store import TaskStore
from .diagnostics import register as register_diagnostics
from .approval import register_approval_commands
from .llm_api import AdminAPI
from homeassistant.helpers import llm

CONFIG_SCHEMA = vol.Schema({vol.Optional(DOMAIN): {
    vol.Required("backend_url"): cv.string,
    vol.Required("caller_user_ids"): [cv.string],
    vol.Required("caller_client_ids"): [cv.string],
    vol.Required("approver_client_ids"): [cv.string],
    vol.Optional("approval_panel", default=True): cv.boolean,
}}, extra=vol.ALLOW_EXTRA)


async def async_setup(hass, config):
    if DOMAIN not in config:
        return True
    policy = config[DOMAIN]
    from homeassistant.const import __version__
    from awesomeversion import AwesomeVersion
    if not AwesomeVersion("2026.10.0") <= AwesomeVersion(__version__) < AwesomeVersion("2026.11.0"):
        raise AdminError("unsupported_core_version_use_reviewed_2026_10")
    if any(not policy[key] for key in ("caller_user_ids", "caller_client_ids", "approver_client_ids")) or set(policy["caller_client_ids"]) & set(policy["approver_client_ids"]):
        raise AdminError("explicit_disjoint_client_policy_required")
    store = await hass.async_add_executor_job(TaskStore, hass.config.path(".storage", DOMAIN))
    await hass.async_add_executor_job(store.retire_grants)
    session = create_session()
    unregister = None
    remove_diagnostics = register_diagnostics()
    try:
        backend = HABackend(policy["backend_url"], session)
        from urllib.parse import urlsplit
        if urlsplit(policy["backend_url"]).port != hass.http.server_port:
            raise AdminError("backend_must_be_this_home_assistant_server")
        identity = NativeIdentity(hass, policy)
        engine = Administrator(store, backend, policy, identity.caller, identity.approved_session)
        if policy["approval_panel"]:
            from .panel import register_panel
            await register_panel(hass)
        unregister = llm.async_register_api(hass, AdminAPI(hass, engine, identity))
        register_approval_commands(hass, engine, identity)
    except BaseException:
        if unregister is not None:
            unregister()
        remove_diagnostics()
        await session.close()
        raise
    hass.data[DOMAIN] = {"engine": engine, "identity": identity, "session": session}
    async def stop(_event):
        unregister()
        remove_diagnostics()
        await session.close()
    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    return True
