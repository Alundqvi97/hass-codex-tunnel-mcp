"""Finite native Supervisor operations; no generic proxy, shell or host access."""
import re
from .model import AdminError

ADDON_ACTIONS = {"hassio.addon_start": "start", "hassio.addon_stop": "stop", "hassio.addon_restart": "restart", "hassio.addon_update": "update"}


def read_command(command):
    return command.get("type") == "supervisor/api" and command.get("method") == "get" and set(command) == {"type", "method", "endpoint"} and bool(re.fullmatch(r"/(?:addons/[a-z0-9_]+/info|core/info|jobs/info)", command.get("endpoint", "")))


def endpoint(op):
    if op["target"] in ADDON_ACTIONS:
        return "/addons/"+op["value"]["addon"]
    if op["target"] == "hassio.core_update":
        return "/core"
    raise AdminError("unsupported_supervisor_operation")


async def snapshot(backend, actor, op):
    try:
        data = await backend.ws(actor, {"type": "supervisor/api", "method": "get", "endpoint": endpoint(op)+"/info"})
    except AdminError as exc:
        if exc.code == "backend_unsupported":
            raise AdminError("maintenance_not_available_on_this_installation") from None
        raise
    # Do not expose Supervisor options, tokens, environment or credentials.
    state = {key: data[key] for key in ("slug", "state", "version", "version_latest") if key in data}
    if not state.get("version"):
        raise AdminError("supervisor_identity_unavailable")
    if op["target"] in ADDON_ACTIONS and state.get("slug") != op["value"]["addon"]:
        raise AdminError("supervisor_target_identity_changed")
    if op["target"] == "hassio.core_update" and state.get("version_latest") != op["value"]["version"]:
        raise AdminError("approved_update_version_unavailable")
    return state


async def write(backend, actor, op):
    action = ADDON_ACTIONS.get(op["target"], "update")
    payload = {"backup": True} if action == "update" else {}
    if op["target"] == "hassio.core_update":
        payload["version"] = op["value"]["version"]
    path = "/store"+endpoint(op) if op["target"] == "hassio.addon_update" else endpoint(op)
    result = await backend.ws(actor, {"type": "supervisor/api", "method": "post", "endpoint": path+"/"+action, "data": payload})
    # Retain only a possible official job identity. Absence or later disappearance
    # never becomes a successful job. Lost acknowledgements are not retried.
    identifier = result.get("job_id") if isinstance(result, dict) else None
    if identifier is not None and not isinstance(identifier, str):
        raise AdminError("supervisor_job_identity_invalid")
    return {"job_id": identifier, "supervisor_acknowledged": True}


def verified(op, before, after, result):
    if op["target"].endswith("update"):
        desired = after.get("version_latest") if op["target"] == "hassio.addon_update" else op["value"]["version"]
        return after.get("version") == desired and after.get("version") != before.get("version")
    if op["target"] == "hassio.addon_start":
        return before.get("state") == "stopped" and after.get("state") == "started"
    if op["target"] == "hassio.addon_stop":
        return before.get("state") == "started" and after.get("state") == "stopped"
    # The selected info API has no process-incarnation fact. Running again does
    # not prove a restart; leave this operation uncertain rather than fabricate it.
    return False
