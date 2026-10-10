"""Fixed Home Assistant API catalog. No filesystem editing or arbitrary proxy."""
from __future__ import annotations

import asyncio
import importlib
import ipaddress
import re
from datetime import date, time, timedelta
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import urlsplit

import aiohttp
import probatio as vol

from .model import AdminError, HELPERS, canonical, redact

_dispatch = ContextVar("hass_codex_admin_dispatch", default=None)
READ_COMMANDS = {"lovelace/config", "lovelace/dashboards/list", "config_entries/get", "config/entity_registry/get_entries", "trace/list", "trace/get", "backup/info", "backup/agents/info"} | {family+"/list" for family in HELPERS}


def create_session():
    trace = aiohttp.TraceConfig()
    async def deny_redirect(*_args):
        raise AdminError("backend_redirect_forbidden")
    trace.on_request_redirect.append(deny_redirect)
    return aiohttp.ClientSession(trust_env=False, trace_configs=[trace])


class HABackend:
    @contextmanager
    def dispatch(self, check):
        token = _dispatch.set(check)
        try:
            yield
        finally:
            _dispatch.reset(token)

    async def final_check(self):
        check = _dispatch.get()
        if check is None:
            raise AdminError("dispatch_grant_required")
        await check()

    def __init__(self, base_url, session, *, timeout=8, credential=None):
        self.flows = None
        self.runtime = None
        parsed = urlsplit(base_url)
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except (ValueError, TypeError):
            loopback = False
        if not loopback or parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise AdminError("literal_loopback_backend_required")
        self.base = base_url.rstrip("/")
        if session.trust_env:
            raise AdminError("backend_environment_proxies_forbidden")
        self.session, self.timeout = session, timeout
        self.credential = credential

    def bearer(self, actor):
        if self.credential is None:
            raise AdminError("backend_credential_custody_required")
        return self.credential(actor)

    async def rest(self, actor, method, path, data=None, *, missing=False, text=False):
        # One bounded reconnect for safe reads. Mutations always get one attempt.
        for attempt in range(2 if method == "GET" else 1):
            try:
                return await self._rest_once(actor, method, path, data, missing=missing, text=text)
            except AdminError as exc:
                if attempt or method != "GET" or exc.code != "backend_unavailable_or_timeout":
                    raise
                await asyncio.sleep(.05)

    async def _rest_once(self, actor, method, path, data=None, *, missing=False, text=False):
        # All call sites below supply constant prefixes and validated identifiers.
        try:
            async with asyncio.timeout(self.timeout):
                if method != "GET":
                    await self.final_check()
                async with self.session.request(method, self.base+path, json=data,
                    headers={"Authorization": "Bearer "+self.bearer(actor)}, allow_redirects=False) as response:
                    if missing and response.status == 404:
                        return None
                    if response.status in (401, 403):
                        raise AdminError("backend_authentication_or_permission")
                    if response.status >= 400 or response.status < 200 or response.status >= 300:
                        raise AdminError("backend_rejected")
                    try:
                        raw = await response.content.readexactly(131073)
                    except asyncio.IncompleteReadError as exc:
                        raw = exc.partial
                    if len(raw) > 131072:
                        raise AdminError("backend_reply_too_large")
                    from .model import decode
                    return raw.decode("utf-8", errors="replace") if text else decode(raw) if raw else None
        except (aiohttp.ClientError, TimeoutError):
            raise AdminError("backend_unavailable_or_timeout") from None

    async def ws(self, actor, command, *, missing=False):
        try:
            async with asyncio.timeout(self.timeout):
                async with self.session.ws_connect(self.base+"/api/websocket", max_msg_size=131072, heartbeat=None) as ws:
                    first = await ws.receive_json()
                    if not isinstance(first, dict) or first.get("type") != "auth_required":
                        raise AdminError("backend_protocol")
                    await ws.send_json({"type": "auth", "access_token": self.bearer(actor)})
                    authentication = await ws.receive_json()
                    if not isinstance(authentication, dict) or authentication.get("type") != "auth_ok":
                        raise AdminError("backend_authentication_or_permission")
                    from .supervisor import read_command
                    if command["type"] not in READ_COMMANDS and not read_command(command):
                        await self.final_check()
                    await ws.send_json({**command, "id": 1})
                    reply = await ws.receive_json()
                    if not isinstance(reply, dict) or reply.get("id") != 1 or reply.get("type") != "result":
                        raise AdminError("backend_protocol")
                    if not reply.get("success"):
                        code = reply.get("error", {}).get("code")
                        if missing and code in {"not_found", "config_not_found"}:
                            return None
                        raise AdminError("backend_unsupported" if code == "unknown_command" else "backend_rejected")
                    return reply.get("result")
        except (aiohttp.ClientError, TimeoutError, ValueError, TypeError):
            raise AdminError("backend_unavailable_or_timeout") from None

    async def read(self, actor, family, target):
        if family in {"automation", "script"}:
            return await self.rest(actor, "GET", f"/api/config/{family}/config/{target}", missing=True)
        if family in HELPERS:
            items = await self.ws(actor, {"type": family+"/list"})
            return next((item for item in items if item["id"] == target), None)
        if family == "dashboard":
            config = await self.ws(actor, {"type": "lovelace/config", "url_path": None if target == "lovelace" else target}, missing=True)
            if config is None:
                return None
            if target == "lovelace":
                return {"title": "Overview", "config": config}
            dashboards = await self.ws(actor, {"type": "lovelace/dashboards/list"})
            item = next((x for x in dashboards if x["url_path"] == target), None)
            if item is None:
                raise AdminError("dashboard_identity_unavailable")
            return {k: item[k] for k in ("title", "icon", "show_in_sidebar", "require_admin") if k in item} | {"config": config}
        if family == "integration":
            entries = await self.ws(actor, {"type": "config_entries/get"})
            return next((x for x in entries if x["entry_id"] == target), None)
        if family == "service":
            # The operation supplies exact entities; use inspect_states instead.
            raise AdminError("service_requires_entity_snapshot")
        if family == "maintenance":
            domain, service = target.split(".")
            services = await self.rest(actor, "GET", "/api/services")
            if not any(x["domain"] == domain and service in x["services"] for x in services):
                raise AdminError("maintenance_not_available_on_this_installation")
            if target == "backup.create":
                info = await self.ws(actor, {"type": "backup/info"})
                if info["agent_errors"] or info["state"] != "idle":
                    raise AdminError("backup_agent_not_ready")
                return {"backups": [{k: item[k] for k in ("backup_id", "agents", "failed_agent_ids", "name", "date") if k in item} for item in info["backups"]]}
            if target == "homeassistant.restart":
                if self.runtime is None:
                    raise AdminError("core_runtime_identity_unavailable")
                return self.runtime()
            if target != "homeassistant.check_config":
                # No unverified restart/update/credential mutation. These
                # require a supported outcome adapter and separate acceptance.
                raise AdminError("maintenance_outcome_adapter_not_supported")
            return await self.rest(actor, "GET", "/api/config")
        raise AdminError("unsupported_read")

    async def snapshot(self, actor, op):
        from .supervisor import TARGETS, snapshot
        if op["family"] == "maintenance" and op["target"] in TARGETS:
            return await snapshot(self, actor, op)
        if op["family"] in HELPERS and op["action"] == "allocate":
            return {"existing_ids": sorted(item["id"] for item in await self.ws(actor, {"type": op["family"]+"/list"}))}
        if op["family"] == "service":
            return {e: await self.rest(actor, "GET", "/api/states/"+e) for e in op["value"]["entity_ids"]}
        return await self.read(actor, op["family"], op["target"])

    async def prepare(self, actor, op, *, planned_absent=False):
        """Use the installed native helper schema, before approval or writes."""
        if op["family"] in HELPERS and op["action"] != "delete":
            module = importlib.import_module("homeassistant.components."+op["family"])
            try:
                value = vol.Schema(module.STORAGE_FIELDS, extra=vol.PREVENT_EXTRA)(op["value"])
                for key, item in value.items():
                    if isinstance(item, timedelta):
                        seconds = int(item.total_seconds())
                        value[key] = f"{seconds//3600}:{seconds//60%60:02}:{seconds%60:02}"
                    elif isinstance(item, (date, time)):
                        value[key] = item.isoformat()
                op = {**op, "value": value}
            except (vol.Invalid, AttributeError):
                raise AdminError("unsupported_helper_definition") from None
            if op["family"] == "input_text" and op["value"].get("mode") == "password":
                raise AdminError("credential_administration_not_supported")
        if op["family"] in HELPERS and op["action"] == "create" and not planned_absent:
            # Include YAML/registry identities, not only the storage collection.
            await self.helper_absent(actor, op["family"], op["target"])
        return op

    async def helper_absent(self, actor, family, target):
        entity = family+"."+target
        entries = await self.ws(actor, {"type": "config/entity_registry/get_entries", "entity_ids": [entity]})
        state = await self.rest(actor, "GET", "/api/states/"+entity, missing=True)
        if entries.get(entity) is not None or state is not None:
            raise AdminError("helper_identity_already_exists")

    async def write(self, actor, op):
        family, action, target, value = (op[k] for k in ("family", "action", "target", "value"))
        if family in {"automation", "script"}:
            return await self.rest(actor, "DELETE" if action == "delete" else "POST", f"/api/config/{family}/config/{target}", value)
        if family in HELPERS:
            verb = "delete" if action == "delete" else "create" if action in {"create", "allocate"} else "update"
            if verb == "create" and action != "allocate":
                await self.helper_absent(actor, family, target)
            args = {} if verb == "create" else {family+"_id": target}
            if verb != "delete":
                args.update(value)
            restore_name = None
            if verb == "create" and action != "allocate" and re.sub(r"[^a-z0-9]+", "_", args["name"].lower()).strip("_") != target:
                # Restoring a renamed helper uses the approved target as its
                # temporary allocation name, then restores the recorded name.
                # Both mutations have their own final grant check.
                restore_name = args["name"]
                args["name"] = target
            result = await self.ws(actor, {**args, "type": family+"/"+verb})
            if verb != "delete" and action != "allocate" and result.get("id") != target:
                raise AdminError("helper_allocated_unexpected_identity")
            if restore_name is not None:
                result = await self.ws(actor, {"type": family+"/update", family+"_id": target, **{**value, "name": restore_name}})
            return result
        if family == "dashboard":
            if target == "lovelace":
                if action != "put":
                    raise AdminError("default_dashboard_put_only")
            elif action == "create":
                await self.ws(actor, {**{k:v for k,v in value.items() if k != "config"}, "type": "lovelace/dashboards/create", "url_path": target, "mode": "storage"})
            elif action == "put":
                dashboards = await self.ws(actor, {"type": "lovelace/dashboards/list"})
                item = next((x for x in dashboards if x["url_path"] == target), None)
                if item is None:
                    raise AdminError("dashboard_not_found")
                await self.ws(actor, {**{k:v for k,v in value.items() if k != "config"}, "type": "lovelace/dashboards/update", "dashboard_id": item["id"]})
            elif action == "delete":
                dashboards = await self.ws(actor, {"type": "lovelace/dashboards/list"})
                item = next((x for x in dashboards if x["url_path"] == target), None)
                if item is None:
                    raise AdminError("dashboard_not_found")
                return await self.ws(actor, {"type": "lovelace/dashboards/delete", "dashboard_id": item["id"]})
            return await self.ws(actor, {"type": "lovelace/config/save", "url_path": None if target == "lovelace" else target, "config": value["config"]})
        if family == "integration":
            if action in {"reauth", "reconfigure"}:
                await self.final_check()
                if self.flows is None:
                    raise AdminError("native_flow_adapter_unavailable")
                return await self.flows.begin(op, self.final_check)
            return await self.rest(actor, "POST", f"/api/config/config_entries/entry/{target}/reload", {})
        if family in {"service", "maintenance"}:
            from .supervisor import TARGETS, write
            if family == "maintenance" and target in TARGETS:
                return await write(self, actor, op)
            if target == "backup.create":
                return await self.ws(actor, {"type": "backup/generate", "agent_ids": ["backup.local"], "include_all_addons": False, "include_database": True, "include_homeassistant": True})
            if target == "homeassistant.check_config":
                return await self.rest(actor, "POST", "/api/config/core/check_config", {})
            domain, service = target.split(".")
            data = {**value["data"], "entity_id": value["entity_ids"]} if family == "service" else value
            return await self.rest(actor, "POST", f"/api/services/{domain}/{service}", data)
        raise AdminError("unsupported_operation")

    def expected(self, op, before):
        if op["action"] == "delete":
            return None
        if op["family"] in {"integration", "maintenance", "service"}:
            return None  # No fabricated outcome for a service/restart.
        if op["family"] == "automation":
            return {"id": op["target"], **op["value"]}
        if op["family"] == "script":
            return op["value"]
        if op["family"] in HELPERS:
            return {"id": op["target"], **op["value"]}
        return {**(before or {}), **op["value"]}

    def verified(self, op, before, after, result):
        if op["family"] == "service":
            desired = {"turn_on": "on", "turn_off": "off", "open_cover": "open", "close_cover": "closed", "media_play": "playing", "media_pause": "paused"}[op["target"].split(".")[1]]
            # HA state feedback is observed; physical household behavior is a
            # separate acceptance check. Attribute-changing commands need a
            # separately supported verifier; never call them verified here.
            data = op["value"]["data"]
            return all(state["state"] == desired and all(state["attributes"].get(key) == value for key, value in data.items()) for state in after.values())
        if op["family"] == "integration":
            if op["action"] != "reload":
                return False  # Flow initiation is not credential-change success.
            return after is not None and after.get("state") == "loaded"
        if op["family"] == "maintenance":
            from .supervisor import TARGETS, verified
            if op["target"] in TARGETS:
                return verified(op, before, after, result)
            if op["target"] == "homeassistant.restart":
                return after.get("state") == "RUNNING" and after.get("version") == before.get("version") and (after.get("pid"), after.get("created")) != (before.get("pid"), before.get("created"))
            if op["target"] == "backup.create":
                old = {x["backup_id"] for x in before["backups"]}
                new = [x for x in after["backups"] if x["backup_id"] not in old]
                return len(new) == 1 and new[0]["backup_id"] == result.get("backup_job_id") and not new[0].get("failed_agent_ids") and new[0].get("agents", {}).get("backup.local", {}).get("size", 0) > 0
            return op["target"] == "homeassistant.check_config" and result.get("result") == "valid"
        return canonical(after) == canonical(self.expected(op, before))

    async def after(self, actor, op):
        if op["target"] != "backup.create":
            return await self.snapshot(actor, op)
        async with asyncio.timeout(self.timeout):
            while True:
                try:
                    return await self.snapshot(actor, op)
                except AdminError as exc:
                    if exc.code != "backup_agent_not_ready":
                        raise
                    await asyncio.sleep(.05)

    async def references(self, actor, target, family):
        # Inspect HA's loaded automation/script definitions using documented
        # config API IDs from states. Unsupported layouts do not trigger editing.
        states = await self.rest(actor, "GET", "/api/states")
        found = []
        for state in states:
            entity = state["entity_id"]
            domain, name = entity.split(".", 1)
            members = state.get("attributes", {}).get("entity_id", [])
            if isinstance(members, list) and family+"."+target in members:
                found.append(entity)
            if domain not in {"automation", "script"}:
                continue
            key = state.get("attributes", {}).get("id", name)
            if (domain, str(key)) == (family, target):
                continue  # The deleted object's own definition is not a dependent.
            data = await self.read(actor, domain, str(key))
            if data is None:
                raise AdminError("dependency_definition_not_accessible")
            if data is not None and target in canonical(data):
                found.append(entity)
            if len(found) >= 50:
                break
        dashboards = await self.ws(actor, {"type": "lovelace/dashboards/list"})
        for path in ["lovelace"]+[x["url_path"] for x in dashboards]:
            if family == "dashboard" and path == target:
                continue
            data = await self.read(actor, "dashboard", path)
            if data is not None and target in canonical(data):
                found.append("dashboard."+path)
        return found

    async def inspect(self, actor, family, target, detail, run_id=None):
        if family == "system":
            if detail == "health":
                data = await self.rest(actor, "GET", "/api/config")
                return {key: data[key] for key in ("version", "state", "components") if key in data}
            if detail == "states":
                return await self.rest(actor, "GET", "/api/states/"+target)
            if detail == "logs":
                return await self.rest(actor, "GET", "/api/error_log", text=True)
        if detail == "traces" and family in {"automation", "script"}:
            return await self.ws(actor, {"type": "trace/list", "domain": family, "item_id": target})
        if detail == "trace" and family in {"automation", "script"} and run_id:
            return await self.ws(actor, {"type": "trace/get", "domain": family, "item_id": target, "run_id": run_id})
        if detail == "config":
            return await self.read(actor, family, target)
        raise AdminError("unsupported_inspection")
