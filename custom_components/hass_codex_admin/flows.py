"""Owner-only handoff to native config flows; no secrets on the MCP path."""
from __future__ import annotations

import asyncio
import time

from homeassistant import config_entries, data_entry_flow
import probatio as vol
from homeassistant.components import websocket_api

from .model import AdminError, canonical, fingerprint


class NativeFlows:
    def __init__(self, hass):
        self.hass = hass
        self.active = {}
        self.lock = asyncio.Lock()

    def entry(self, identifier):
        entry = self.hass.config_entries.async_get_entry(identifier)
        if entry is None:
            raise AdminError("integration_not_found")
        return entry

    def identity(self, entry):
        return {"entry_id": entry.entry_id, "domain": entry.domain, "unique_id": entry.unique_id}

    def prune(self):
        for identifier, context in list(self.active.items()):
            try:
                progress = self.hass.config_entries.flow.async_get(identifier)
            except data_entry_flow.UnknownFlow:
                self.active.pop(identifier)
                continue
            if time.monotonic() - context["created"] >= 900:
                if progress["context"].get("entry_id") == context["identity"]["entry_id"]:
                    self.hass.config_entries.flow.async_abort(identifier)
                self.active.pop(identifier)

    async def begin(self, op, check):
        async with self.lock:
            self.prune()
            entry = self.entry(op["target"])
            if any(entry.async_get_active_flows(self.hass, {config_entries.SOURCE_REAUTH, config_entries.SOURCE_RECONFIGURE})):
                raise AdminError("native_flow_already_active")
            if len(self.active) >= 32:
                raise AdminError("native_flow_capacity")
            await check()
            try:
                if op["action"] == "reauth":
                    entry.async_start_reauth(self.hass)
                    async with asyncio.timeout(4):
                        while not (flows := list(entry.async_get_active_flows(self.hass, {config_entries.SOURCE_REAUTH}))):
                            await asyncio.sleep(.01)
                    result = flows[0]
                else:
                    result = await self.hass.config_entries.flow.async_init(entry.domain, context={"source": config_entries.SOURCE_RECONFIGURE, "entry_id": entry.entry_id})
            except (data_entry_flow.UnknownHandler, data_entry_flow.UnknownStep, TimeoutError):
                raise AdminError("native_flow_not_supported") from None
            if result.get("type") in {data_entry_flow.FlowResultType.ABORT, data_entry_flow.FlowResultType.CREATE_ENTRY}:
                raise AdminError("native_flow_finished_without_reviewable_handoff")
            identifier = result["flow_id"]
            self.active[identifier] = {"identity": self.identity(entry), "source": op["action"], "result": result, "created": time.monotonic()}
            return {"owner_input_required": True, "flow_id": identifier, "entry_id": entry.entry_id}

    def validate(self, flow_id, op):
        context = self.active.get(flow_id)
        if context is None or context["source"] != op["action"] or context["identity"] != self.identity(self.entry(op["target"])):
            raise AdminError("native_flow_identity_changed")
        try:
            progress = self.hass.config_entries.flow.async_get(flow_id)
        except data_entry_flow.UnknownFlow:
            raise AdminError("native_flow_outcome_unobserved") from None
        expected = config_entries.SOURCE_REAUTH if op["action"] == "reauth" else config_entries.SOURCE_RECONFIGURE
        if progress["handler"] != context["identity"]["domain"] or progress["context"].get("entry_id") != op["target"] or progress["context"].get("source") != expected:
            raise AdminError("native_flow_identity_changed")
        return context

    def describe(self, context):
        result = context["result"]
        schema = result.get("data_schema")
        fields = []
        if schema is not None:
            # Do not serialize integration defaults, descriptions, data, URLs,
            # credentials or options. Unsupported selectors stay in native UI.
            for key, validator in schema.schema.items():
                name = str(key.schema) if isinstance(key, vol.Marker) else str(key)
                if validator not in (str, bool, int) or len(name) > 80:
                    raise AdminError("native_flow_requires_native_frontend")
                fields.append({"name": name, "kind": "boolean" if validator is bool else "integer" if validator is int else "text", "required": isinstance(key, vol.Required)})
        return {"owner_input_required": True, "step": result.get("step_id"), "fields": fields, "errors": {str(k): "invalid_input" for k in (result.get("errors") or {})}}

    async def command(self, engine, identity, owner, message):
        async with engine.lock, self.lock:
            row = await engine.db("get", message["task"])
            n = message["operation"]
            if n >= len(row["operations"]) or row["hash"] != message["plan_hash"] or row["approved_by"] != owner.session:
                raise AdminError("native_flow_task_binding")
            op = row["plan"]["operations"][n]
            item = row["operations"][n]
            receipt = item["result"] or {}
            result = receipt.get("result", {})
            if op["family"] != "integration" or op["action"] not in {"reauth", "reconfigure"} or item["status"] != "uncertain" or not receipt.get("backend_acknowledged") or not result.get("owner_input_required"):
                raise AdminError("native_flow_task_binding")
            flow_id = result["flow_id"]
            context = self.validate(flow_id, op)
            if message["action"] == "cancel":
                # Cleanup-only authority survives task/connector revocation and
                # expiry for the same current native approving owner session.
                identity.approved_session(owner.session)
                self.hass.config_entries.flow.async_abort(flow_id)
                self.active.pop(flow_id)
                return {"cancelled": True, "operation_status": "uncertain", "native_entry_effects_not_reversed": True}
            actor = identity.caller(identity.transport_credential(row["session"]))
            async def authorize():
                engine.check_revocation(row["id"])
                await engine.db("authorize", row["id"], actor, fingerprint(engine.policy), row["hash"])
                engine.check_revocation(row["id"])
                identity.approved_session(owner.session)
                engine.current(actor)
            await authorize()
            action = message["action"]
            if action == "status":
                return self.describe(context)
            inputs = message.get("input")
            if inputs is not None and (not isinstance(inputs, dict) or len(canonical(inputs)) > 8192):
                raise AdminError("native_flow_input_limits")
            await authorize()
            entry = self.entry(op["target"])
            reloaded = asyncio.Event()
            observed_unloaded = False
            def state_changed():
                nonlocal observed_unloaded
                if entry.state.value != "loaded":
                    observed_unloaded = True
                elif observed_unloaded:
                    reloaded.set()
            remove = entry.async_on_state_change(state_changed)
            try:
                try:
                    async with asyncio.timeout(10):
                        next_result = await self.hass.config_entries.flow.async_configure(flow_id, inputs)
                except (data_entry_flow.UnknownFlow, data_entry_flow.InvalidData):
                    raise AdminError("native_flow_invalid_or_stale_input") from None
                terminal_success = next_result["type"] == data_entry_flow.FlowResultType.ABORT and next_result.get("reason") == ("reauth_successful" if op["action"] == "reauth" else "reconfigure_successful")
                if terminal_success:
                    try:
                        await asyncio.wait_for(reloaded.wait(), 5)
                    except TimeoutError:
                        self.active.pop(flow_id, None)
                        raise AdminError("native_flow_reload_not_verified") from None
            finally:
                remove()
            context["result"] = next_result
            if next_result["type"] not in {data_entry_flow.FlowResultType.ABORT, data_entry_flow.FlowResultType.CREATE_ENTRY}:
                return self.describe(context)
            self.active.pop(flow_id)
            expected_reason = "reauth_successful" if op["action"] == "reauth" else "reconfigure_successful"
            if next_result["type"] != data_entry_flow.FlowResultType.ABORT or next_result.get("reason") != expected_reason:
                raise AdminError("native_flow_did_not_confirm_success")
            await authorize()
            after = await engine.backend.snapshot(actor, op)
            if self.identity(self.entry(op["target"])) != context["identity"] or after.get("state") != "loaded":
                raise AdminError("native_flow_outcome_requires_reconciliation")
            await engine.db("finish", row["id"], n, "applied", after, {"native_terminal_result_verified": True, "loaded_entry_verified": True, "external_authentication_verified": False}, expected="uncertain")
            return {"completed": True, "external_authentication_verified": False}


def register(hass, engine, identity, flows):
    @websocket_api.websocket_command({vol.Required("type"): "hass_codex_admin/flow", vol.Required("action"): vol.In(["status", "submit", "cancel"]), vol.Required("task"): str, vol.Required("plan_hash"): str, vol.Required("operation"): vol.All(int, vol.Range(min=0, max=19)), vol.Optional("input"): dict})
    @websocket_api.async_response
    async def command(hass, connection, message):
        try:
            owner = identity.approver(connection)
            async with asyncio.timeout(20):
                value = await flows.command(engine, identity, owner, message)
            connection.send_result(message["id"], value)
        except (AdminError, TimeoutError) as exc:
            code = exc.code if isinstance(exc, AdminError) else "native_flow_deadline"
            connection.send_error(message["id"], code, code)
        except Exception:
            connection.send_error(message["id"], "native_flow_outcome_requires_reconciliation", "native_flow_outcome_requires_reconciliation")
    websocket_api.async_register_command(hass, command)
