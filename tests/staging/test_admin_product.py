"""Actual HA Core 2026.10 + native MCP + native owner approval + fixed APIs.

Only loopback, synthetic configuration/accounts and task-owned temporary files.
No tunnel, household device, production credential, privileged actor or VM.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import unittest

import aiohttp
from homeassistant import auth, loader, bootstrap, config_entries
from homeassistant.auth.const import GROUP_ID_ADMIN
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

REPO = Path(__file__).resolve().parents[2]


class NativeAdministrator(unittest.IsolatedAsyncioTestCase):
    persist_root = None

    async def asyncSetUp(self):
        from admin_network_guard import install
        install()
        self.temp = tempfile.TemporaryDirectory(prefix="ha-admin-native-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.persist_root or self.temp.name)
        if not (self.root / "automations.yaml").exists():
            (self.root / "automations.yaml").write_text("[]\n")
        if not (self.root / "scripts.yaml").exists():
            (self.root / "scripts.yaml").write_text("{}\n")
        (self.root / "configuration.yaml").write_text("automation: !include automations.yaml\nscript: !include scripts.yaml\ninput_boolean: {}\nlovelace:\n  mode: storage\n")
        archive = os.environ.get("ADMIN_RELEASE_ARCHIVE")
        if archive:
            import importlib.util
            spec = importlib.util.spec_from_file_location("admin_release_package", REPO / "scripts/development/package.py")
            package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
            if not (self.root / "custom_components").exists():
                package.install_fresh(archive, self.root)
            else:
                # Persisted process fixtures must already have exactly the
                # installed archive bytes, never source-checkout fallback.
                import zipfile, hashlib
                manifest = package.verify(archive)
                for name, record in manifest["files"].items():
                    self.assertEqual(hashlib.sha256((self.root/name).read_bytes()).hexdigest(), record["sha256"])
        else:
            shutil.copytree(REPO / "custom_components/hass_codex_admin", self.root / "custom_components/hass_codex_admin", ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
        self.legacy_package = json.loads((self.root / "custom_components/hass_codex_admin/manifest.json").read_text())["version"] == "0.1.0"
        port_file = self.root / "fixture.port"
        if self.persist_root and port_file.exists():
            self.port = int(port_file.read_text())
        else:
            with socket.socket() as port:
                port.bind(("127.0.0.1", 0));self.port = port.getsockname()[1]
            if self.persist_root:
                port_file.write_text(str(self.port))
        self.base = f"http://127.0.0.1:{self.port}"
        self.hass = HomeAssistant(str(self.root))
        self.addAsyncCleanup(self.hass.async_stop)
        self.hass.config.skip_pip = True
        self.hass.config.internal_url = self.base
        self.hass.config.time_zone = "UTC"
        loader.async_setup(self.hass)
        self.hass.config_entries = config_entries.ConfigEntries(self.hass, {})
        self.assertTrue(await bootstrap.async_load_base_functionality(self.hass))
        self.hass.auth = await auth.auth_manager_from_config(self.hass, [{"type": "homeassistant"}], [])
        users = await self.hass.auth.async_get_users()
        if users:
            self.owner = next(user for user in users if user.name == "Synthetic owner")
            self.remote_refresh = next(t for t in self.owner.refresh_tokens.values() if t.client_id == "https://synthetic-mcp.invalid")
            self.owner_refresh = next(t for t in self.owner.refresh_tokens.values() if t.client_id == self.base)
        else:
            self.owner = await self.hass.auth.async_create_user("Synthetic owner", group_ids=[GROUP_ID_ADMIN])
            self.remote_refresh = await self.hass.auth.async_create_refresh_token(self.owner, client_id="https://synthetic-mcp.invalid")
            self.owner_refresh = await self.hass.auth.async_create_refresh_token(self.owner, client_id=self.base)
        self.native_remote_bearer = self.hass.auth.async_create_access_token(self.remote_refresh)
        self.owner_bearer = self.hass.auth.async_create_access_token(self.owner_refresh)
        config = {"http": {"server_host": "127.0.0.1", "server_port": self.port}, "automation": [], "script": {}, "input_boolean": {}, "lovelace": {"mode": "storage"},
                  "hass_codex_admin": {"backend_url": self.base, "approver_client_ids": [self.base], "approval_panel": True, "edit_coordination": "owner_window"}}
        if self.legacy_package:
            config["hass_codex_admin"].pop("edit_coordination")
        for domain in ("homeassistant", "persistent_notification", "http", "api", "websocket_api", "config", "automation", "script", "input_boolean", "lovelace", "hass_codex_admin"):
            loaded = await async_setup_component(self.hass, domain, config)
            if domain == "hass_codex_admin" and getattr(self, "expect_admin_failure", False):
                self.assertFalse(loaded); break
            self.assertTrue(loaded, domain)
        await self.hass.async_start()
        await self.hass.async_block_till_done()
        self.client = aiohttp.ClientSession(trust_env=False)
        self.addAsyncCleanup(self.client.close)
        self.counter = 0
        if getattr(self, "expect_admin_failure", False):
            return
        identity = self.hass.data["hass_codex_admin"]["identity"]
        connector_file = self.root / "fixture.connector"
        if self.persist_root and connector_file.exists():
            if getattr(self, "expect_restore", False):
                from custom_components.hass_codex_admin.model import AdminError
                with self.assertRaises(AdminError):
                    identity.transport_credential(connector_file.read_text())
                issued = await identity.issue(identity.approved_session(self.owner_refresh.id), "Fresh owner consent after restore", 1)
                self.bearer = issued["connector_credential"]
                connector_file.write_text(issued["id"])
            else:
                self.bearer = identity.transport_credential(connector_file.read_text())
        else:
            issued = await identity.issue(identity.approved_session(self.owner_refresh.id), "Synthetic connection", 1)
            self.bearer = issued["connector_credential"]
            if self.persist_root:
                connector_file.write_text(issued["id"])
                connector_file.chmod(0o600)

    async def rpc(self, method, params=None, bearer=None, path=None):
        self.counter += 1
        async with self.client.post(getattr(self, "rpc_base", self.base)+(path or getattr(self, "rpc_path", "/api/hass_codex_admin/mcp")), json={"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params or {}},
            headers={"Authorization": "Bearer "+(bearer or self.bearer), "Accept": "application/json"}) as response:
            self.assertEqual(response.status, 200)
            return await response.json()

    async def tool(self, name, args, **rpc_fields):
        body = await self.rpc("tools/call", {"name": name, "arguments": args}, **rpc_fields)
        self.assertNotIn("error", body, body)
        result = body["result"]
        content = json.loads(result["content"][0]["text"])
        if result.get("isError"):
            return {"error": content["error"]}
        return content["result"]

    async def approval(self, action, *, bearer=None, **fields):
        if action == "approve" and not self.legacy_package:
            fields.setdefault("confirm_edit_window", True)  # synthetic owner accepts fixture-only edit policy
        async with self.client.ws_connect(self.base+"/api/websocket") as ws:
            self.assertEqual((await ws.receive_json())["type"], "auth_required")
            await ws.send_json({"type": "auth", "access_token": bearer or self.owner_bearer})
            self.assertEqual((await ws.receive_json())["type"], "auth_ok")
            await ws.send_json({"id": 1, "type": "hass_codex_admin/approval", "action": action, **fields})
            return await ws.receive_json()

    async def approved(self, operations):
        task = await self.tool("admin_propose", {"operations": operations})
        self.assertNotIn("error", task, task)
        self.assertTrue((await self.approval("enroll"))["success"])
        result = await self.approval("approve", task=task["id"], plan_hash=task["hash"], confirm_effects=True)
        self.assertTrue(result["success"], result)
        return task

    async def test_connector_revocation_sql_failure_cannot_renew_on_boot(self):
        from unittest.mock import patch
        from custom_components.hass_codex_admin.model import AdminError
        identity = self.hass.data["hass_codex_admin"]["identity"]
        identifier = identity.caller(self.bearer).session
        store = identity.store
        # Real durable intent succeeds, real SQLite deletion is the only fault.
        original = store.transaction
        with patch.object(store, "transaction", side_effect=AdminError("storage_unavailable")):
            with self.assertRaises(AdminError):
                await identity.revoke(identifier)
        with self.assertRaises(AdminError):
            identity.caller(self.bearer)
        self.assertTrue((store.intents / identifier).is_file())
        renewed = await asyncio.to_thread(store.activate_connectors)
        self.assertNotIn(identifier, {row["id"] for row in renewed})
        self.assertFalse((store.intents / identifier).exists())
        self.assertNotIn(identifier, {row["id"] for row in await asyncio.to_thread(store.connectors)})

    async def test_connector_cancelled_late_activation_cannot_return_authority(self):
        import threading
        from unittest.mock import patch
        from custom_components.hass_codex_admin.model import AdminError
        identity = self.hass.data["hass_codex_admin"]["identity"]
        owner = identity.approved_session(self.owner_refresh.id)
        entered, release = threading.Event(), threading.Event()
        original = identity.store.confirm_connector
        identifiers = []
        def delayed(identifier):
            identifiers.append(identifier); entered.set()
            if not release.wait(3):
                raise AssertionError("activation boundary stalled")
            return original(identifier)
        with patch.object(identity.store, "confirm_connector", delayed):
            pending = asyncio.create_task(identity.issue(owner, "Cancelled issuance", 1))
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            pending.cancel()
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await pending
                self.assertTrue((identity.store.intents / identifiers[0]).exists())
            finally:
                release.set()
            await self.hass.async_block_till_done()
        renewed = await asyncio.to_thread(identity.store.activate_connectors)
        self.assertNotIn(identifiers[0], {row["id"] for row in renewed})
        # Invalid intent paths, symlinks and corrupt files never get ignored.
        with self.assertRaises(AdminError):
            await identity.revoke("../tasks.sqlite")
        marker = identity.store.intents / ("a"*32)
        marker.symlink_to(identity.store.path)
        with self.assertRaises(AdminError):
            await asyncio.to_thread(identity.store.activate_connectors)
        marker.unlink()

    async def test_failed_task_revoke_latches_before_dispatch(self):
        from unittest.mock import patch
        from custom_components.hass_codex_admin.model import AdminError
        task = await self.approved([{"family": "script", "action": "create", "target": "failed_revoke", "value": {"sequence": [{"delay": "00:00:00"}]}}])
        engine = self.hass.data["hass_codex_admin"]["engine"]
        with patch.object(engine.store, "decide", side_effect=AdminError("storage_unavailable")):
            response = await self.approval("revoke", task=task["id"], plan_hash=task["hash"])
            self.assertFalse(response["success"])
        self.assertEqual(await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}), {"error": "approval_revoked"})
        self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": "failed_revoke"}))
        good = await self.approved([{"family": "script", "action": "create", "target": "after_failed_revoke", "value": {"sequence": [{"delay": "00:00:00"}]}}])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": good["id"], "plan_hash": good["hash"]}))

    async def test_missing_create_ack_does_not_adopt_external_identical_object(self):
        from unittest.mock import patch
        from custom_components.hass_codex_admin.model import AdminError
        op = {"family": "script", "action": "create", "target": "external_identical", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op]); args = {"task": task["id"], "plan_hash": task["hash"]}
        engine = self.hass.data["hass_codex_admin"]["engine"]
        with patch.object(engine.backend, "write", side_effect=AdminError("backend_unavailable_or_timeout")):
            self.assertIn("error", await self.tool("admin_execute", args))
        # An independently authenticated native editor creates identical bytes.
        async with self.client.post(self.base+"/api/config/script/config/"+op["target"], json=op["value"], headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(await self.tool("admin_reconcile", args), {"error": "creation_ownership_requires_owner_reconciliation"})
        self.assertEqual(await self.tool("admin_rollback", args), {"error": "operation_consumed_or_uncertain"})
        self.assertEqual(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}), op["value"])

    async def test_repeated_mixed_tasks_varied_schedule_and_duplicate_calls(self):
        import time
        from unittest.mock import patch
        engine = self.hass.data["hass_codex_admin"]["engine"]
        writes = []
        original_write = engine.backend.write
        async def counted(actor, operation):
            writes.append((operation["target"], operation["action"]))
            return await original_write(actor, operation)
        started = time.perf_counter(); latencies = []
        with patch.object(engine.backend, "write", counted):
            for n, delay in enumerate((0, .001, .003, .002, 0)):
                unknown = await self.rpc("tools/call", {"name": "not_a_tool", "arguments": {}})
                self.assertTrue(unknown.get("error") or unknown.get("result", {}).get("isError"))
                op = {"family": "script", "action": "create", "target": "mixed_"+str(n), "value": {"alias": "Create", "sequence": [{"delay": "00:00:00"}]}}
                task = await self.approved([op, {**op, "action": "put", "value": {**op["value"], "alias": "Repair"}}])
                args = {"task": task["id"], "plan_hash": task["hash"]}
                async def call():
                    await asyncio.sleep(delay); return await self.tool("admin_execute", args)
                begin = time.perf_counter()
                results = await asyncio.gather(call(), self.tool("admin_execute", args))
                self.assertTrue(all("error" not in result for result in results), results)
                self.assertEqual(writes.count((op["target"], "create")), 1)
                self.assertEqual(writes.count((op["target"], "put")), 1)
                self.assertEqual((await self.tool("admin_inspect", {"family": "script", "target": op["target"]}))["alias"], "Repair")
                self.assertNotIn("error", await self.tool("admin_rollback", args))
                self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}))
                latencies.append(round((time.perf_counter()-begin)*1000, 2))
        self.assertFalse(engine.lock.locked())
        self.assertEqual(len(writes), 20)  # two writes + two reverse writes each
        print("NATIVE_RELIABILITY_METRICS="+json.dumps({"iterations": 5, "failed": 0, "duplicate_writes": 0, "duration_seconds": round(time.perf_counter()-started, 3), "task_and_rollback_ms": latencies, "scope": "bounded loopback scheduling variation; not a stability soak"}))

    async def test_native_bearer_bypass_reproduction_and_connector_global_denial(self):
        effects = []
        async def effect(call):
            effects.append(call.context.user_id)
        self.hass.services.async_register("synthetic", "effect", effect)
        # Red baseline: the former connector's ordinary admin bearer can bypass
        # every task check. A read-only user also reaches non-entity services.
        for token in (self.native_remote_bearer,):
            async with self.client.post(self.base+"/api/services/synthetic/effect", json={}, headers={"Authorization": "Bearer "+token}) as response:
                self.assertEqual(response.status, 200)
        from homeassistant.auth.const import GROUP_ID_READ_ONLY
        reader = await self.hass.auth.async_create_user("Synthetic reader", group_ids=[GROUP_ID_READ_ONLY])
        reader_refresh = await self.hass.auth.async_create_refresh_token(reader, client_id=self.base)
        async with self.client.post(self.base+"/api/services/synthetic/effect", json={}, headers={"Authorization": "Bearer "+self.hass.auth.async_create_access_token(reader_refresh)}) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(len(effects), 2)
        for path in ("/api/services/synthetic/effect", "/api/services/automation/trigger", "/api/config/script/config/escaped", "/api/mcp", "/api/mcp/hass_codex_admin", "/api/mcp/assist", "/mcp_server/messages/forged"):
            async with self.client.post(self.base+path, json={}, headers={"Authorization": "Bearer "+self.bearer}) as response:
                self.assertEqual(response.status, 401, path)
        async with self.client.ws_connect(self.base+"/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": self.bearer})
            self.assertEqual((await ws.receive_json())["type"], "auth_invalid")
        self.assertEqual(len(effects), 2)
        async with self.client.post(self.base+"/api/services/synthetic/effect", json={}, headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(len(effects), 3)
        for path in ("/api/hass_codex_admin/mcp?route=/api/services/synthetic/effect", "/api/hass_codex_admin/mcp/../mcp", "/api/hass_codex_admin/mcp/"):
            async with self.client.post(self.base+path, json={}, headers={"Authorization": "Bearer "+self.bearer}, allow_redirects=False) as response:
                self.assertIn(response.status, (400, 404, 405))
        async with self.client.post(self.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
            self.assertEqual(response.status, 401)
        self.assertEqual((await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"}))["version"], "2026.10.0")

    async def test_owned_credential_issuance_revocation_and_debug_redaction(self):
        import logging
        ws_logger = logging.getLogger("homeassistant.components.websocket_api.http.connection")
        old_level = ws_logger.level
        ws_logger.setLevel(logging.DEBUG)
        captured = []
        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(record.getMessage())
        handler = Capture(); ws_logger.addHandler(handler)
        self.addCleanup(ws_logger.removeHandler, handler)
        self.addCleanup(ws_logger.setLevel, old_level)
        async with self.client.ws_connect(self.base+"/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": self.owner_bearer})
            self.assertEqual((await ws.receive_json())["type"], "auth_ok")
            await ws.send_json({"id": 1, "type": "hass_codex_admin/connection", "action": "issue", "label": "Owned synthetic connection"})
            result = await ws.receive_json(); self.assertTrue(result["success"])
            issued = result["result"]
            self.assertIsNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "none"}, bearer=issued["connector_credential"]))
            await ws.send_json({"id": 2, "type": "hass_codex_admin/connection", "action": "revoke", "connector_id": issued["id"]})
            self.assertTrue((await ws.receive_json())["success"])
        diagnostic = "\n".join(captured)
        self.assertNotIn(self.owner_bearer, diagnostic)
        self.assertNotIn(issued["connector_credential"], diagnostic)
        private_db = (self.root/".storage/hass_codex_admin/tasks.sqlite").read_bytes()
        self.assertNotIn(self.bearer.encode(), private_db)
        self.assertNotIn(self.owner_bearer.encode(), private_db)
        async with self.client.post(self.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+issued["connector_credential"]}) as response:
            self.assertEqual(response.status, 401)

    async def native_ws(self, command, bearer=None):
        async with self.client.ws_connect(self.base+"/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": bearer or self.owner_bearer})
            self.assertEqual((await ws.receive_json())["type"], "auth_ok")
            await ws.send_json({"id": 1, **command})
            return await ws.receive_json()

    async def test_local_edit_after_intent_is_preserved_and_recovery_stays_useful(self):
        engine = self.hass.data["hass_codex_admin"]["engine"]
        operation = {"family": "script", "action": "create", "target": "conflict_window", "value": {"alias": "Remote plan", "sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([operation])
        original = engine.db
        local = {**operation["value"], "alias": "Independent local edit"}
        async def boundary(method, *args, **kwargs):
            result = await original(method, *args, **kwargs)
            if method == "claim":
                async with self.client.post(self.base+"/api/config/script/config/conflict_window", json=local, headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
                    self.assertEqual(response.status, 200)
            return result
        engine.db = boundary
        try:
            self.assertEqual(await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}), {"error": "object_changed_requires_new_approval"})
        finally:
            engine.db = original
        self.assertEqual(await self.tool("admin_inspect", {"family": "script", "target": operation["target"]}), local)
        repair = await self.approved([{**operation, "action": "put", "value": {**local, "alias": "Explicit fresh repair"}}])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": repair["id"], "plan_hash": repair["hash"]}))
        self.assertNotIn("error", await self.tool("admin_rollback", {"task": repair["id"], "plan_hash": repair["hash"]}))
        self.assertEqual(await self.tool("admin_inspect", {"family": "script", "target": operation["target"]}), local)

    async def test_native_helper_id_collision_binds_assigned_identity_and_preserves_local_object(self):
        engine = self.hass.data["hass_codex_admin"]["engine"]
        task = await self.approved([{ "family": "input_boolean", "action": "create", "target": "allocation_race", "value": {"name": "Allocation race"}}])
        original = engine.backend.final_check
        raced = False
        async def boundary():
            nonlocal raced
            await original()
            if not raced:
                raced = True
                local = await self.native_ws({"type": "input_boolean/create", "name": "Allocation race"})
                self.assertTrue(local["success"], local)
                self.assertEqual(local["result"]["id"], "allocation_race")
        engine.backend.final_check = boundary
        args = {"task": task["id"], "plan_hash": task["hash"]}
        try:
            completed = await self.tool("admin_execute", args)
            self.assertNotIn("error", completed, completed)
        finally:
            engine.backend.final_check = original
        self.assertEqual(completed["operations"][0]["status"], "applied")
        self.assertEqual(completed["operations"][0]["result"]["created_target"], "allocation_race_2")
        self.assertIsNotNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "allocation_race"}))
        self.assertIsNotNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "allocation_race_2"}))
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertNotIn("error", await self.tool("admin_rollback", args))
        self.assertIsNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "allocation_race_2"}))
        self.assertIsNotNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "allocation_race"}))
        fresh = await self.approved([{ "family": "script", "action": "create", "target": "after_collision", "value": {"sequence": [{"delay": "00:00:00"}]}}])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": fresh["id"], "plan_hash": fresh["hash"]}))

    async def test_connection_crash_reconnect_and_revocation_have_actual_mcp_outcomes(self):
        import sys, os
        from unittest.mock import patch
        from custom_components.hass_codex_tunnel_mcp.tunnel import TunnelManager, _read_health_url
        from custom_components.hass_codex_tunnel_mcp.const import CONF_HA_MCP_BEARER_TOKEN
        fixture = self.root / "tunnel-client"
        fixture.write_text("#!"+sys.executable+"\nimport sys\nsys.path.insert(0, "+repr(str(REPO/"tests/staging"))+")\n"+(REPO/"tests/staging/admin_transport_fixture.py").read_text())
        fixture.chmod(0o700)
        calls = []
        def provider(force):
            calls.append(force); return fixture
        identity = self.hass.data["hass_codex_admin"]["identity"]
        connector_id = identity.caller(self.bearer).session
        manager = TunnelManager(provider, self.root/"transport", retry_delays=(.03, .06), poll_interval=.05,
            credential_provider=lambda data: identity.transport_credential(data["admin_connection_id"]))
        flags = patch.dict(os.environ, {"CLOUDFLARED_MANAGED": "true", "HARPOON_TARGETS": "http://synthetic.invalid", "LOG_HTTP_RAW_UNSAFE": "true"})
        flags.start(); self.addCleanup(flags.stop)
        spawn = manager._spawn
        async def reviewed_spawn(command, environment):
            self.assertNotIn("CLOUDFLARED_MANAGED", environment)
            self.assertNotIn("HARPOON_TARGETS", environment)
            self.assertNotIn("LOG_HTTP_RAW_UNSAFE", environment)
            await spawn(command, environment)
        manager._spawn = reviewed_spawn
        self.addAsyncCleanup(manager.close)
        data = {"tunnel_id": "synthetic-tunnel", "api_key": "synthetic-platform-key", "ha_mcp_url": self.base+"/api/hass_codex_admin/mcp", "admin_connection_id": connector_id, "auto_update_tunnel_client": False}
        transport_state = self.root/"transport.state";transport_state.write_text("ready")
        with patch.dict(os.environ, {"ADMIN_TRANSPORT_STATE_FILE": str(transport_state)}):
            await manager.start(data)
        self.assertTrue(await manager.wait_until_healthy(4))
        self.rpc_base = _read_health_url(self.root/"transport/health.url");self.rpc_path = "/mcp"
        self.assertEqual((await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"}))["version"], "2026.10.0")
        await asyncio.gather(*(manager.start(data) for _ in range(5)))
        self.assertEqual(calls, [False])
        old = manager.process;old.kill()
        for _ in range(100):
            if manager.process is not old and manager.status.healthy:
                break
            await asyncio.sleep(.04)
        self.assertIsNot(manager.process, old)
        self.assertTrue(manager.status.healthy)
        self.rpc_base = _read_health_url(self.root/"transport/health.url")
        for turn in range(3):
            self.assertIn("error", await self.tool("admin_propose", {"operations": [{"invalid": turn}]}))
            task = await self.approved([{ "family": "script", "action": "create", "target": "transport_repair_"+str(turn), "value": {"sequence": [{"delay": "00:00:00"}]}}])
            args = {"task": task["id"], "plan_hash": task["hash"]}
            results = await asyncio.gather(*(self.tool("admin_execute", args) for _ in range(3)))
            self.assertTrue(all("error" not in result for result in results), results)
            self.assertNotIn("error", await self.tool("admin_rollback", args))
        unchanged = manager.process
        for mode, category in (("disconnected", "transport_not_ready"), ("provider-unavailable", "provider_unavailable")):
            transport_state.write_text(mode)
            for _ in range(60):
                if manager.status.last_error == category:
                    break
                await asyncio.sleep(.03)
            self.assertEqual(manager.status.last_error, category)
            self.assertIs(manager.process, unchanged)
            transport_state.write_text("ready")
            self.assertTrue(await manager.wait_until_healthy(3))
            self.assertNotIn("error", await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"}))
        await self.hass.http.stop()
        for _ in range(60):
            if manager.status.last_error == "backend_unavailable":
                break
            await asyncio.sleep(.04)
        self.assertEqual(manager.status.last_error, "backend_unavailable")
        self.assertIs(manager.process, unchanged)
        # Rebind the existing native app after an injected listener loss.
        # Core normally reconstructs this server on restart; this fixture uses
        # its supported setup/start methods without restarting the engine.
        await self.hass.http.async_bind()
        await self.hass.http.start()
        self.assertTrue(await manager.wait_until_healthy(3))
        self.assertNotIn("error", await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"}))
        await identity.revoke(connector_id)
        for _ in range(80):
            if manager.status.state == "authentication_denied":
                break
            await asyncio.sleep(.04)
        self.assertEqual(manager.status.state, "authentication_denied")
        self.assertFalse(manager.status.healthy)
        self.assertIsNotNone(manager.process.returncode)
        self.assertEqual(calls, [False])
        await manager.close()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            await manager.start(data)

    async def test_updater_failed_activation_rolls_back_and_late_stop_cannot_revive(self):
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch, AsyncMock
        from custom_components.hass_codex_tunnel_mcp.tunnel import TunnelManager, _read_health_url
        from custom_components.hass_codex_tunnel_mcp.updater import TunnelClientUpdater, UpdateCheckResult
        from custom_components.hass_codex_tunnel_mcp.binary import TunnelClientAsset
        good = self.root / "tunnel-client"
        good.write_text("#!"+sys.executable+"\nimport sys\nsys.path.insert(0, "+repr(str(REPO/"tests/staging"))+")\n"+(REPO/"tests/staging/admin_transport_fixture.py").read_text())
        good.chmod(0o700)
        identity = self.hass.data["hass_codex_admin"]["identity"]
        manager = TunnelManager(lambda force: good, self.root/"updater-run", poll_interval=.03,
            credential_provider=lambda data: identity.transport_credential(data["admin_connection_id"]))
        self.addAsyncCleanup(manager.close)
        data = {"tunnel_id": "synthetic-tunnel", "api_key": "synthetic-platform-key", "ha_mcp_url": self.base+"/api/hass_codex_admin/mcp", "admin_connection_id": identity.caller(self.bearer).session}
        entry = SimpleNamespace(entry_id="synthetic-update", data=data, options={})
        updater = TunnelClientUpdater(self.hass, entry, self.root/"bin", lambda: None)
        await updater.async_load()
        asset = TunnelClientAsset("linux", "amd64", "fixture.zip", "a"*64, "v0.0.17")
        candidate = UpdateCheckResult("v0.0.17", "v0.0.17", asset, None)
        await manager.start(data)
        self.assertTrue(await manager.wait_until_healthy(3))
        # Inject only the OS spawn failure; actual ownership/epoch, rollback
        # child and native MCP backend remain connected.
        original_spawn = manager._spawn
        async def spawn(command, env):
            if command[0] == str(self.root/"absent-candidate"):
                raise FileNotFoundError("synthetic_candidate_spawn_failure")
            await original_spawn(command, env)
        with patch.object(manager, "_spawn", spawn), patch.object(updater, "async_check_for_update", AsyncMock(return_value=candidate)), patch("custom_components.hass_codex_tunnel_mcp.updater.ensure_tunnel_client", AsyncMock(return_value=self.root/"absent-candidate")):
            with self.assertRaises(FileNotFoundError):
                await updater.async_update_tunnel_client(manager, data)
        self.assertTrue(await manager.wait_until_healthy(3))
        self.assertEqual(updater.state.active_version, "v0.0.16")
        self.assertIn("v0.0.17", updater.state.failed_versions)
        self.rpc_base = _read_health_url(self.root/"updater-run/health.url"); self.rpc_path = "/mcp"
        self.assertNotIn("error", await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"}))
        entered, release = asyncio.Event(), asyncio.Event()
        async def delayed_install(*args, **kwargs):
            entered.set(); await release.wait(); return good
        with patch.object(updater, "async_check_for_update", AsyncMock(return_value=candidate)), patch("custom_components.hass_codex_tunnel_mcp.updater.ensure_tunnel_client", delayed_install):
            updating = asyncio.create_task(updater.async_update_tunnel_client(manager, data))
            await entered.wait()
            await manager.stop()
            release.set()
            with self.assertRaisesRegex(Exception, "superseded"):
                await updating
        self.assertIsNone(manager.process)
        self.assertEqual(manager.status.state, "stopped")

    async def test_queued_update_and_rollback_cannot_reverse_later_stop(self):
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch, AsyncMock
        from custom_components.hass_codex_tunnel_mcp.tunnel import TunnelManager
        from custom_components.hass_codex_tunnel_mcp.updater import TunnelClientUpdater, UpdateCheckResult
        from custom_components.hass_codex_tunnel_mcp.binary import TunnelClientAsset
        good = self.root/"queued-client"
        good.write_text("#!"+sys.executable+"\nimport sys\nsys.path.insert(0, "+repr(str(REPO/"tests/staging"))+")\n"+(REPO/"tests/staging/admin_transport_fixture.py").read_text());good.chmod(0o700)
        identity = self.hass.data["hass_codex_admin"]["identity"]
        data = {"tunnel_id": "synthetic-tunnel", "api_key": "synthetic-platform-key", "ha_mcp_url": self.base+"/api/hass_codex_admin/mcp", "admin_connection_id": identity.caller(self.bearer).session}
        manager = TunnelManager(lambda force: good, self.root/"queued-run", poll_interval=.03,
            credential_provider=lambda values: identity.transport_credential(values["admin_connection_id"]))
        self.addAsyncCleanup(manager.close)
        updater = TunnelClientUpdater(self.hass, SimpleNamespace(entry_id="queued-update",data=data,options={}), self.root/"bin", lambda: None)
        await updater.async_load()
        updater.state.previous_version = "v0.0.10"
        candidate = UpdateCheckResult("v0.0.11", "v0.0.11", TunnelClientAsset("linux", "amd64", "fixture.zip", "a"*64, "v0.0.11"), None)
        await manager.start(data)
        self.assertTrue(await manager.wait_until_healthy(3))
        with patch.object(updater, "async_check_for_update", AsyncMock(return_value=candidate)), patch("custom_components.hass_codex_tunnel_mcp.updater.ensure_tunnel_client", AsyncMock(return_value=good)):
            await updater._lock.acquire()
            updating = asyncio.create_task(updater.async_update_tunnel_client(manager,data))
            rolling = asyncio.create_task(updater.async_rollback(manager,data))
            await asyncio.sleep(.02)
            await manager.stop()
            updater._lock.release()
            result = await asyncio.gather(updating,rolling,return_exceptions=True)
        self.assertIsInstance(result[0], Exception)
        self.assertIn("superseded", str(result[0]))
        self.assertFalse(result[1])
        self.assertIsNone(manager.process)
        self.assertEqual(manager.status.state,"stopped")

    async def test_wrapper_setup_failure_core_stop_and_native_nonadmin_denial(self):
        import sys
        from types import SimpleNamespace
        from unittest.mock import patch, AsyncMock
        from homeassistant.auth.const import GROUP_ID_READ_ONLY
        import custom_components.hass_codex_tunnel_mcp as integration
        from custom_components.hass_codex_tunnel_mcp.tunnel import TunnelManager
        good = self.root / "lifecycle-client"
        good.write_text("#!"+sys.executable+"\nimport sys\nsys.path.insert(0, "+repr(str(REPO/"tests/staging"))+")\n"+(REPO/"tests/staging/admin_transport_fixture.py").read_text())
        good.chmod(0o700)
        identity = self.hass.data["hass_codex_admin"]["identity"]
        data = {"tunnel_id": "synthetic-tunnel", "api_key": "synthetic-platform-key", "ha_mcp_url": self.base+"/api/hass_codex_admin/mcp", "admin_connection_id": identity.caller(self.bearer).session, "auto_update_tunnel_client": False}
        callbacks = []
        entry = SimpleNamespace(entry_id="synthetic-lifecycle", data=data, options={}, async_on_unload=callbacks.append, add_update_listener=lambda listener: lambda: None)
        managers = []
        def manager_factory(*args, **kwargs):
            manager = TunnelManager(*args, **kwargs, poll_interval=.03)
            managers.append(manager); return manager
        with patch("custom_components.hass_codex_tunnel_mcp.updater.ensure_tunnel_client", AsyncMock(return_value=good)), patch.object(integration, "TunnelManager", manager_factory):
            with patch.object(self.hass.config_entries, "async_forward_entry_setups", AsyncMock(side_effect=RuntimeError("synthetic_platform_failure"))):
                with self.assertRaisesRegex(RuntimeError, "platform_failure"):
                    await integration.async_setup_entry(self.hass, entry)
            self.assertIsNone(managers[0].process)
            self.assertNotIn(entry.entry_id, self.hass.data[integration.DOMAIN])
            with patch.object(self.hass.config_entries, "async_forward_entry_setups", AsyncMock()):
                self.assertTrue(await integration.async_setup_entry(self.hass, entry))
        manager = managers[-1]
        self.addAsyncCleanup(manager.close)
        self.assertTrue(await manager.wait_until_healthy(3))
        child = manager.process
        reader = await self.hass.auth.async_create_user("Synthetic local reader", group_ids=[GROUP_ID_READ_ONLY])
        refresh = await self.hass.auth.async_create_refresh_token(reader, client_id=self.base)
        for service in ("restart_tunnel", "redownload_tunnel_client", "check_tunnel_client_update", "update_tunnel_client", "rollback_tunnel_client"):
            async with self.client.post(self.base+"/api/services/"+integration.DOMAIN+"/"+service, json={}, headers={"Authorization": "Bearer "+self.hass.auth.async_create_access_token(refresh)}) as response:
                self.assertEqual(response.status, 401, service)
        self.assertIs(manager.process, child)
        await self.hass.async_stop()
        self.assertIsNotNone(child.returncode)
        self.assertIsNone(manager.process)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            await manager.start(data)

    async def test_native_owner_oauth_pkce_exchange_refresh_revoke_and_connector_separation(self):
        import base64, hashlib, secrets
        provider = self.hass.auth.get_auth_provider("homeassistant", None)
        password = secrets.token_urlsafe(24)
        await provider.async_add_auth("synthetic_owner", password)
        credential = await provider.async_get_or_create_credentials({"username": "synthetic_owner"})
        await self.hass.auth.async_link_user(self.owner, credential)
        async with self.client.get(self.base+"/.well-known/oauth-authorization-server") as response:
            self.assertEqual(response.status, 200)
            metadata = await response.json()
            self.assertEqual(metadata["token_endpoint"], self.base+"/auth/token")
            self.assertIn("S256", metadata["code_challenge_methods_supported"])
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        async def login():
            async with self.client.post(self.base+"/auth/login_flow", json={"client_id": self.base, "handler": ["homeassistant", None], "redirect_uri": self.base+"/auth/callback", "code_challenge": challenge, "code_challenge_method": "S256"}) as response:
                self.assertEqual(response.status, 200)
                flow = await response.json()
            async with self.client.post(self.base+"/auth/login_flow/"+flow["flow_id"], json={"client_id": self.base, "username": "synthetic_owner", "password": password}) as response:
                self.assertEqual(response.status, 200)
                result = await response.json()
                self.assertEqual(result["type"], "create_entry", result)
                return result["result"]
        code = await login()
        async with self.client.post(self.base+"/auth/token", data={"grant_type": "authorization_code", "client_id": self.base, "code": code, "code_verifier": "wrong"}) as response:
            self.assertEqual(response.status, 400)
        code = await login()
        exchange = {"grant_type": "authorization_code", "client_id": self.base, "code": code, "code_verifier": verifier}
        async with self.client.post(self.base+"/auth/token", data=exchange) as response:
            self.assertEqual(response.status, 200)
            tokens = await response.json()
        async with self.client.post(self.base+"/auth/token", data=exchange) as response:
            self.assertEqual(response.status, 400)
        refresh = {"grant_type": "refresh_token", "client_id": self.base, "refresh_token": tokens["refresh_token"]}
        async with self.client.post(self.base+"/auth/token", data={**refresh, "client_id": self.base+"/wrong-client"}) as response:
            self.assertEqual(response.status, 400)
        async with self.client.post(self.base+"/auth/token", data=refresh) as response:
            self.assertEqual(response.status, 200)
            refreshed = await response.json()
        async with self.client.get(self.base+"/api/config", headers={"Authorization": "Bearer "+refreshed["access_token"]}) as response:
            self.assertEqual(response.status, 200)
        async with self.client.post(self.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+refreshed["access_token"]}) as response:
            self.assertEqual(response.status, 401)
        async with self.client.post(self.base+"/auth/token", data={"action": "revoke", "token": tokens["refresh_token"]}) as response:
            self.assertEqual(response.status, 200)
        async with self.client.post(self.base+"/auth/token", data=refresh) as response:
            self.assertEqual(response.status, 400)
        async with self.client.get(self.base+"/api/config", headers={"Authorization": "Bearer "+refreshed["access_token"]}) as response:
            self.assertEqual(response.status, 401)
        self.assertNotIn("error", await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"}))

    async def test_native_cover_media_feedback_and_group_dependencies(self):
        from homeassistant.components.cover import CoverEntity, CoverEntityFeature
        from homeassistant.components.media_player import MediaPlayerEntity, MediaPlayerEntityFeature, MediaPlayerState
        self.assertTrue(await async_setup_component(self.hass, "cover", {}))
        self.assertTrue(await async_setup_component(self.hass, "media_player", {}))
        class SyntheticCover(CoverEntity):
            _attr_name = "Synthetic cover"
            _attr_unique_id = "owned-cover"
            _attr_should_poll = False
            _attr_supported_features = CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE
            _attr_is_closed = True
            async def async_open_cover(device, **kwargs):
                device._attr_is_closed = False;device.async_write_ha_state()
            async def async_close_cover(device, **kwargs):
                device._attr_is_closed = True;device.async_write_ha_state()
        class SyntheticMedia(MediaPlayerEntity):
            _attr_name = "Synthetic media"
            _attr_unique_id = "owned-media"
            _attr_should_poll = False
            _attr_supported_features = MediaPlayerEntityFeature.PLAY | MediaPlayerEntityFeature.PAUSE
            _attr_state = MediaPlayerState.PAUSED
            async def async_media_play(device):
                device._attr_state = MediaPlayerState.PLAYING;device.async_write_ha_state()
            async def async_media_pause(device):
                device._attr_state = MediaPlayerState.PAUSED;device.async_write_ha_state()
        cover, media = SyntheticCover(), SyntheticMedia()
        await self.hass.data["cover"].async_add_entities([cover])
        await self.hass.data["media_player"].async_add_entities([media])
        for commands in (("cover.open_cover", "media_player.media_play"), ("cover.close_cover", "media_player.media_pause")):
            task = await self.approved([{ "family": "service", "action": "call", "target": command, "value": {"entity_ids": [device.entity_id], "data": {}}} for command, device in zip(commands, (cover, media))])
            result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
            self.assertNotIn("error", result, result)
            self.assertEqual([item["status"] for item in result["operations"]], ["applied", "applied"])
        helper = await self.approved([{ "family": "input_boolean", "action": "create", "target": "group_member", "value": {"name": "Group member"}}])
        args = {"task": helper["id"], "plan_hash": helper["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertTrue(await async_setup_component(self.hass, "group", {"group": {"synthetic_dependents": {"entities": ["input_boolean.group_member"]}}}))
        await self.hass.async_block_till_done()
        self.assertEqual(await self.tool("admin_rollback", args), {"error": "referenced_object_requires_explicit_repair"})
        self.assertIsNotNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "group_member"}))

    async def test_connected_native_script_create_readback_replay_and_rollback(self):
        initialized = await self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "isolated-test", "version": "1"}})
        self.assertEqual(initialized["result"]["protocolVersion"], "2025-03-26")
        listed = await self.rpc("tools/list")
        self.assertEqual({x["name"] for x in listed["result"]["tools"]}, {"admin_inspect", "admin_propose", "admin_execute", "admin_status", "admin_rollback", "admin_reconcile"})
        operation = {"family": "script", "action": "create", "target": "synthetic_repair", "value": {"alias": "Synthetic repair", "sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([operation])
        result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertNotIn("error", result, result)
        self.assertEqual(result["operations"][0]["status"], "applied")
        defined = await self.tool("admin_inspect", {"family": "script", "target": "synthetic_repair"})
        self.assertEqual(defined, operation["value"])
        replay = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertEqual(replay["operations"][0]["status"], "applied")
        restored = await self.tool("admin_rollback", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertNotIn("error", restored, restored)
        self.assertEqual(restored["operations"][0]["status"], "rolled_back")
        self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": "synthetic_repair"}))

    async def test_automation_fault_diagnosis_and_repair(self):
        broken = {"alias": "Synthetic fault", "triggers": [], "actions": [{"variables": {"fault": "{{ 1 / 0 }}"}}]}
        op = {"family": "automation", "action": "create", "target": "synthetic_fault", "value": broken}
        task = await self.approved([op])
        result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertNotIn("error", result, result)
        await self.hass.async_block_till_done()
        async with self.client.post(self.base+"/api/services/automation/trigger", json={"entity_id": "automation.synthetic_fault"}, headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
            self.assertEqual(response.status, 200)
        traces = await self.tool("admin_inspect", {"family": "automation", "target": "synthetic_fault", "detail": "traces"})
        self.assertTrue(traces, traces)
        trace = await self.tool("admin_inspect", {"family": "automation", "target": "synthetic_fault", "detail": "trace", "run_id": traces[0]["run_id"]})
        self.assertIn("division by zero", json.dumps(trace))
        repaired = {**broken, "actions": [{"delay": "00:00:00"}]}
        repair = await self.approved([{**op, "action": "put", "value": repaired}])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": repair["id"], "plan_hash": repair["hash"]}))
        self.assertEqual((await self.tool("admin_inspect", {"family": "automation", "target": "synthetic_fault"}))["actions"], repaired["actions"])
        self.assertNotIn("error", await self.tool("admin_rollback", {"task": repair["id"], "plan_hash": repair["hash"]}))
        self.assertEqual((await self.tool("admin_inspect", {"family": "automation", "target": "synthetic_fault"}))["actions"], broken["actions"])

    async def test_helper_create_modify_delete_and_restore(self):
        create = {"family": "input_boolean", "action": "create", "target": "synthetic_helper", "value": {"name": "Synthetic helper", "initial": False}}
        task = await self.approved([create, {**create, "action": "put", "value": {"name": "Synthetic helper", "initial": True}}])
        result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertNotIn("error", result, result)
        self.assertEqual([x["status"] for x in result["operations"]], ["applied", "applied"])
        self.assertEqual((await self.tool("admin_inspect", {"family": "input_boolean", "target": "synthetic_helper"}))["initial"], True)
        deletion = await self.approved([{**create, "action": "delete", "value": None}])
        self.assertEqual(deletion["plan"]["effects"][0][0], "destructive")
        self.assertNotIn("error", await self.tool("admin_execute", {"task": deletion["id"], "plan_hash": deletion["hash"]}))
        self.assertIsNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "synthetic_helper"}))
        self.assertNotIn("error", await self.tool("admin_rollback", {"task": deletion["id"], "plan_hash": deletion["hash"]}))
        self.assertEqual((await self.tool("admin_inspect", {"family": "input_boolean", "target": "synthetic_helper"}))["initial"], True)
        self.assertNotIn("error", await self.tool("admin_rollback", {"task": task["id"], "plan_hash": task["hash"]}))
        self.assertIsNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "synthetic_helper"}))

    async def test_dashboard_structure_metadata_and_delete_restore(self):
        op = {"family": "dashboard", "action": "create", "target": "synthetic-board", "value": {"title": "Synthetic board", "icon": "mdi:shield", "require_admin": False, "show_in_sidebar": False, "config": {"views": [{"title": "Test", "cards": [{"type": "markdown", "content": "Untrusted <script>alert(1)</script>"}]}]}}}
        task = await self.approved([op])
        result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertNotIn("error", result, result)
        self.assertEqual(await self.tool("admin_inspect", {"family": "dashboard", "target": op["target"]}), op["value"])
        edited = {**op["value"], "config": {"views": [{"title": "Repair", "cards": []}]}}
        task2 = await self.approved([{**op, "action": "put", "value": edited}])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": task2["id"], "plan_hash": task2["hash"]}))
        deletion = await self.approved([{**op, "action": "delete", "value": None}])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": deletion["id"], "plan_hash": deletion["hash"]}))
        self.assertNotIn("error", await self.tool("admin_rollback", {"task": deletion["id"], "plan_hash": deletion["hash"]}))
        self.assertEqual(await self.tool("admin_inspect", {"family": "dashboard", "target": op["target"]}), edited)

    async def test_same_script_two_edits_one_approval_reverse_rollback(self):
        import time
        op = {"family": "script", "action": "create", "target": "bounded_repair", "value": {"alias": "Step 1", "sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op, {**op, "action": "put", "value": {**op["value"], "alias": "Step 2"}}, {**op, "action": "put", "value": {**op["value"], "alias": "Step 3"}}])
        started = time.perf_counter()
        result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        execute_ms = (time.perf_counter()-started)*1000
        self.assertNotIn("error", result, result)
        self.assertEqual([x["status"] for x in result["operations"]], ["applied"]*3)
        self.assertEqual((await self.tool("admin_inspect", {"family": "script", "target": op["target"]}))["alias"], "Step 3")
        started = time.perf_counter()
        result = await self.tool("admin_rollback", {"task": task["id"], "plan_hash": task["hash"]})
        rollback_ms = (time.perf_counter()-started)*1000
        self.assertNotIn("error", result, result)
        self.assertEqual([x["status"] for x in result["operations"]], ["rolled_back"]*3)
        self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}))
        with self.hass.data["hass_codex_admin"]["engine"].store.transaction() as db:
            approvals = db.execute("SELECT count(*) FROM audit WHERE task=? AND event='approved'", (task["id"],)).fetchone()[0]
        self.assertEqual(approvals, 1)
        print("NATIVE_REPAIR_METRICS="+json.dumps({"operations": 3, "approvals": approvals, "execute_ms": round(execute_ms, 2), "rollback_ms": round(rollback_ms, 2)}))

    async def test_approval_ui_registration_and_safe_rendering(self):
        async with self.client.get(self.base+"/hass_codex_admin/panel.js") as response:
            self.assertEqual(response.status, 200)
            source = await response.text()
        self.assertIn("textContent", source)
        self.assertNotIn("innerHTML", source)
        self.assertIn("confirm_effects: true", source)
        # This verifies registered module delivery, not browser/UI rendering.

    async def test_reserved_arguments_unknown_routes_and_no_approval_bypass(self):
        baseline = {"family": "input_boolean", "action": "put", "target": "approved_helper", "value": {"name": "X"}}
        for key in ("input_boolean_id", "type", "id", "entity_id"):
            result = await self.tool("admin_propose", {"operations": [{**baseline, "value": {"name": "X", key: "other_helper"}}]})
            self.assertEqual(result, {"error": "helper_reserved_argument"})
        malformed = [{**baseline, "family": []}, {**baseline, "action": {}}, {**baseline, "target": "../scripts.yaml"}, {**baseline, "family": "service", "action": "call", "target": "script.turn_on", "value": {"entity_ids": ["script.any"], "data": {}}}]
        for op in malformed:
            self.assertIn("error", await self.tool("admin_propose", {"operations": [op]}))
        self.assertTrue((await self.rpc("tools/call", {"name": "call_service", "arguments": {"domain": "script", "service": "turn_on"}}))["result"]["isError"])
        async with self.client.ws_connect(self.base+"/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": self.bearer})
            self.assertEqual((await ws.receive_json())["type"], "auth_invalid")
        healthy = await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"})
        self.assertEqual(healthy["version"], "2026.10.0")

    async def test_revocation_expiry_changed_hash_and_owner_logout(self):
        op = {"family": "script", "action": "create", "target": "revoked_task", "value": {"alias": "Revoked", "sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        self.assertEqual(await self.tool("admin_execute", {**args, "plan_hash": "0"*64}), {"error": "caller_scope_or_policy_changed"})
        self.assertFalse((await self.approval("approve", task=task["id"], plan_hash=task["hash"], confirm_effects=True))["success"])
        self.assertTrue((await self.approval("revoke", **args))["success"])
        self.assertEqual(await self.tool("admin_execute", args), {"error": "approval_revoked"})
        self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}))
        expiring = await self.approved([{**op, "target": "expired_task"}])
        store = self.hass.data["hass_codex_admin"]["engine"].store
        with store.transaction() as db:
            db.execute("UPDATE tasks SET expires=0 WHERE id=?", (expiring["id"],))
        self.assertEqual(await self.tool("admin_execute", {"task": expiring["id"], "plan_hash": expiring["hash"]}), {"error": "approval_required_or_expired"})
        logout = await self.approved([{**op, "target": "owner_logout"}])
        self.hass.auth.async_remove_refresh_token(self.owner_refresh)
        async with self.client.post(self.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+self.bearer}) as response:
            self.assertEqual(response.status, 401)
        self.assertFalse((self.root / "scripts.yaml").read_text().find("owner_logout:") >= 0)

    async def test_connector_expiry_revocation_and_wrong_connection(self):
        identity = self.hass.data["hass_codex_admin"]["identity"]
        task = await self.approved([{ "family": "script", "action": "create", "target": "refresh_test", "value": {"sequence": [{"delay": "00:00:00"}]}}])
        other = await identity.issue(identity.approved_session(self.owner_refresh.id), "Other connection", 1)
        self.assertEqual(await self.tool("admin_status", {"task": task["id"]}, bearer=other["connector_credential"]), {"error": "wrong_caller"})
        original = identity.caller(self.bearer)
        await identity.revoke(original.session)
        async with self.client.post(self.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+self.bearer}) as response:
            self.assertEqual(response.status, 401)
        self.bearer = other["connector_credential"]
        self.assertEqual((await self.tool("admin_inspect", {"family": "system", "target": "core", "detail": "health"}))["version"], "2026.10.0")
        next(iter(identity.connectors.values()))["expires"] = 0
        async with self.client.post(self.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+self.bearer}) as response:
            self.assertEqual(response.status, 401)

    async def test_delete_checks_dashboard_references_and_preserves_object(self):
        helper = {"family": "input_boolean", "action": "create", "target": "referenced_helper", "value": {"name": "Referenced helper"}}
        board = {"family": "dashboard", "action": "create", "target": "reference-board", "value": {"title": "References", "config": {"views": [{"cards": [{"type": "entities", "entities": ["input_boolean.referenced_helper"]}]}]}}}
        task = await self.approved([helper, board])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
        deletion = await self.approved([{**helper, "action": "delete", "value": None}])
        self.assertEqual(await self.tool("admin_execute", {"task": deletion["id"], "plan_hash": deletion["hash"]}), {"error": "referenced_object_requires_explicit_repair"})
        self.assertIsNotNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": helper["target"]}))

    async def test_native_supervisor_adapter_fixed_targets_and_verified_state(self):
        from homeassistant.components.hassio.websocket_api import websocket_supervisor_api
        from homeassistant.components import websocket_api
        calls = []
        states = {"synthetic_addon": {"slug": "synthetic_addon", "version": "1.0.0", "version_latest": "1.1.0", "state": "stopped"}}
        class SyntheticSupervisor:
            async def send_command(supervisor, endpoint, *, method, payload, **kwargs):
                calls.append((endpoint, method, payload))
                parts = endpoint.split("/")
                slug = parts[3] if parts[1] == "store" else parts[2]
                state = states[slug]
                if method == "get":
                    return {"data": {**state, "options": {"password": "never-export-this"}}}
                action = endpoint.rsplit("/", 1)[1]
                if action == "start": state["state"] = "started"
                elif action == "stop": state["state"] = "stopped"
                elif action == "update":
                    self.assertEqual(endpoint, "/store/addons/synthetic_addon/update")
                    self.assertEqual(payload, {"backup": True})
                    state["version"] = state["version_latest"]
                return {"data": {}}
        # Only the upstream Supervisor network boundary is replaced. Actual
        # native WS authentication/handler, engine, dispatch and SQLite execute.
        self.hass.data["hassio"] = SyntheticSupervisor()
        websocket_api.async_register_command(self.hass, websocket_supervisor_api)
        for action in ("start", "update", "stop"):
            value = {"addon": "synthetic_addon", **({"release": "latest"} if action == "update" else {})}
            task = await self.approved([{"family": "maintenance", "action": "call", "target": "hassio.addon_"+action, "value": value}])
            result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
            self.assertNotIn("error", result, result)
            self.assertEqual(result["operations"][0]["status"], "applied")
            self.assertNotIn("never-export-this", json.dumps(result))
        self.assertIn(("/store/addons/synthetic_addon/update", "post", {"backup": True}), calls)
        invalid = await self.tool("admin_propose", {"operations": [{"family": "maintenance", "action": "call", "target": "hassio.addon_update", "value": {"addon": "synthetic_addon", "version": "9.9.9"}}]})
        self.assertEqual(invalid, {"error": "exact_addon_required"})
        task = await self.approved([{"family": "maintenance", "action": "call", "target": "hassio.addon_restart", "value": {"addon": "synthetic_addon"}}])
        self.assertEqual(await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}), {"error": "outcome_requires_reconciliation"})
        self.assertEqual((await self.tool("admin_status", {"task": task["id"]}))["operations"][0]["status"], "uncertain")

    async def test_config_maintenance_supported_and_supervisor_gaps_explicit(self):
        task = await self.approved([{ "family": "maintenance", "action": "call", "target": "homeassistant.check_config", "value": {}}])
        result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertNotIn("error", result, result)
        self.assertEqual(result["operations"][0]["status"], "applied")
        for target, value in (("hassio.addon_restart", {"addon": "synthetic"}), ("hassio.backup_full", {})):
            result = await self.tool("admin_propose", {"operations": [{"family": "maintenance", "action": "call", "target": target, "value": value}]})
            self.assertEqual(result, {"error": "maintenance_not_available_on_this_installation"})

    async def test_interrupted_write_is_reconciled_without_repeating_mutation(self):
        # Fault injection wraps the actual adapter only at the external readback
        # boundary. The mutation still goes through real HA HTTP/native storage.
        from custom_components.hass_codex_admin.model import AdminError
        engine = self.hass.data["hass_codex_admin"]["engine"]
        original = engine.backend.after
        op = {"family": "script", "action": "create", "target": "uncertain_write", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op])
        async def lost_readback(actor, operation):
            await original(actor, operation)
            raise AdminError("backend_unavailable_or_timeout")
        engine.backend.after = lost_readback
        args = {"task": task["id"], "plan_hash": task["hash"]}
        self.assertEqual(await self.tool("admin_execute", args), {"error": "backend_unavailable_or_timeout"})
        engine.backend.after = original
        status = await self.tool("admin_status", {"task": task["id"]})
        self.assertEqual(status["operations"][0]["status"], "uncertain")
        self.assertEqual(await self.tool("admin_execute", args), {"error": "operation_consumed_or_uncertain"})
        result = await self.tool("admin_reconcile", args)
        self.assertNotIn("error", result, result)
        self.assertEqual(result["operations"][0]["status"], "applied")
        self.assertTrue(result["operations"][0]["result"]["mutation_attribution_verified"])
        self.assertNotIn("error", await self.tool("admin_rollback", args))
        self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}))

    async def test_real_concurrent_requests_have_one_effect_and_durable_restart(self):
        import time
        from custom_components.hass_codex_admin.store import TaskStore
        from custom_components.hass_codex_admin.engine import Administrator
        from custom_components.hass_codex_admin.model import AdminError
        engine = self.hass.data["hass_codex_admin"]["engine"]
        actor = self.hass.data["hass_codex_admin"]["identity"].caller(self.bearer)
        op = {"family": "script", "action": "create", "target": "concurrent_repair", "value": {"sequence": [{"delay": "00:00:00"}]}}
        for round_number in range(4):
            task = await self.approved([{**op, "target": op["target"]+str(round_number)}])
            args = {"task": task["id"], "plan_hash": task["hash"]}
            started = time.monotonic()
            results = await asyncio.gather(*(self.tool("admin_execute", args) for _ in range(3)))
            self.assertTrue(all("error" not in r for r in results), results)
            with engine.store.transaction() as db:
                count = db.execute("SELECT count(*) FROM audit WHERE task=? AND event='dispatch_started'", (task["id"],)).fetchone()[0]
            self.assertEqual(count, 1)
            self.assertLess(time.monotonic()-started, 5)
        reopened = TaskStore(engine.store.directory)
        restarted = Administrator(reopened, engine.backend, engine.policy, engine.authenticate, engine.approved_session)
        result = await restarted.execute(actor, **args)
        self.assertEqual(result["operations"][0]["status"], "applied")
        # A committed mutation-intent prefix never becomes fresh after reopen.
        unresolved = await self.approved([{**op, "target": "restart_unresolved"}])
        reopened.claim(unresolved["id"], 0, actor, unresolved["policy"], unresolved["hash"])
        again = Administrator(TaskStore(engine.store.directory), engine.backend, engine.policy, engine.authenticate, engine.approved_session)
        with self.assertRaises(AdminError) as error:
            await again.execute(actor, unresolved["id"], unresolved["hash"])
        self.assertEqual(error.exception.code, "operation_consumed_or_uncertain")
        # Store/engine recreation above is not a whole-process or host reboot.

    async def test_contention_corruption_and_failed_update_stop_without_fallback(self):
        import sqlite3, time
        engine = self.hass.data["hass_codex_admin"]["engine"]
        op = {"family": "script", "action": "create", "target": "corruption_test", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op])
        blocker = sqlite3.connect(engine.store.path, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        try:
            start = time.monotonic()
            self.assertEqual(await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}), {"error": "storage_busy"})
            self.assertLess(time.monotonic()-start, 1)
        finally:
            blocker.rollback();blocker.close()
        self.assertNotIn("error", await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
        bad = await self.approved([{**op, "action": "put", "value": {"sequence": "not a native HA script"}}])
        self.assertEqual(await self.tool("admin_execute", {"task": bad["id"], "plan_hash": bad["hash"]}), {"error": "backend_rejected"})
        self.assertEqual(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}), op["value"])
        with engine.store.transaction() as db:
            db.execute("UPDATE tasks SET plan=? WHERE id=?", ('{"v":1}', task["id"]))
        self.assertEqual(await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}), {"error": "stored_plan_integrity"})

    async def test_native_synthetic_device_service_feedback_and_no_replay(self):
        from homeassistant.components.switch import SwitchEntity
        self.assertTrue(await async_setup_component(self.hass, "switch", {}))
        class SyntheticSwitch(SwitchEntity):
            _attr_name = "Synthetic lamp"
            _attr_unique_id = "task-owned-switch"
            _attr_is_on = False
            _attr_should_poll = False
            changes = 0
            async def async_turn_on(device, **kwargs):
                device.changes += 1
                device._attr_is_on = True
                device.async_write_ha_state()
            async def async_turn_off(device, **kwargs):
                device.changes += 1
                device._attr_is_on = False
                device.async_write_ha_state()
        device = SyntheticSwitch()
        second = SyntheticSwitch()
        second._attr_name = "Synthetic second lamp"
        second._attr_unique_id = "task-owned-second-switch"
        await self.hass.data["switch"].async_add_entities([device, second])
        self.assertEqual(device.entity_id, "switch.synthetic_lamp")
        op = {"family": "service", "action": "call", "target": "switch.turn_on", "value": {"entity_ids": [device.entity_id], "data": {}}}
        task = await self.approved([op, {**op, "value": {**op["value"], "entity_ids": [second.entity_id]}}])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertTrue(device.is_on)
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertEqual(device.changes, 1)
        self.assertTrue(second.is_on)
        self.assertEqual(second.changes, 1)
        self.assertEqual(await self.tool("admin_propose", {"operations": [op, op]}), {"error": "overlapping_device_task_not_supported"})
        async with self.client.post(self.base+"/api/services/switch/turn_off", json={"entity_id": device.entity_id}, headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(await self.tool("admin_execute", args), {"error": "recorded_result_has_drift"})
        self.assertEqual((device.changes, second.changes), (2, 1))
        # Device is a real HA entity/service fixture; no physical device tested.

    async def test_native_reconfigure_and_reauth_owner_handoff_secret_isolation(self):
        import probatio as vol
        from unittest.mock import patch
        from homeassistant.config_entries import ConfigFlow, ConfigEntry, ConfigEntryState, HANDLERS
        self.assertTrue(await async_setup_component(self.hass, "sun", {}))
        await self.hass.async_block_till_done()
        entry = self.hass.config_entries.async_entries("sun")[0]
        secret = "synthetic-private-input-not-for-chatgpt"
        class SyntheticFlow(ConfigFlow):
            VERSION = 1
            async def async_step_reconfigure(flow, user_input=None):
                if user_input is None or user_input.get("password") != secret:
                    return flow.async_show_form(step_id="reconfigure", data_schema=vol.Schema({vol.Required("password"): str}), errors={} if user_input is None else {"base": "invalid_auth"})
                return flow.async_update_reload_and_abort(flow._get_reconfigure_entry(), data_updates={"fixture_verified": True})
            async def async_step_reauth(flow, entry_data):
                return await flow.async_step_reauth_confirm()
            async def async_step_reauth_confirm(flow, user_input=None):
                if user_input is None or user_input.get("password") != secret:
                    return flow.async_show_form(step_id="reauth_confirm", data_schema=vol.Schema({vol.Required("password"): str}), errors={} if user_input is None else {"base": "invalid_auth"})
                return flow.async_update_reload_and_abort(flow._get_reauth_entry(), data_updates={"fixture_reauth": True})
        for action in ("reconfigure", "reauth"):
            with patch.dict(HANDLERS, {"sun": SyntheticFlow}):
                task = await self.approved([{"family": "integration", "action": action, "target": entry.entry_id, "value": {}}])
                args = {"task": task["id"], "plan_hash": task["hash"]}
                self.assertEqual(await self.tool("admin_execute", args), {"error": "outcome_requires_reconciliation"})
                pending = await self.tool("admin_status", {"task": task["id"]})
                self.assertEqual(pending["operations"][0]["status"], "uncertain")
                command = {"type": "hass_codex_admin/flow", "task": task["id"], "plan_hash": task["hash"], "operation": 0}
                state = await self.native_ws({**command, "action": "status"})
                self.assertTrue(state["success"], state)
                if not state["result"]["fields"]:
                    state = await self.native_ws({**command, "action": "submit"})
                self.assertEqual(state["result"]["fields"][0]["name"], "password")
                # Connector capabilities cannot authenticate this owner channel.
                async with self.client.ws_connect(self.base+"/api/websocket") as ws:
                    await ws.receive_json(); await ws.send_json({"type": "auth", "access_token": self.bearer})
                    self.assertEqual((await ws.receive_json())["type"], "auth_invalid")
                bad = await self.native_ws({**command, "action": "submit", "input": {"password": "incorrect"}})
                self.assertTrue(bad["success"])
                self.assertTrue(bad["result"]["owner_input_required"])
                done = await self.native_ws({**command, "action": "submit", "input": {"password": secret}})
                self.assertTrue(done["success"], done)
                self.assertTrue(done["result"]["completed"])
                self.assertFalse(done["result"]["external_authentication_verified"])
                self.assertFalse((await self.native_ws({**command, "action": "submit", "input": {"password": secret}}))["success"])
                history = await self.tool("admin_status", {"task": task["id"]})
                self.assertEqual(history["operations"][0]["status"], "applied")
                self.assertNotIn(secret, json.dumps(history))
                await self.hass.async_block_till_done()

    async def test_flow_lock_order_queued_revoke_and_cleanup_after_revocation(self):
        import probatio as vol
        from unittest.mock import patch
        from homeassistant.config_entries import ConfigFlow, HANDLERS
        from custom_components.hass_codex_admin.model import AdminError
        self.assertTrue(await async_setup_component(self.hass, "sun", {})); await self.hass.async_block_till_done()
        entry = self.hass.config_entries.async_entries("sun")[0]
        starts = []
        class SyntheticFlow(ConfigFlow):
            VERSION = 1
            async def async_step_reconfigure(flow, user_input=None):
                starts.append(True)
                return flow.async_show_form(step_id="reconfigure", data_schema=vol.Schema({vol.Required("password"): str}))
        engine = self.hass.data["hass_codex_admin"]["engine"]
        identity = self.hass.data["hass_codex_admin"]["identity"]
        flows = engine.backend.flows
        op = {"family": "integration", "action": "reconfigure", "target": entry.entry_id, "value": {}}
        with patch.dict(HANDLERS, {"sun": SyntheticFlow}):
            task = await self.approved([op]); args = {"task": task["id"], "plan_hash": task["hash"]}
            await flows.lock.acquire()
            actor = identity.caller(self.bearer)
            work = asyncio.create_task(engine.execute(actor, **args))
            try:
                async with asyncio.timeout(2):
                    while (await engine.db("get", task["id"]))["operations"][0]["status"] != "dispatching": await asyncio.sleep(.01)
                self.assertTrue((await self.approval("revoke", **args))["success"])
            finally: flows.lock.release()
            with self.assertRaises(AdminError) as error: await work
            self.assertEqual(error.exception.code, "approval_revoked")
            self.assertEqual(starts, [])
            good = await self.approved([op]); args = {"task": good["id"], "plan_hash": good["hash"]}
            self.assertEqual(await self.tool("admin_execute", args), {"error": "outcome_requires_reconciliation"})
            command = {"type": "hass_codex_admin/flow", "action": "status", "operation": 0, **args}
            owner = identity.approved_session(self.owner_refresh.id)
            await engine.lock.acquire()
            waiting = asyncio.create_task(flows.command(engine, identity, owner, command))
            await asyncio.sleep(.01)
            self.assertFalse(flows.lock.locked())  # no ABBA lock inversion
            engine.lock.release(); self.assertTrue((await waiting)["owner_input_required"])
            self.assertTrue((await self.approval("revoke", **args))["success"])
            cancelled = await self.native_ws({**command, "action": "cancel"})
            self.assertTrue(cancelled["success"], cancelled)
            self.assertEqual(flows.active, {})
            replacement = await self.approved([op]); args = {"task": replacement["id"], "plan_hash": replacement["hash"]}
            self.assertEqual(await self.tool("admin_execute", args), {"error": "outcome_requires_reconciliation"})
            # Owner logout while waiting defeats cleanup too; a retired task
            # grants no continuation and cleanup still requires a current owner.
            await engine.lock.acquire()
            waiting = asyncio.create_task(flows.command(engine, identity, owner, {**command, **args, "action": "cancel"}))
            await asyncio.sleep(.01)
            self.hass.auth.async_remove_refresh_token(self.owner_refresh)
            engine.lock.release()
            with self.assertRaises(AdminError) as error: await waiting
            self.assertEqual(error.exception.code, "owner_frontend_session_required")

    async def test_bound_helper_interrupted_rollback_reconciles_actual_id(self):
        from custom_components.hass_codex_admin.model import AdminError
        from unittest.mock import patch
        task = await self.approved([
            {"family": "input_boolean", "action": "allocate", "target": "hint", "value": {"name": "Actual binding"}},
            {"family": "input_boolean", "action": "put", "target": "@0", "value": {"icon": "mdi:shield"}},
        ])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        engine = self.hass.data["hass_codex_admin"]["engine"]
        with patch.object(engine.backend, "after", side_effect=AdminError("backend_unavailable_or_timeout")):
            self.assertEqual(await self.tool("admin_rollback", args), {"error": "backend_unavailable_or_timeout"})
        recovered = await self.tool("admin_reconcile", args)
        self.assertNotIn("error", recovered, recovered)
        self.assertEqual(recovered["operations"][1]["status"], "rolled_back")
        self.assertNotIn("error", await self.tool("admin_rollback", args))
        self.assertIsNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "actual_binding"}))

    async def test_native_flow_success_without_completed_reload_stays_uncertain(self):
        import probatio as vol
        from unittest.mock import patch, AsyncMock
        from homeassistant.config_entries import ConfigFlow, HANDLERS
        self.assertTrue(await async_setup_component(self.hass, "sun", {})); await self.hass.async_block_till_done()
        entry = self.hass.config_entries.async_entries("sun")[0]
        class SyntheticFlow(ConfigFlow):
            VERSION = 1
            async def async_step_reconfigure(flow, user_input=None):
                if user_input is None: return flow.async_show_form(step_id="reconfigure", data_schema=vol.Schema({vol.Required("name"): str}))
                return flow.async_update_reload_and_abort(flow._get_reconfigure_entry(), data_updates={"name": user_input["name"]})
        with patch.dict(HANDLERS, {"sun": SyntheticFlow}):
            task = await self.approved([{"family": "integration", "action": "reconfigure", "target": entry.entry_id, "value": {}}])
            args = {"task": task["id"], "plan_hash": task["hash"]}
            self.assertEqual(await self.tool("admin_execute", args), {"error": "outcome_requires_reconciliation"})
            with patch.object(self.hass.config_entries, "async_reload", AsyncMock(return_value=False)):
                outcome = await self.native_ws({"type": "hass_codex_admin/flow", "action": "submit", "operation": 0, "input": {"name": "Owner change"}, **args})
            self.assertFalse(outcome["success"])
            self.assertEqual(outcome["error"]["code"], "native_flow_reload_not_verified")
            self.assertEqual((await self.tool("admin_status", {"task": task["id"]}))["operations"][0]["status"], "uncertain")

    async def test_allocated_helper_followup_binding_and_replay(self):
        engine = self.hass.data["hass_codex_admin"]["engine"]
        task = await self.approved([
            {"family": "input_boolean", "action": "allocate", "target": "allocation_hint", "value": {"name": "Server assigned object"}},
            {"family": "input_boolean", "action": "put", "target": "@0", "value": {"icon": "mdi:shield"}},
        ])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        completed = await self.tool("admin_execute", args)
        self.assertNotIn("error", completed, completed)
        self.assertEqual(completed["operations"][0]["result"]["created_target"], "server_assigned_object")
        self.assertEqual((await self.tool("admin_inspect", {"family": "input_boolean", "target": "server_assigned_object"}))["icon"], "mdi:shield")
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertNotIn("error", await self.tool("admin_rollback", args))
        self.assertIsNone(await self.tool("admin_inspect", {"family": "input_boolean", "target": "server_assigned_object"}))
        self.assertEqual(await self.tool("admin_propose", {"operations": [{"family": "input_boolean", "action": "delete", "target": "@0", "value": None}]}), {"error": "invalid_allocation_reference"})

    async def test_independent_editor_during_dispatch_exposes_platform_limit_and_after_detects_drift(self):
        from unittest.mock import patch
        engine = self.hass.data["hass_codex_admin"]["engine"]
        original = {"alias": "Original", "sequence": [{"delay": "00:00:00"}]}
        op = {"family": "script", "action": "create", "target": "editor_gap", "value": original}
        seeded = await self.approved([op])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": seeded["id"], "plan_hash": seeded["hash"]}))
        async def local_edit(alias):
            async with self.client.post(self.base+"/api/config/script/config/editor_gap", json={**original, "alias": alias}, headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
                self.assertEqual(response.status, 200)
        desired = {**original, "alias": "Project edit"}
        task = await self.approved([{**op, "action": "put", "value": desired}]); args = {"task": task["id"], "plan_hash": task["hash"]}
        check = engine.backend.final_check
        raced = False
        async def gap():
            nonlocal raced
            await check()
            if not raced:
                raced = True; await local_edit("Concurrent local edit")
        with patch.object(engine.backend, "final_check", gap):
            applied = await self.tool("admin_execute", args)
        # This is evidence of HA's missing CAS, NOT a passing concurrent-edit
        # guarantee: a local editor violating the proposed named-object window
        # can be overwritten in the final-check/send gap. Production mode stays
        # unaccepted until the owner explicitly accepts this cooperation policy.
        self.assertEqual(applied["operations"][0]["status"], "applied")
        self.assertEqual((await self.tool("admin_inspect", {"family": "script", "target": "editor_gap"}))["alias"], "Project edit")
        followup = await self.approved([{**op, "action": "put", "value": {**original, "alias": "Second project edit"}}])
        args = {"task": followup["id"], "plan_hash": followup["hash"]}
        write = engine.backend.write
        async def after_dispatch(actor, operation):
            result = await write(actor, operation); await local_edit("Local edit after dispatch"); return result
        with patch.object(engine.backend, "write", after_dispatch):
            self.assertEqual(await self.tool("admin_execute", args), {"error": "outcome_requires_reconciliation"})
        self.assertEqual(await self.tool("admin_rollback", args), {"error": "operation_consumed_or_uncertain"})
        self.assertEqual((await self.tool("admin_inspect", {"family": "script", "target": "editor_gap"}))["alias"], "Local edit after dispatch")

    async def test_edit_window_is_explicit_policy_and_owner_consent_not_cas(self):
        engine = self.hass.data["hass_codex_admin"]["engine"]
        op = {"family": "script", "action": "create", "target": "edit_window", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.tool("admin_propose", {"operations": [op]})
        denied = await self.approval("approve", task=task["id"], plan_hash=task["hash"], confirm_effects=True, confirm_edit_window=False)
        self.assertFalse(denied["success"])
        self.assertEqual(denied["error"]["code"], "explicit_named_object_edit_window_required")
        engine.policy["edit_coordination"] = "unaccepted"
        denied = await self.approval("approve", task=task["id"], plan_hash=task["hash"], confirm_effects=True)
        self.assertEqual(denied["error"]["code"], "owner_edit_policy_acceptance_required")
        engine.policy["edit_coordination"] = "owner_window"
        self.assertTrue((await self.approval("approve", task=task["id"], plan_hash=task["hash"], confirm_effects=True))["success"])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))

    async def test_actual_calculated_integration_reload_and_readback(self):
        self.assertTrue(await async_setup_component(self.hass, "sun", {}))
        await self.hass.async_block_till_done()
        entries = self.hass.config_entries.async_entries("sun")
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.state.value, "loaded")
        task = await self.approved([{ "family": "integration", "action": "reload", "target": entry.entry_id, "value": {}}])
        result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
        self.assertNotIn("error", result, result)
        self.assertEqual(result["operations"][0]["status"], "applied")
        observed = await self.tool("admin_inspect", {"family": "integration", "target": entry.entry_id})
        self.assertEqual(observed["state"], "loaded")

    async def test_all_native_helper_families_create_and_restore(self):
        definitions = {"input_number": {"min": 0, "max": 10, "step": 1}, "input_text": {}, "input_select": {"options": ["one", "two"]}, "input_datetime": {"has_date": True, "has_time": True}, "input_button": {}, "counter": {}, "timer": {"duration": "00:01:00"}}
        for family, fields in definitions.items():
            self.assertTrue(await async_setup_component(self.hass, family, {family: {}}))
            target = "synthetic_"+family
            op = {"family": family, "action": "create", "target": target, "value": {"name": "Synthetic "+family, **fields}}
            task = await self.approved([op])
            result = await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
            self.assertNotIn("error", result, {"family": family, "result": result})
            self.assertEqual(result["operations"][0]["status"], "applied")
            result = await self.tool("admin_rollback", {"task": task["id"], "plan_hash": task["hash"]})
            self.assertNotIn("error", result, {"family": family, "result": result})
            self.assertIsNone(await self.tool("admin_inspect", {"family": family, "target": target}))

    async def test_revoke_after_committed_claim_prevents_undispatched_write(self):
        from custom_components.hass_codex_admin.model import AdminError
        engine = self.hass.data["hass_codex_admin"]["engine"]
        actor = self.hass.data["hass_codex_admin"]["identity"].caller(self.bearer)
        op = {"family": "script", "action": "create", "target": "claim_revoked", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        claimed, resume = asyncio.Event(), asyncio.Event()
        original = engine.db
        async def boundary(method, *values, **kwargs):
            result = await original(method, *values, **kwargs)
            if method == "claim":
                claimed.set()
                await resume.wait()
            return result
        engine.db = boundary
        work = asyncio.create_task(engine.execute(actor, **args))
        try:
            await asyncio.wait_for(claimed.wait(), 2)
            self.assertTrue((await self.approval("revoke", **args))["success"])
            resume.set()
            with self.assertRaises(AdminError) as error:
                await work
            self.assertEqual(error.exception.code, "approval_revoked")
            self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}))
        finally:
            resume.set()
            if not work.done():
                work.cancel()
                await asyncio.gather(work, return_exceptions=True)
            engine.db = original

    async def test_cancel_after_actual_write_retains_uncertainty_and_recovers(self):
        engine = self.hass.data["hass_codex_admin"]["engine"]
        actor = self.hass.data["hass_codex_admin"]["identity"].caller(self.bearer)
        op = {"family": "script", "action": "create", "target": "cancelled_write", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        written, release = asyncio.Event(), asyncio.Event()
        original = engine.backend.write
        async def interrupted(actor, operation):
            result = await original(actor, operation)
            written.set()
            await release.wait()
            return result
        engine.backend.write = interrupted
        work = asyncio.create_task(engine.execute(actor, **args))
        try:
            await asyncio.wait_for(written.wait(), 2)
            work.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await work
            self.assertFalse(engine.lock.locked())
            result = await self.tool("admin_status", {"task": task["id"]})
            self.assertEqual(result["operations"][0]["status"], "uncertain")
        finally:
            release.set();engine.backend.write = original
        self.assertEqual(await self.tool("admin_reconcile", args), {"error": "creation_ownership_requires_owner_reconciliation"})
        self.assertEqual(await self.tool("admin_rollback", args), {"error": "operation_consumed_or_uncertain"})
        self.assertEqual(await self.tool("admin_inspect", {"family": "script", "target": op["target"]}), op["value"])
        # Recovery is a new exact owner-approved deletion, not inferred ownership.
        cleanup = await self.approved([{**op, "action": "delete", "value": None}])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": cleanup["id"], "plan_hash": cleanup["hash"]}))

    async def test_future_store_version_private_files_and_debug_secret_suppression(self):
        import io, logging, os, sqlite3
        from custom_components.hass_codex_admin.store import TaskStore
        from custom_components.hass_codex_admin.model import AdminError
        with tempfile.TemporaryDirectory(prefix="ha-admin-schema-") as root:
            store = TaskStore(root)
            self.assertEqual(os.stat(store.path).st_mode & 0o777, 0o600)
            db = sqlite3.connect(store.path)
            try:
                db.execute("PRAGMA user_version=99")
            finally:
                db.close()
            with self.assertRaises(AdminError) as error:
                TaskStore(root)
            self.assertEqual(error.exception.code, "unsupported_storage_version")
        stream = io.StringIO();handler = logging.StreamHandler(stream)
        logger = logging.getLogger("homeassistant.components.mcp_server.http")
        old = logger.level;logger.setLevel(logging.DEBUG);logger.addHandler(handler)
        try:
            op = {"family": "script", "action": "create", "target": "literal_secret", "value": {"alias": "Bearer synthetic-do-not-log", "sequence": [{"delay": "00:00:00"}]}}
            self.assertEqual(await self.tool("admin_propose", {"operations": [op]}), {"error": "literal_secrets_not_supported"})
        finally:
            logger.removeHandler(handler);logger.setLevel(old)
        self.assertNotIn("synthetic-do-not-log", stream.getvalue())
        self.assertIn("payload omitted", stream.getvalue())

    async def test_actual_core_backup_is_created_and_observed_once(self):
        self.assertTrue(await async_setup_component(self.hass, "backup", {"backup": {}}))
        await self.hass.async_block_till_done()
        task = await self.approved([{ "family": "maintenance", "action": "call", "target": "backup.create", "value": {}}])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        result = await self.tool("admin_execute", args)
        self.assertNotIn("error", result, {"result": result, "status": await self.tool("admin_status", {"task": task["id"]})})
        self.assertEqual(result["operations"][0]["status"], "applied")
        self.assertEqual(len(result["operations"][0]["after_state"]["backups"]), 1)
        self.assertNotIn("error", await self.tool("admin_execute", args))
        archives = list(self.root.rglob("*.tar"))
        self.assertEqual(len(archives), 1)
        self.assertGreater(archives[0].stat().st_size, 0)
        # Synthetic HA backup only. No HAOS/host restore is executed or proved.

    async def test_helper_merge_rename_delete_and_exact_identity_restoration(self):
        op = {"family": "input_boolean", "action": "create", "target": "original_name", "value": {"name": "Original name", "icon": "mdi:shield", "initial": False}}
        task = await self.approved([op])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
        rename = await self.approved([{**op, "action": "put", "value": {"name": "New name"}}])
        outcome = await self.tool("admin_execute", {"task": rename["id"], "plan_hash": rename["hash"]})
        self.assertNotIn("error", outcome, await self.tool("admin_status", {"task": rename["id"]}))
        before = await self.tool("admin_inspect", {"family": op["family"], "target": op["target"]})
        self.assertEqual(before, {"id": "original_name", "name": "New name", "icon": "mdi:shield", "initial": False})
        deletion = await self.approved([{**op, "action": "delete", "value": None}])
        args = {"task": deletion["id"], "plan_hash": deletion["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertNotIn("error", await self.tool("admin_rollback", args))
        self.assertEqual(await self.tool("admin_inspect", {"family": op["family"], "target": op["target"]}), before)
        self.assertIsNone(await self.tool("admin_inspect", {"family": op["family"], "target": "new_name"}))

    async def test_partial_task_rolls_back_only_applied_prefix(self):
        op = {"family": "script", "action": "create", "target": "prefix_first", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op, {**op, "target": "prefix_second"}])
        async with self.client.post(self.base+"/api/config/script/config/prefix_second", json=op["value"], headers={"Authorization": "Bearer "+self.owner_bearer}) as response:
            self.assertEqual(response.status, 200)
        args = {"task": task["id"], "plan_hash": task["hash"]}
        self.assertEqual(await self.tool("admin_execute", args), {"error": "object_changed_requires_new_approval"})
        result = await self.tool("admin_rollback", args)
        self.assertNotIn("error", result, result)
        self.assertEqual([x["status"] for x in result["operations"]], ["rolled_back", "pending"])
        self.assertIsNone(await self.tool("admin_inspect", {"family": "script", "target": "prefix_first"}))
        self.assertIsNotNone(await self.tool("admin_inspect", {"family": "script", "target": "prefix_second"}))

    async def test_helper_add_field_rollback_and_delete_recreate_one_approval(self):
        op = {"family": "input_boolean", "action": "create", "target": "recreate_helper", "value": {"name": "Recreate helper", "initial": False}}
        task = await self.approved([op])
        self.assertNotIn("error", await self.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
        changed = await self.approved([{**op, "action": "put", "value": {"name": "Recreate helper", "icon": "mdi:shield"}}])
        args = {"task": changed["id"], "plan_hash": changed["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertNotIn("error", await self.tool("admin_rollback", args))
        original = await self.tool("admin_inspect", {"family": op["family"], "target": op["target"]})
        self.assertNotIn("icon", original)
        replacement = await self.approved([{**op, "action": "delete", "value": None}, {**op, "value": {**op["value"], "initial": True}}])
        args = {"task": replacement["id"], "plan_hash": replacement["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertNotIn("error", await self.tool("admin_rollback", args))
        self.assertEqual(await self.tool("admin_inspect", {"family": op["family"], "target": op["target"]}), original)

    async def test_rollback_creation_checks_new_dependents(self):
        op = {"family": "input_boolean", "action": "create", "target": "new_dependent", "value": {"name": "New dependent"}}
        task = await self.approved([op]);args = {"task": task["id"], "plan_hash": task["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        board = await self.approved([{"family": "dashboard", "action": "create", "target": "dependent-board", "value": {"title": "Dependent", "config": {"views": [{"cards": [{"type": "entities", "entities": ["input_boolean.new_dependent"]}]}]}}}])
        board_args = {"task": board["id"], "plan_hash": board["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", board_args))
        self.assertEqual(await self.tool("admin_rollback", args), {"error": "referenced_object_requires_explicit_repair"})
        self.assertIsNotNone(await self.tool("admin_inspect", {"family": op["family"], "target": op["target"]}))
        self.assertNotIn("error", await self.tool("admin_rollback", board_args))
        self.assertNotIn("error", await self.tool("admin_rollback", args))

    async def test_late_thread_completion_cannot_overwrite_reconciliation(self):
        import threading
        from custom_components.hass_codex_admin.model import AdminError
        op = {"family": "script", "action": "create", "target": "late_completion", "value": {"sequence": [{"delay": "00:00:00"}]}}
        task = await self.approved([op])
        args = {"task": task["id"], "plan_hash": task["hash"]}
        engine = self.hass.data["hass_codex_admin"]["engine"]
        original_after = engine.backend.after
        async def lost_ack(*_args):
            raise TimeoutError()
        engine.backend.after = lost_ack
        self.addCleanup(setattr, engine.backend, "after", original_after)
        self.assertIn("error", await self.tool("admin_execute", args))
        entered, release = threading.Event(), threading.Event()
        def late_finish():
            entered.set()
            if not release.wait(3):
                raise AssertionError("test boundary stalled")
            engine.store.finish(task["id"], 0, "uncertain", None, {"late": True}, expected="dispatching")
        pending = asyncio.create_task(asyncio.to_thread(late_finish))
        await asyncio.to_thread(entered.wait, 1)
        try:
            self.assertNotIn("error", await self.tool("admin_reconcile", args))
        finally:
            release.set()
        with self.assertRaises(AdminError) as error:
            await pending
        self.assertEqual(error.exception.code, "stale_operation_completion")
        self.assertEqual((await self.tool("admin_status", {"task": task["id"]}))["operations"][0]["status"], "applied")
        engine.backend.after = original_after
        self.assertNotIn("error", await self.tool("admin_rollback", args))

    async def test_native_light_brightness_and_temperature_feedback(self):
        from homeassistant.components.light import LightEntity, ColorMode
        self.assertTrue(await async_setup_component(self.hass, "light", {}))
        class SyntheticLight(LightEntity):
            _attr_name = "Synthetic light"
            _attr_unique_id = "task-owned-light"
            _attr_is_on = False
            _attr_should_poll = False
            _attr_supported_color_modes = {ColorMode.COLOR_TEMP}
            _attr_color_mode = ColorMode.COLOR_TEMP
            _attr_min_color_temp_kelvin = 1000
            _attr_max_color_temp_kelvin = 10000
            changes = 0
            async def async_turn_on(device, **kwargs):
                device.changes += 1
                device._attr_is_on = True
                device._attr_brightness = kwargs.get("brightness")
                device._attr_color_temp_kelvin = kwargs.get("color_temp_kelvin")
                device.async_write_ha_state()
        device = SyntheticLight()
        await self.hass.data["light"].async_add_entities([device])
        op = {"family": "service", "action": "call", "target": "light.turn_on", "value": {"entity_ids": [device.entity_id], "data": {"brightness": 80, "color_temp_kelvin": 3500}}}
        task = await self.approved([op]);args = {"task": task["id"], "plan_hash": task["hash"]}
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertNotIn("error", await self.tool("admin_execute", args))
        self.assertEqual(device.changes, 1)
        self.assertEqual((device.brightness, device.color_temp_kelvin), (80, 3500))
        self.assertEqual(await self.tool("admin_propose", {"operations": [{**op, "value": {**op["value"], "data": {"rgb_color": [0, 0, 0]}}}]}), {"error": "service_argument_verifier_not_supported"})

    async def test_chunked_backend_read_complete_bounded_and_malformed(self):
        from aiohttp import web
        from custom_components.hass_codex_admin.backend import HABackend, create_session
        from custom_components.hass_codex_admin.model import Actor, AdminError
        async def reply(request):
            response = web.StreamResponse();await response.prepare(request)
            if request.path == "/large":
                await response.write(b"x"*131073)
            elif request.path == "/malformed":
                await response.write(b'{"bad":')
            else:
                await response.write(b'{"value":')
                await asyncio.sleep(.01)
                await response.write(b'"complete"}')
            await response.write_eof()
            return response
        app = web.Application();app.router.add_get("/{path}", reply)
        runner = web.AppRunner(app);await runner.setup();self.addAsyncCleanup(runner.cleanup)
        site = web.TCPSite(runner, "127.0.0.1", 0);await site.start()
        port = site._server.sockets[0].getsockname()[1]
        async with create_session() as session:
            backend = HABackend(f"http://127.0.0.1:{port}", session, credential=lambda actor: actor.bearer)
            actor = Actor("fixture", "fixture", "synthetic-boundary-bearer")
            self.assertEqual(await backend.rest(actor, "GET", "/chunks"), {"value": "complete"})
            for path, code in (("/large", "backend_reply_too_large"), ("/malformed", "invalid_json")):
                with self.assertRaises(AdminError) as error:
                    await backend.rest(actor, "GET", path)
                self.assertEqual(error.exception.code, code)

    async def test_websocket_redirect_never_reaches_redirected_server(self):
        from aiohttp import web
        from custom_components.hass_codex_admin.backend import HABackend, create_session
        from custom_components.hass_codex_admin.model import Actor, AdminError
        # Only the external protocol boundary is substituted with loopback
        # servers. The real aiohttp session/redirect policy is exercised.
        received = []
        async def redirected(request):
            received.append(True)
            ws = web.WebSocketResponse();await ws.prepare(request)
            await ws.send_json({"type": "auth_required"})
            await ws.close()
            return ws
        app = web.Application();app.router.add_get("/api/websocket", redirected)
        target = web.AppRunner(app);await target.setup()
        self.addAsyncCleanup(target.cleanup)
        site = web.TCPSite(target, "127.0.0.1", 0);await site.start()
        target_port = site._server.sockets[0].getsockname()[1]
        async def redirect(request):
            raise web.HTTPFound(f"http://127.0.0.1:{target_port}/api/websocket")
        app = web.Application();app.router.add_get("/api/websocket", redirect)
        source = web.AppRunner(app);await source.setup()
        self.addAsyncCleanup(source.cleanup)
        site = web.TCPSite(source, "127.0.0.1", 0);await site.start()
        source_port = site._server.sockets[0].getsockname()[1]
        async with create_session() as session:
            backend = HABackend(f"http://127.0.0.1:{source_port}", session, credential=lambda actor: actor.bearer)
            with self.assertRaises(AdminError) as error:
                await backend.ws(Actor("fixture", "fixture", "synthetic-boundary-bearer"), {"type": "input_boolean/list"})
            self.assertEqual(error.exception.code, "backend_redirect_forbidden")
        self.assertEqual(received, [])


class WholeProcessRestart(unittest.TestCase):
    def test_native_ha_process_restart_retains_consumption_and_definitions(self):
        import os, subprocess, sys
        with tempfile.TemporaryDirectory(prefix="ha-admin-process-") as root:
            environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(REPO)}
            for stage in ("create", "resume"):
                result = subprocess.run([sys.executable, "-B", str(REPO/"tests/staging/admin_process_fixture.py"), root, stage], env=environment, capture_output=True, text=True, timeout=35)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertIn("NATIVE_PROCESS_"+stage.upper()+"=PASS", result.stdout)

    def test_abrupt_core_death_intent_mutation_and_buffered_helper_save(self):
        import os, subprocess, sys
        for boundary in ("crash-before-intent", "crash-after-intent", "crash-after-mutation", "crash-helper-receipt"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix="ha-admin-death-") as root:
                environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(REPO)}
                for stage, code in (("seed", 0), (boundary, 73), ("recover-crash", 0)):
                    result = subprocess.run([sys.executable, "-B", str(REPO/"tests/staging/admin_process_fixture.py"), root, stage], env=environment, capture_output=True, text=True, timeout=35)
                    self.assertEqual(result.returncode, code, result.stdout+result.stderr)
                    if code == 0:
                        self.assertIn("NATIVE_PROCESS_"+stage.upper()+"=PASS", result.stdout)

    def test_supported_core_backup_restore_rotates_old_credentials_and_retires_grants(self):
        import os, subprocess, sys
        with tempfile.TemporaryDirectory(prefix="ha-admin-backup-") as temporary:
            root = Path(temporary)/"config";root.mkdir()
            environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(REPO)}
            for stage in ("create", "backup-create", "backup-mutate", "backup-resume"):
                result = subprocess.run([sys.executable, "-B", str(REPO/"tests/staging/admin_process_fixture.py"), str(root), stage], env=environment, capture_output=True, text=True, timeout=35)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertIn("NATIVE_PROCESS_"+stage.upper()+"=PASS", result.stdout)
