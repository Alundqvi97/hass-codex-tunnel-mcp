"""Two disposable native HA processes; persistent test state never enters Git."""
import asyncio
import json
import os
from pathlib import Path
import sys

from test_admin_product import NativeAdministrator


async def run():
    root, stage = Path(sys.argv[1]), sys.argv[2]
    if stage == "backup-resume":
        from homeassistant.backup_restore import restore_backup
        assert root.name == "config" and root.parent.name.startswith("ha-admin-backup-")
        assert restore_backup(str(root))
    fixture = NativeAdministrator()
    fixture.persist_root = root
    fixture.expect_restore = stage == "backup-resume"
    await fixture.asyncSetUp()
    try:
        receipt = root / "fixture.receipt"
        if stage.startswith("backup-"):
            control = root.parent / "control"
            control.mkdir(exist_ok=True, mode=0o700)
            if stage == "backup-create":
                from homeassistant.setup import async_setup_component
                fixture.assertTrue(await async_setup_component(fixture.hass, "backup", {"backup": {}}))
                await fixture.hass.async_block_till_done()
                task = await fixture.approved([{ "family": "maintenance", "action": "call", "target": "backup.create", "value": {}}])
                result = await fixture.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]})
                fixture.assertNotIn("error", result, result)
                identifier = result["operations"][0]["result"]["result"]["backup_job_id"]
                (control / "backup.id").write_text(identifier)
                (control / "old.connector").write_text(fixture.bearer)
                (control / "old.connector").chmod(0o600)
            elif stage == "backup-mutate":
                from homeassistant.setup import async_setup_component
                task = await fixture.approved([{ "family": "script", "action": "put", "target": "process_restart", "value": {"alias": "After backup", "sequence": [{"delay": "00:00:00"}]}}])
                fixture.assertNotIn("error", await fixture.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
                identity = fixture.hass.data["hass_codex_admin"]["identity"]
                await identity.revoke(identity.caller(fixture.bearer).session)
                fixture.assertTrue(await async_setup_component(fixture.hass, "backup", {"backup": {}}))
                await fixture.hass.async_block_till_done()
                try:
                    await fixture.native_ws({"type": "backup/restore", "backup_id": (control/"backup.id").read_text(), "agent_id": "backup.local", "restore_database": False, "restore_homeassistant": True})
                except (TypeError, ConnectionError):
                    pass  # Native restart may close the acknowledgement socket.
                fixture.assertTrue((root/".HA_RESTORE").exists())
            else:
                old = (control/"old.connector").read_text()
                async with fixture.client.post(fixture.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+old}) as response:
                    fixture.assertEqual(response.status, 401)
                restored = await fixture.tool("admin_inspect", {"family": "script", "target": "process_restart"})
                fixture.assertEqual(restored, {"sequence": [{"delay": "00:00:00"}]})
                original = json.loads(receipt.read_text())
                fixture.assertEqual(await fixture.tool("admin_execute", original), {"error": "caller_scope_or_policy_changed"})
                fixture.assertEqual(await fixture.tool("admin_rollback", original), {"error": "caller_scope_or_policy_changed"})
                history = await fixture.hass.data["hass_codex_admin"]["engine"].db("get", original["task"])
                fixture.assertEqual(history["operations"][0]["status"], "applied")
        elif stage == "lifecycle-request":
            from homeassistant.components.homeassistant import async_set_stop_handler
            from homeassistant.const import RESTART_EXIT_CODE
            requested = asyncio.Event()
            async def hold_shutdown(hass, restart):
                fixture.assertTrue(restart)
                requested.set()
            # Public injected stop boundary lets the real HTTP acknowledgment
            # commit before actual owned Core shutdown. No fake incarnation.
            async_set_stop_handler(fixture.hass, hold_shutdown)
            task = await fixture.approved([{"family": "maintenance", "action": "call", "target": "homeassistant.restart", "value": {}}])
            args = {"task": task["id"], "plan_hash": task["hash"]}
            receipt.write_text(json.dumps(args))
            result = await fixture.tool("admin_execute", args)
            fixture.assertEqual(result, {"error": "outcome_requires_reconciliation"})
            await asyncio.wait_for(requested.wait(), 2)
            row = await fixture.hass.data["hass_codex_admin"]["engine"].db("get", task["id"])
            fixture.assertTrue(row["operations"][0]["result"]["backend_acknowledged"])
            await fixture.hass.async_stop(RESTART_EXIT_CODE)
            fixture.assertEqual(fixture.hass.state.value, "STOPPED")
        elif stage == "lifecycle-resume":
            args = json.loads(receipt.read_text())
            fixture.assertEqual(await fixture.tool("admin_execute", args), {"error": "operation_consumed_or_uncertain"})
            result = await fixture.tool("admin_reconcile", args)
            fixture.assertNotIn("error", result, result)
            item = result["operations"][0]
            fixture.assertEqual(item["status"], "applied")
            fixture.assertTrue(item["result"]["current_lifecycle_facts_verified"])
            fixture.assertNotEqual((item["before_state"]["pid"], item["before_state"]["created"]), (item["after_state"]["pid"], item["after_state"]["created"]))
            fixture.assertEqual(result["status"], "revoked")  # boot never renews task authority
        elif stage == "seed":
            pass
        elif stage.startswith("crash-"):
            engine = fixture.hass.data["hass_codex_admin"]["engine"]
            helper = stage == "crash-helper-receipt"
            op = {"family": "input_boolean" if helper else "script", "action": "create", "target": "crash_helper" if helper else "crash_script", "value": {"name": "Crash helper"} if helper else {"alias": "Durable mutation", "sequence": [{"delay": "00:00:00"}]}}
            task = await fixture.approved([op])
            args = {"task": task["id"], "plan_hash": task["hash"]}
            receipt.write_text(json.dumps({"args": args, "op": op, "stage": stage}))
            original_db = engine.db
            async def intent(method, *values, **kwargs):
                if method == "claim" and stage == "crash-before-intent":
                    os._exit(73)
                result = await original_db(method, *values, **kwargs)
                if method == "claim" and stage == "crash-after-intent":
                    os._exit(73)
                return result
            engine.db = intent
            original_write = engine.backend.write
            async def mutation(actor, operation):
                result = await original_write(actor, operation)
                if stage == "crash-after-mutation":
                    os._exit(73)
                return result
            engine.backend.write = mutation
            result = await fixture.tool("admin_execute", args)
            fixture.assertNotIn("error", result, result)
            fixture.assertEqual(result["operations"][0]["status"], "applied")
            os._exit(73)  # Real abrupt death before HA's delayed helper save.
        elif stage == "recover-crash":
            saved = json.loads(receipt.read_text())
            args, op, boundary = saved["args"], saved["op"], saved["stage"]
            observed = await fixture.tool("admin_inspect", {"family": op["family"], "target": op["target"]})
            result = await fixture.tool("admin_execute", args)
            if boundary == "crash-after-mutation":
                fixture.assertIsNotNone(observed)
                fixture.assertEqual(result, {"error": "operation_consumed_or_uncertain"})
                reconciled = await fixture.tool("admin_reconcile", args)
                fixture.assertEqual(reconciled, {"error": "creation_ownership_requires_owner_reconciliation"})
                fixture.assertEqual(await fixture.tool("admin_rollback", args), {"error": "operation_consumed_or_uncertain"})
                # Lost acknowledgement never conveys ownership after restart.
                cleanup = await fixture.approved([{**op, "action": "delete", "value": None}])
                fixture.assertNotIn("error", await fixture.tool("admin_execute", {"task": cleanup["id"], "plan_hash": cleanup["hash"]}))
            elif boundary == "crash-helper-receipt":
                fixture.assertIsNone(observed)
                fixture.assertEqual(result, {"error": "recorded_result_has_drift"})
                task = await fixture.approved([op])
                fixture.assertNotIn("error", await fixture.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
            else:
                fixture.assertIsNone(observed)
                fixture.assertIn(result["error"], ("approval_required_or_expired", "operation_consumed_or_uncertain"))
                fixture.assertIn("error", await fixture.tool("admin_reconcile", args)) if boundary == "crash-after-intent" else None
        elif stage == "create":
            op = {"family": "script", "action": "create", "target": "process_restart", "value": {"sequence": [{"delay": "00:00:00"}]}}
            task = await fixture.approved([op])
            args = {"task": task["id"], "plan_hash": task["hash"]}
            result = await fixture.tool("admin_execute", args)
            fixture.assertNotIn("error", result, result)
            receipt.write_text(json.dumps(args))
            (root / "fixture.old-credential").write_text(fixture.bearer)
            (root / "fixture.old-credential").chmod(0o600)
        elif stage == "resume":
            args = json.loads(receipt.read_text())
            old = (root / "fixture.old-credential").read_text()
            async with fixture.client.post(fixture.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+old}) as response:
                fixture.assertEqual(response.status, 401)
            result = await fixture.tool("admin_execute", args)
            fixture.assertNotIn("error", result, result)
            fixture.assertEqual(result["operations"][0]["status"], "applied")
            engine = fixture.hass.data["hass_codex_admin"]["engine"]
            with engine.store.transaction() as db:
                fixture.assertEqual(db.execute("SELECT count(*) FROM audit WHERE task=? AND event='dispatch_started'", (args["task"],)).fetchone()[0], 1)
            fixture.assertIsNotNone(await fixture.tool("admin_inspect", {"family": "script", "target": "process_restart"}))
            # HA boot/backup restoration invalidates saved authority; results
            # remain readable, but restoration requires one fresh task approval.
            fixture.assertEqual(await fixture.tool("admin_rollback", args), {"error": "approval_required_or_expired"})
            task = await fixture.approved([{"family": "script", "action": "delete", "target": "process_restart", "value": None}])
            fixture.assertNotIn("error", await fixture.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
            fixture.assertIsNone(await fixture.tool("admin_inspect", {"family": "script", "target": "process_restart"}))
        else:
            raise ValueError("Unknown fixture stage")
        print("NATIVE_PROCESS_"+stage.upper()+"=PASS")
    finally:
        await fixture.client.close()
        await fixture.hass.async_stop()
        fixture.doCleanups()


if __name__ == "__main__":
    asyncio.run(run())
