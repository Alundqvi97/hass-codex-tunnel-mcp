"""Two disposable native HA processes; persistent test state never enters Git."""
import asyncio
import json
from pathlib import Path
import sys

from test_admin_product import NativeAdministrator


async def run():
    root, stage = Path(sys.argv[1]), sys.argv[2]
    fixture = NativeAdministrator()
    fixture.persist_root = root
    await fixture.asyncSetUp()
    try:
        receipt = root / "fixture.receipt"
        if stage == "create":
            op = {"family": "script", "action": "create", "target": "process_restart", "value": {"sequence": [{"delay": "00:00:00"}]}}
            task = await fixture.approved([op])
            args = {"task": task["id"], "plan_hash": task["hash"]}
            result = await fixture.tool("admin_execute", args)
            fixture.assertNotIn("error", result, result)
            receipt.write_text(json.dumps(args))
        elif stage == "resume":
            args = json.loads(receipt.read_text())
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
