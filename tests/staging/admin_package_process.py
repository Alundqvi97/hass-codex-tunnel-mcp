"""One real Core process per archive upgrade/rollback acceptance boundary."""
import asyncio
import json
from pathlib import Path
import sys
from test_admin_product import NativeAdministrator


async def run():
    stage, directory = sys.argv[1:]
    fixture = NativeAdministrator(); fixture.persist_root = directory
    fixture.expect_admin_failure = stage == "unsafe-downgrade"
    try:
        await fixture.asyncSetUp()
        async with fixture.client.get(fixture.base+"/api/config", headers={"Authorization": "Bearer "+fixture.owner_bearer}) as response:
            fixture.assertEqual(response.status, 200)  # independent local management
        root = Path(directory)
        if stage != "unsafe-downgrade":
            module = sys.modules["custom_components.hass_codex_admin.engine"]
            fixture.assertTrue(Path(module.__file__).resolve().is_relative_to(root.resolve()))  # no source-checkout fallback
        if stage == "unsafe-downgrade":
            fixture.assertNotIn("hass_codex_admin", fixture.hass.data)
            old = (root/"legacy.raw").read_text()
            async with fixture.client.post(fixture.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+old}) as response:
                fixture.assertEqual(response.status, 404)  # component never registered this route
            async with fixture.client.post(fixture.base+"/api/services/homeassistant/check_config", json={}, headers={"Authorization": "Bearer "+old}) as response:
                fixture.assertEqual(response.status, 401)
        else:
            async with fixture.client.post(fixture.base+"/api/services/homeassistant/check_config", json={}, headers={"Authorization": "Bearer "+fixture.bearer}) as response:
                fixture.assertEqual(response.status, 401)
            op = {"family": "script", "action": "create", "target": "package_"+stage.replace("-", "_"), "value": {"sequence": [{"delay": "00:00:00"}]}}
            task = await fixture.approved([op]); args = {"task": task["id"], "plan_hash": task["hash"]}
            fixture.assertNotIn("error", await fixture.tool("admin_execute", args))
            fixture.assertNotIn("error", await fixture.tool("admin_rollback", args))
            if stage == "legacy":
                stale = await fixture.approved([{**op, "target": "retired_upgrade_approval"}])
                (root/"legacy.task").write_text(json.dumps({"task": stale["id"], "plan_hash": stale["hash"]}))
                (root/"legacy.raw").write_text(fixture.bearer); (root/"legacy.raw").chmod(0o600)
            else:
                old = (root/"legacy.raw").read_text()
                async with fixture.client.post(fixture.base+"/api/hass_codex_admin/mcp", json={}, headers={"Authorization": "Bearer "+old}) as response:
                    fixture.assertEqual(response.status, 401)
                stale = json.loads((root/"legacy.task").read_text())
                fixture.assertIn("error", await fixture.tool("admin_execute", stale))
                fixture.assertIsNone(await fixture.tool("admin_inspect", {"family": "script", "target": "retired_upgrade_approval"}))
        print("PACKAGE_TRANSITION="+stage+":PASS")
    finally:
        if hasattr(fixture, "client"): await fixture.client.close()
        if hasattr(fixture, "hass"): await fixture.hass.async_stop()
        fixture.doCleanups()


asyncio.run(run())
