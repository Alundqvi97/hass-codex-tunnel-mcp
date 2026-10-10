"""Optional real official binary contract; never contacts the hosted service."""
import asyncio
import json
import os
import unittest
from pathlib import Path
import test_admin_product as product
from admin_official_transport import OfficialTransport


class OfficialClientContract(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(os.environ.get("ADMIN_OFFICIAL_CLIENT"), "supply hash-verified official binary for loopback-only contract")
    async def test_actual_official_client_scoped_mcp_and_recovery(self):
        fixture = product.NativeAdministrator(); await fixture.asyncSetUp()
        transport = OfficialTransport(fixture, Path(os.environ["ADMIN_OFFICIAL_CLIENT"]))
        try:
            await transport.start()
            listed = await transport.call("tools/list")
            self.assertEqual(len(listed["result"]["tools"]), 6)
            unknown = await transport.call("tools/call", {"name": "unapproved_arbitrary_command", "arguments": {}})
            self.assertTrue(unknown.get("error") or unknown.get("result", {}).get("isError"))
            op = {"family": "script", "action": "create", "target": "official_transport", "value": {"sequence": [{"delay": "00:00:00"}]}}
            proposed = await transport.call("tools/call", {"name": "admin_propose", "arguments": {"operations": [op]}})
            task = json.loads(proposed["result"]["content"][0]["text"])["result"]
            args = {"task": task["id"], "plan_hash": task["hash"]}
            denied = await transport.call("tools/call", {"name": "admin_execute", "arguments": args})
            self.assertTrue(denied["result"]["isError"])
            self.assertTrue((await fixture.approval("approve", task=task["id"], plan_hash=task["hash"], confirm_effects=True))["success"])
            applied = await transport.call("tools/call", {"name": "admin_execute", "arguments": args})
            self.assertEqual(json.loads(applied["result"]["content"][0]["text"])["result"]["operations"][0]["status"], "applied")
            child = transport.manager.process
            child.kill(); await child.wait()
            async with asyncio.timeout(7):
                while transport.manager.process is child or transport.manager.status.state != "healthy":
                    await asyncio.sleep(.05)
            self.assertIsNot(transport.manager.process, child)
            rolled = await transport.call("tools/call", {"name": "admin_rollback", "arguments": args})
            self.assertEqual(json.loads(rolled["result"]["content"][0]["text"])["result"]["operations"][0]["status"], "rolled_back")
            self.assertEqual(len(transport.manager._log_tasks), 2)
            self.assertIsNone(await fixture.tool("admin_inspect", {"family": "script", "target": op["target"]}))
        finally:
            await transport.close(); await fixture.client.close(); await fixture.hass.async_stop(); fixture.doCleanups()
