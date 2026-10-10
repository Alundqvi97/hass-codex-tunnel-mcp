"""Optional bounded browser acceptance; requires sandbox-capable Chromium."""
import asyncio
import os
import secrets
import unittest
import test_admin_product as product
REPO = product.REPO


class OwnerPanelBrowser(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(os.environ.get("ADMIN_BROWSER_EXECUTABLE"), "set ADMIN_BROWSER_EXECUTABLE to sandbox-capable Chromium")
    async def test_actual_owner_panel_review_approve_and_revoke(self):
        fixture = product.NativeAdministrator()
        await fixture.asyncSetUp()
        try:
            provider = fixture.hass.auth.get_auth_provider("homeassistant", None)
            password = secrets.token_urlsafe(24)
            await provider.async_add_auth("browser_owner", password)
            credential = await provider.async_get_or_create_credentials({"username": "browser_owner"})
            await fixture.hass.auth.async_link_user(fixture.owner, credential)
            task = await fixture.tool("admin_propose", {"operations": [{"family": "script", "action": "create", "target": "browser_review", "value": {"alias": "<script>untrusted text</script>", "sequence": [{"delay": "00:00:00"}]}}]})
            child = await asyncio.create_subprocess_exec("node", str(REPO/"tests/staging/admin_browser_fixture.cjs"), env={**os.environ, "ADMIN_BROWSER_BASE": fixture.base, "ADMIN_BROWSER_USERNAME": "browser_owner", "ADMIN_BROWSER_PASSWORD": password, "ADMIN_BROWSER_CONNECTOR": fixture.bearer, "ADMIN_BROWSER_TASK": task["id"], "ADMIN_BROWSER_HASH": task["hash"]}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(child.communicate(), 35)
            finally:
                if child.returncode is None:
                    child.kill(); await child.wait()
            self.assertEqual(child.returncode, 0, err.decode())
            self.assertIn("ACTUAL_OWNER_PANEL_BROWSER=PASS", out.decode())
            self.assertEqual((await fixture.tool("admin_status", {"task": task["id"]}))["operations"][0]["status"], "rolled_back")
        finally:
            await fixture.client.close(); await fixture.hass.async_stop(); fixture.doCleanups()
