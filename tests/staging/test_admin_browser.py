"""Optional bounded browser acceptance; requires sandbox-capable Chromium."""
import asyncio
import os
import secrets
import re
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
            def signal_owned(method):
                try:
                    method()
                except ProcessLookupError:
                    pass  # An exit racing the deadline still gets bounded output.
            output = asyncio.create_task(child.communicate())
            timed_out = False
            try:
                out, err = await asyncio.wait_for(asyncio.shield(output), 35)
            except TimeoutError:
                timed_out = True
                # Keep the body deadline unchanged; reserve at most five more
                # seconds for graceful owned-browser close, then bounded reap.
                signal_owned(child.terminate)
                try:
                    out, err = await asyncio.wait_for(asyncio.shield(output), 3)
                except TimeoutError:
                    signal_owned(child.kill)
                    try:
                        out, err = await asyncio.wait_for(asyncio.shield(output), 2)
                    except TimeoutError:
                        output.cancel()
                        out, err = b"", b"Owned browser cleanup/reap incomplete; no cleanup success claimed."
            except BaseException:
                if child.returncode is None:
                    signal_owned(child.terminate)
                    try:
                        await asyncio.wait_for(asyncio.shield(output), 3)
                    except TimeoutError:
                        signal_owned(child.kill)
                        try:
                            await asyncio.wait_for(asyncio.shield(output), 2)
                        except TimeoutError:
                            output.cancel()
                raise
            diagnostic = (out+err).decode(errors="replace")
            for value in (password, fixture.bearer):
                diagnostic = diagnostic.replace(value, "[redacted]")
            diagnostic = re.sub(r"hca_[A-Za-z0-9_-]{43}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[redacted]", diagnostic)
            if timed_out:
                diagnostic += "\nFixture exceeded its unchanged35-second limit."
            if (timed_out or child.returncode != 0) and os.environ.get("GITHUB_ACTIONS") == "true":
                # Native GitHub annotation gives readable, sanitized failure
                # evidence when the private log-download host is unavailable.
                safe = diagnostic[-5000:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                print("::error title=Sandboxed owner panel::"+safe, flush=True)
            if timed_out and "BROWSER_CLEANUP=COMPLETE" not in diagnostic:
                diagnostic += "\nForced termination cannot establish browser-descendant cleanup."
            self.assertFalse(timed_out, diagnostic)
            self.assertEqual(child.returncode, 0, diagnostic)
            self.assertIn("ACTUAL_OWNER_PANEL_BROWSER=PASS", out.decode())
            self.assertEqual((await fixture.tool("admin_status", {"task": task["id"]}))["operations"][0]["status"], "rolled_back")
        finally:
            await fixture.client.close(); await fixture.hass.async_stop(); fixture.doCleanups()
