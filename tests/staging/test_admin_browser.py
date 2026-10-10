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
            from homeassistant.components.http import StaticPathConfig
            document = fixture.root / "browser-fixture.html"
            document.write_text('<!doctype html><html><head><meta charset="utf-8"></head><body></body></html>')
            await fixture.hass.http.async_register_static_paths([
                StaticPathConfig("/__admin_browser_fixture", str(document), False)
            ])
            provider = fixture.hass.auth.get_auth_provider("homeassistant", None)
            password = secrets.token_urlsafe(24)
            await provider.async_add_auth("browser_owner", password)
            credential = await provider.async_get_or_create_credentials({"username": "browser_owner"})
            await fixture.hass.auth.async_link_user(fixture.owner, credential)
            from unittest.mock import patch
            from homeassistant.config_entries import ConfigFlow, HANDLERS
            from homeassistant.helpers import selector
            from homeassistant.setup import async_setup_component
            import probatio as vol
            self.assertTrue(await async_setup_component(fixture.hass, "sun", {}))
            await fixture.hass.async_block_till_done()
            entry = fixture.hass.config_entries.async_entries("sun")[0]
            class BrowserFlow(ConfigFlow):
                VERSION = 1
                async def async_step_reconfigure(flow, user_input=None):
                    return flow.async_show_menu(step_id="reconfigure", menu_options=["settings"])
                async def async_step_settings(flow, user_input=None):
                    if user_input is None:
                        return flow.async_show_form(step_id="settings", data_schema=vol.Schema({vol.Required("pin", default=password): selector.TextSelector({"type": "password"}), vol.Required("choices"): selector.SelectSelector({"options": ["a", "b"], "multiple": True}), vol.Required("limit"): selector.NumberSelector({"min": 1, "max": 9}), vol.Optional("clear_choices"): selector.SelectSelector({"options": ["a", "b"], "multiple": True}), vol.Optional("extra_limit"): selector.NumberSelector({"min": 0, "max": 9}), vol.Optional("extra_choice"): selector.SelectSelector({"options": ["a", "b"]}), vol.Required("notes"): selector.TextSelector({"multiline": True}), vol.Optional("enabled"): selector.BooleanSelector()}))
                    self.assertEqual(user_input, {"pin": password, "choices": ["b"], "clear_choices": [], "limit": 3.5, "notes": "first\nsecond"})
                    return flow.async_update_reload_and_abort(flow._get_reconfigure_entry(), data_updates={"browser_selectors_verified": True})
            handler_patch = patch.dict(HANDLERS, {"sun": BrowserFlow})
            handler_patch.start()
            self.addCleanup(handler_patch.stop)
            task = await fixture.tool("admin_propose", {"operations": [{"family": "script", "action": "create", "target": "browser_review", "value": {"alias": "<script>untrusted text</script>", "sequence": [{"delay": "00:00:00"}]}}]})
            child = await asyncio.create_subprocess_exec("node", str(REPO/"tests/staging/admin_browser_fixture.cjs"), env={**os.environ, "ADMIN_BROWSER_BASE": fixture.base, "ADMIN_BROWSER_USERNAME": "browser_owner", "ADMIN_BROWSER_PASSWORD": password, "ADMIN_BROWSER_CONNECTOR": fixture.bearer, "ADMIN_BROWSER_TASK": task["id"], "ADMIN_BROWSER_HASH": task["hash"], "ADMIN_BROWSER_FLOW_ENTRY": entry.entry_id}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
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
