"""Real partial Core startup and owned-state retention in the staging launcher."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHILD = r'''
import asyncio, argparse, importlib.util, os, pathlib, shutil, signal, sys
root=pathlib.Path(sys.argv[2]); scenario=sys.argv[1]
sys.path.insert(0,str(root/'tests/staging'))
import test_admin_product as product
spec=importlib.util.spec_from_file_location('bounded_staging',root/'scripts/development/staging.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
async def check():
    loop=asyncio.get_running_loop(); captured=[]
    if scenario in ('before','incomplete'):
        async def blocked(self):
            if scenario=='incomplete':
                self.root=pathlib.Path(self.persist_root)
                self.hass=product.HomeAssistant(str(self.root))
                original_stop=self.hass.async_stop
                async def failed_stop(*args,**kwargs): raise RuntimeError('Injected shutdown failure')
                self.hass.async_stop=failed_stop
                captured.append((self.root,original_stop))
            loop.call_later(.1,os.kill,os.getpid(),signal.SIGTERM)
            await asyncio.sleep(30)
            raise AssertionError('Interrupted startup continued')
        product.NativeAdministrator.asyncSetUp=blocked
    else:
        original=product.async_setup_component
        async def blocked(hass,domain,config):
            if domain=='automation':
                assert hass.state is product.homeassistant_state_not_running
                if scenario=='partial':loop.call_later(.1,os.kill,os.getpid(),signal.SIGTERM)
                await asyncio.sleep(30)
                raise AssertionError('Interrupted partial setup continued')
            return await original(hass,domain,config)
        from homeassistant.core import CoreState
        product.homeassistant_state_not_running=CoreState.not_running
        product.async_setup_component=blocked
        if scenario=='deadline':
            original_timer=loop.call_later
            def timer(delay,callback,*args,**kwargs):
                return original_timer(.3 if getattr(callback,'__name__','')=='expire_startup' else delay,callback,*args,**kwargs)
            loop.call_later=timer
    args=argparse.Namespace(archive=pathlib.Path(sys.argv[3]),official_client=None,seconds=10)
    try:await module.run(args)
    except RuntimeError as error:
        if scenario=='deadline':assert 'startup exceeded' in str(error)
        elif scenario=='incomplete':
            assert 'cleanup incomplete' in str(error)
            state,stop=captured[0]; assert state.exists(), 'Uncertain state must not auto-delete'
            await stop(force=True); shutil.rmtree(state)
        else:raise
    else:assert scenario not in ('deadline','incomplete')
os.umask(0o077)
asyncio.run(check())
'''


class BoundedStagingStartup(unittest.TestCase):
    def check_scenario(self, scenario):
        archive = os.environ.get("ADMIN_RELEASE_ARCHIVE", str(ROOT / "artifacts/native-admin-0.2.0.zip"))
        result = subprocess.run([sys.executable, "-B", "-c", CHILD, scenario, str(ROOT), archive],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        self.assertFalse(any(event["staging"] == "ready" for event in events))
        self.assertEqual(events[0]["staging"], "startup_interrupted")
        self.assertEqual(events[0]["startup_deadline_expired"], scenario == "deadline")
        self.assertEqual(events[-1]["staging"], "cleanup_incomplete" if scenario == "incomplete" else "stopped")
        self.assertEqual(events[-1]["temporary_state_removed"], scenario != "incomplete")
        if scenario == "incomplete":
            self.assertIn("core", events[-1]["cleanup_failures"])
            self.assertFalse(Path(events[-1]["retained_state"]).exists())  # Separate explicit test recovery.

    def test_stop_before_fixture_startup(self):
        self.check_scenario("before")

    def test_stop_with_partial_not_running_core(self):
        self.check_scenario("partial")

    def test_startup_deadline_never_announces_readiness(self):
        self.check_scenario("deadline")

    def test_uncertain_cleanup_retains_state_until_explicit_recovery(self):
        self.check_scenario("incomplete")
