#!/usr/bin/env python3
"""Bounded loopback staging using the existing archive-installed Core fixture.

Development only. No hosted mode, external credentials, persistence service or
public listener. SIGINT/SIGTERM or the deadline stops Core and removes its state.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import secrets
import sys
import tempfile
import ipaddress

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_ARCHIVE = "deb0a0507f8a3105c4c5f14fcb7eabb3952a5dd5d48fabcdff180548df3981d8"
EXPECTED_CLIENT = "01260ee973d5510861bc32979739561edd33869f99f9f8cd324f6d0da5b2e692"


async def run(args):
    # Do not start from main, the wrong repository or an unreviewed baseline.
    import subprocess
    subprocess.run(["bash", str(ROOT / "scripts/development/install.sh"), "--check-base"], check=True, cwd=ROOT)
    archive = args.archive.resolve(strict=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != EXPECTED_ARCHIVE:
        raise ValueError("Staging requires the reviewed 0.2.0 release archive")
    if args.official_client:
        if args.official_client.is_symlink() or not args.official_client.is_file():
            raise ValueError("Expected the verified regular Linux amd64 client")
        if hashlib.sha256(args.official_client.read_bytes()).hexdigest() != EXPECTED_CLIENT:
            raise ValueError("Official v0.0.16 executable digest mismatch")
    os.environ["ADMIN_RELEASE_ARCHIVE"] = str(archive)
    sys.path.insert(0, str(ROOT / "tests/staging"))
    from test_admin_product import NativeAdministrator
    from admin_official_transport import OfficialTransport
    fixture = NativeAdministrator()
    owned_state = tempfile.TemporaryDirectory(prefix="ha-codex-staging-", delete=False)
    fixture.persist_root = owned_state.name
    storage = Path(owned_state.name) / ".storage"
    storage.mkdir(mode=0o700)
    # Synthetic, already configured test state. Running real onboarding's
    # core_config step installs unrelated Internet integrations (met/radio/etc).
    # Match this Core's storage schema without activating those integrations.
    from homeassistant.components.onboarding import STORAGE_VERSION, STORAGE_KEY
    from homeassistant.components.onboarding.const import STEPS
    (storage / STORAGE_KEY).write_text(json.dumps({"version": STORAGE_VERSION,
        "minor_version": 1, "key": STORAGE_KEY, "data": {"done": STEPS}}))
    transport = None
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    owner_task = asyncio.current_task()
    phase = "starting"
    startup_expired = False
    def stop():
        stopped.set()
        if phase == "starting":
            owner_task.cancel()
    def expire_startup():
        nonlocal startup_expired
        startup_expired = True
        stop()
    def checkpoint():
        if stopped.is_set():
            raise asyncio.CancelledError
    async def checked(awaitable):
        if stopped.is_set():
            awaitable.close()
            raise asyncio.CancelledError
        result = await awaitable
        checkpoint()
        return result
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    startup_timer = loop.call_later(45, expire_startup)
    try:
        await checked(fixture.asyncSetUp())
        from homeassistant.setup import async_setup_component
        fixture.assertTrue(await checked(async_setup_component(fixture.hass, "frontend", {})))
        provider = fixture.hass.auth.get_auth_provider("homeassistant", None)
        password = secrets.token_urlsafe(24)
        await checked(provider.async_add_auth("staging_owner", password))
        credential = await checked(provider.async_get_or_create_credentials({"username": "staging_owner"}))
        await checked(fixture.hass.auth.async_link_user(fixture.owner, credential))
        # Only synthetic native login input; no real account/key and no token
        # output. The enclosing directory and this file are private to the task.
        login_file = fixture.root / "owner-login.json"
        with login_file.open("x") as output:
            json.dump({"username": "staging_owner", "password": password}, output)
        login_file.chmod(0o600)
        async with fixture.client.get(fixture.base + "/") as response:
            fixture.assertEqual(response.status, 200)
            document = await response.text()
            fixture.assertIn("<home-assistant", document)
            fixture.assertNotIn("<ha-onboarding", document)
        checkpoint()
        broken = {"alias": "Codex staging fault", "triggers": [], "actions": [{"variables": {"fault": "{{ 1 / 0 }}"}}]}
        operations = [
            {"family": "automation", "action": "create", "target": "codex_staging_fault", "value": broken},
            {"family": "script", "action": "create", "target": "codex_staging_script", "value": {"sequence": [{"delay": "00:00:00"}]}},
            {"family": "input_boolean", "action": "create", "target": "codex_staging_helper", "value": {"name": "Codex staging helper", "initial": False}},
            {"family": "dashboard", "action": "create", "target": "codex-staging-board", "value": {"title": "Codex staging", "require_admin": True, "show_in_sidebar": False, "config": {"views": [{"title": "Synthetic", "cards": []}]}}},
        ]
        task = await checked(fixture.approved(operations))
        result = await checked(fixture.tool("admin_execute", {"task": task["id"], "plan_hash": task["hash"]}))
        fixture.assertNotIn("error", result, result)
        # Reuse the actual native synthetic entity/service fixture; no hardware.
        await checked(fixture.test_native_synthetic_device_service_feedback_and_no_replay())
        for op in operations:
            fixture.assertIsNotNone(await checked(fixture.tool("admin_inspect", {"family": op["family"], "target": op["target"]})))
        listed = await checked(fixture.rpc("tools/list"))
        fixture.assertEqual(len(listed["result"]["tools"]), 6)
        async with fixture.client.get(fixture.base + "/hass_codex_admin/panel.js") as response:
            fixture.assertEqual(response.status, 200)
            fixture.assertIn("hass-codex-admin", await response.text())
        checkpoint()
        # Pending repair has no authority. Native owner approval is a separate
        # operation; starting staging does not silently approve this repair.
        repair = await checked(fixture.tool("admin_propose", {"operations": [{**operations[0], "action": "put", "value": {**broken, "actions": [{"delay": "00:00:00"}]}}]}))
        denied = await checked(fixture.tool("admin_execute", {"task": repair["id"], "plan_hash": repair["hash"]}))
        fixture.assertEqual(denied, {"error": "approval_required_or_expired"})
        if args.official_client:
            transport = OfficialTransport(fixture, args.official_client.resolve())
            await checked(transport.start())
            fixture.assertEqual(len((await checked(transport.call("tools/list")))["result"]["tools"]), 6)
        import psutil
        owned_processes = [psutil.Process()]
        # Audit the retained manager's actual child, not unrelated short-lived
        # Core discovery subprocesses whose exit races a descendant snapshot.
        if transport is not None:
            owned_processes.append(psutil.Process(transport.manager.process.pid))
        connections = [c for process in owned_processes for c in process.net_connections(kind="inet")]
        listeners = sorted({c.laddr.ip for c in connections if c.status == psutil.CONN_LISTEN})
        fixture.assertTrue(listeners)
        fixture.assertTrue(all(ipaddress.ip_address(address).is_loopback for address in listeners))
        fixture.assertTrue(all(ipaddress.ip_address(c.raddr.ip).is_loopback for c in connections if c.raddr))
        fixture.assertTrue(all(process.is_running() for process in owned_processes))
        checkpoint()
        phase = "ready"
        startup_timer.cancel()
        print(json.dumps({"staging": "ready", "pid": os.getpid(), "listener_addresses": listeners,
                          "lifetime_seconds": args.seconds,
                          "root": str(fixture.root), "ha_origin": fixture.base,
                          "objects": [op["target"] for op in operations],
                          "tools": 6, "owner_panel_asset": "verified",
                          "native_frontend": "served", "synthetic_owner_login_file": str(login_file),
                          "pending_repair": repair["id"], "unapproved_execution": "denied",
                          "official_transport": "loopback_fixture" if transport else "not_started",
                          "hosted": "not_authorized_or_connected"}), flush=True)
        try:
            await asyncio.wait_for(stopped.wait(), args.seconds)
        except TimeoutError:
            pass
    except asyncio.CancelledError:
        if not stopped.is_set():
            raise
        print(json.dumps({"staging": "startup_interrupted", "startup_deadline_expired": startup_expired}), flush=True)
        if startup_expired:
            raise RuntimeError("Staging startup exceeded its 45-second observation deadline")
    finally:
        phase = "cleanup"
        startup_timer.cancel()
        failures = []
        # This fixture is used outside unittest's async runner. Close the actual
        # resources explicitly instead of invoking its registered test cleanups.
        operations = []
        if transport is not None:
            operations.append(("transport", transport.close))
        if hasattr(fixture, "client"):
            operations.append(("http_client", fixture.client.close))
        if hasattr(fixture, "hass"):
            operations.append(("core", lambda: fixture.hass.async_stop(force=True)))
        retained_cleanup = []
        for name, close in operations:
            task = asyncio.create_task(close())
            retained_cleanup.append(task)
            try:
                done, _ = await asyncio.wait({task}, timeout=10)
                if not done:
                    failures.append(name)
                else:
                    task.result()
            except Exception:
                failures.append(name)
        # A deadline bounds observation, not cancellation-resistant ownership
        # or asyncio runner teardown. Never delete state/report PASS on timeout.
        from homeassistant.core import CoreState
        if hasattr(fixture, "hass") and fixture.hass.state is not CoreState.stopped:
            failures.append("core_not_stopped")
        if hasattr(fixture, "client") and not fixture.client.closed:
            failures.append("http_client_not_closed")
        if transport is not None and hasattr(transport, "manager") and transport.manager.process is not None:
            failures.append("owned_process_not_reaped")
        import psutil
        if any(c.status == psutil.CONN_LISTEN for c in psutil.Process().net_connections(kind="inet")):
            failures.append("owned_listener_not_closed")
        if not failures:
            if hasattr(fixture, "temp"):
                fixture.temp.cleanup()
            owned_state.cleanup()
        cleanup_complete = not failures and not Path(owned_state.name).exists() and (not hasattr(fixture, "root") or not fixture.root.exists())
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
        print(json.dumps({"staging": "stopped" if cleanup_complete else "cleanup_incomplete",
                          "temporary_state_removed": cleanup_complete, "cleanup_failures": failures,
                          "retained_state": None if cleanup_complete else owned_state.name}), flush=True)
        if not cleanup_complete:
            raise RuntimeError("Owned staging cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=ROOT / "artifacts/native-admin-0.2.0.zip")
    parser.add_argument("--official-client", type=Path, help="Verified Linux amd64 v0.0.16; local control plane only")
    parser.add_argument("--seconds", type=int, default=900, help="Ready lifetime, 1..900 seconds; not persistent hosting")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 900:
        parser.error("Lifetime must be 1..900 seconds")
    if os.getuid() == 0:
        parser.error("Use an ordinary non-root development user")
    os.umask(0o077)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
