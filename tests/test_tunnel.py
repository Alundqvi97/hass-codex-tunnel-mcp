from __future__ import annotations

import asyncio
from pathlib import Path

from custom_components.hass_codex_tunnel_mcp.const import (
    CONF_API_KEY,
    CONF_CONTROL_PLANE_BASE_URL,
    CONF_CONTROL_PLANE_PATH,
    CONF_HA_MCP_BEARER_TOKEN,
    CONF_HA_MCP_URL,
    CONF_TUNNEL_ID,
)
from custom_components.hass_codex_tunnel_mcp.tunnel import (
    TunnelCommandConfig,
    TunnelManager,
    _read_health_url,
    build_mcp_server_url,
    build_tunnel_command,
)


def test_build_mcp_server_url() -> None:
    assert (
        build_mcp_server_url("http://127.0.0.1:9584/private_secret")
        == "channel=main,url=http://127.0.0.1:9584/private_secret"
    )


def test_build_tunnel_command_includes_required_flags(tmp_path: Path) -> None:
    command = build_tunnel_command(
        tmp_path / "tunnel-client",
        TunnelCommandConfig(
            tunnel_id="tunnel_0123456789abcdef0123456789abcdef",
            mcp_server_url="http://127.0.0.1:9584/private_secret",
            run_dir=tmp_path,
            control_plane_base_url="https://control.example",
            control_plane_url_path="/v1",
        ),
    )

    assert command[:2] == [str(tmp_path / "tunnel-client"), "run"]
    assert "--control-plane.tunnel-id" in command
    assert "tunnel_0123456789abcdef0123456789abcdef" in command
    assert "--control-plane.api-key" in command
    assert "env:CONTROL_PLANE_API_KEY" in command
    assert "--mcp.server-url" in command
    assert "channel=main,url=http://127.0.0.1:9584/private_secret" in command
    assert "--health.listen-addr" in command
    assert "127.0.0.1:0" in command
    assert "--control-plane.base-url" in command
    assert "https://control.example" in command
    assert "--control-plane.url-path" in command
    assert "/v1" in command


def test_build_tunnel_command_uses_env_backed_ha_token_header(tmp_path: Path) -> None:
    command = build_tunnel_command(
        tmp_path / "tunnel-client",
        TunnelCommandConfig(
            tunnel_id="tunnel_0123456789abcdef0123456789abcdef",
            mcp_server_url="http://127.0.0.1:8123/api/mcp",
            run_dir=tmp_path,
            use_ha_mcp_bearer_token=True,
        ),
    )

    assert "--mcp.extra-headers" in command
    assert "--mcp.discovery-extra-headers" in command
    assert command.count("Authorization: env:HA_MCP_AUTH_HEADER") == 2
    assert not any("Bearer" in arg for arg in command)


def test_tunnel_manager_lifecycle_with_fake_client(tmp_path: Path) -> None:
    asyncio.run(_run_tunnel_manager_lifecycle_with_fake_client(tmp_path))


def test_tunnel_manager_cleans_up_stale_client(tmp_path: Path) -> None:
    asyncio.run(_run_tunnel_manager_cleans_up_stale_client(tmp_path))


def test_read_health_url(tmp_path: Path) -> None:
    health_file = tmp_path / "health.url"

    assert _read_health_url(health_file) == ""

    health_file.write_text("http://127.0.0.1:9\n", encoding="utf-8")

    assert _read_health_url(health_file) == "http://127.0.0.1:9"


def fixture_client(tmp_path):
    source = Path(__file__).resolve().parent / "staging"
    fake = tmp_path / "tunnel-client"
    fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.path.insert(0, "+repr(str(source))+")\n"+(source / "admin_transport_fixture.py").read_text())
    fake.chmod(0o755)
    return fake


def entry_data():
    return {CONF_TUNNEL_ID: "synthetic-tunnel", CONF_API_KEY: "synthetic-platform-key", CONF_HA_MCP_URL: "http://127.0.0.1:9/fixture-only", CONF_HA_MCP_BEARER_TOKEN: ""}


async def _run_tunnel_manager_lifecycle_with_fake_client(tmp_path):
    fake = fixture_client(tmp_path)
    manager = TunnelManager(lambda force: fake, tmp_path / "run", poll_interval=.05)
    try:
        await manager.start(entry_data())
        assert await manager.wait_until_healthy(3)
        first = manager.process
        await asyncio.gather(*(manager.start(entry_data()) for _ in range(5)))
        assert manager.process is first
        first.kill()
        for _ in range(100):
            if manager.process is not first and manager.status.healthy:
                break
            await asyncio.sleep(.05)
        assert manager.process is not first
        assert manager.status.healthy
        await manager.restart(entry_data())
        assert await manager.wait_until_healthy(3)
    finally:
        await manager.stop()
    assert manager.status.state == "stopped"
    await asyncio.sleep(.1)
    assert manager.process is None


async def _run_tunnel_manager_cleans_up_stale_client(tmp_path):
    # A stale file cannot assert readiness or justify killing a numeric PID.
    fake = fixture_client(tmp_path)
    manager = TunnelManager(lambda force: fake, tmp_path / "run", poll_interval=.05)
    other = TunnelManager(lambda force: fake, tmp_path / "run", poll_interval=.05)
    try:
        await manager.start(entry_data())
        assert await manager.wait_until_healthy(3)
        child = manager.process
        try:
            await other.start(entry_data())
        except BlockingIOError:
            pass
        else:
            raise AssertionError("duplicate process owner accepted")
        assert manager.process is child and child.returncode is None
    finally:
        await other.stop()
        await manager.stop()


def test_tunnel_manager_bounds_crash_recovery_without_download(tmp_path: Path) -> None:
    """Four retries of the same binary, then an explicit exhausted state."""
    asyncio.run(_run_unexpected_exit_test(tmp_path))


async def _run_unexpected_exit_test(tmp_path: Path) -> None:
    fake = tmp_path / "tunnel-client"
    fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(17)\n", encoding="utf-8")
    fake.chmod(0o755)
    launches = 0

    def provider(force):
        nonlocal launches
        launches += 1
        return fake

    manager = TunnelManager(provider, tmp_path / "run", retry_delays=(.01, .02, .04, .08), poll_interval=.02)
    await manager.start({
        CONF_TUNNEL_ID: "tunnel_0123456789abcdef0123456789abcdef",
        CONF_API_KEY: "synthetic-platform-key",
        CONF_HA_MCP_URL: "http://127.0.0.1:9/fixture-only",
        CONF_HA_MCP_BEARER_TOKEN: "",
        CONF_CONTROL_PLANE_BASE_URL: "",
        CONF_CONTROL_PLANE_PATH: "",
    })
    for _ in range(60):
        if manager.status.state == "exhausted":
            break
        await asyncio.sleep(0.05)
    assert manager.status.state == "exhausted"
    assert manager.status.returncode == 17
    assert launches == 1
    assert manager.status.healthy is False
    await manager.stop()


def test_repeated_cancellation_still_reaps_owned_child(tmp_path):
    async def run():
        fake = fixture_client(tmp_path)
        source = fake.read_text().replace("from http.server", "import signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nfrom http.server")
        fake.write_text(source)
        manager = TunnelManager(lambda force: fake, tmp_path/"run", poll_interval=.02, terminate_timeout=.08)
        await manager.start(entry_data())
        assert await manager.wait_until_healthy(3)
        child = manager.process
        stopping = asyncio.create_task(manager.stop())
        await asyncio.sleep(.02);stopping.cancel()
        await asyncio.sleep(.01);stopping.cancel()
        try:
            await stopping
        except asyncio.CancelledError:
            pass
        assert child.returncode is not None
        assert manager.process is None and manager.status.state == "stopped"
        await manager.start(entry_data())
        assert await manager.wait_until_healthy(3)
        await manager.close()
    asyncio.run(run())


def test_cancelled_spawn_captures_and_cleans_child(tmp_path, monkeypatch):
    async def run():
        fake = fixture_client(tmp_path)
        original = asyncio.create_subprocess_exec
        spawned, release = asyncio.Event(), asyncio.Event()
        children = []
        async def delayed(*args, **kwargs):
            child = await original(*args, **kwargs)
            children.append(child);spawned.set()
            await release.wait()
            return child
        monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed)
        manager = TunnelManager(lambda force: fake, tmp_path/"run", poll_interval=.02, terminate_timeout=.08)
        starting = asyncio.create_task(manager.start(entry_data()))
        await asyncio.wait_for(spawned.wait(), 2)
        starting.cancel();await asyncio.sleep(.01);starting.cancel();release.set()
        try:
            await starting
        except asyncio.CancelledError:
            pass
        assert children[0].returncode is not None
        assert manager.process is None
        await manager.stop()
    asyncio.run(run())


def test_stale_health_file_cannot_assert_ready_or_follow_network(tmp_path):
    from custom_components.hass_codex_tunnel_mcp.tunnel import _observe_health
    health = tmp_path/"health.url"
    for value in ("http://127.0.0.1:9/readyz", "https://example.invalid/readyz", "http://127.0.0.1:9/?token=x", "http://user:secret@127.0.0.1:9"):
        health.write_text(value)
        category, _ = _observe_health(health, entry_data())
        assert category != "ready"
    health.unlink()
    health.symlink_to(tmp_path/"missing")
    assert _read_health_url(health) == ""


def test_lifecycle_epoch_blocks_late_update_and_close_blocks_restart(tmp_path):
    async def run():
        fake = fixture_client(tmp_path)
        manager = TunnelManager(lambda force: fake, tmp_path/"run", poll_interval=.02)
        await manager.start(entry_data())
        epoch = manager.epoch
        await manager.stop()
        try:
            await manager.start(entry_data(), executable_override=fake, expected_epoch=epoch)
        except RuntimeError as exc:
            assert "superseded" in str(exc)
        else:
            raise AssertionError("late updater revived stopped transport")
        assert manager.process is None
        await manager.close()
        try:
            await manager.start(entry_data())
        except RuntimeError as exc:
            assert "closed" in str(exc)
        else:
            raise AssertionError("closed integration restarted")
    asyncio.run(run())


def test_long_output_is_drained_without_logging_secrets(tmp_path, caplog):
    async def run():
        fake = fixture_client(tmp_path)
        source = fake.read_text().replace("from http.server", "import sys\nsys.stdout.write('synthetic-secret'*20000+'\\n');sys.stdout.flush()\nfrom http.server")
        fake.write_text(source)
        manager = TunnelManager(lambda force: fake, tmp_path/"run", poll_interval=.02)
        try:
            await manager.start(entry_data())
            assert await manager.wait_until_healthy(3)
            assert "synthetic-secret" not in caplog.text
        finally:
            await manager.close()
    asyncio.run(run())


def test_close_cancellation_while_start_owns_lifecycle_lock(tmp_path):
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def provider(force):
            entered.set()
            await release.wait()
            return fixture_client(tmp_path)
        manager = TunnelManager(provider, tmp_path/'run', poll_interval=.01)
        starting = asyncio.create_task(manager.start(entry_data()))
        await entered.wait()
        closing = asyncio.create_task(manager.close())
        await asyncio.sleep(.01)
        closing.cancel()
        release.set()
        await starting
        child = manager.process
        result = await asyncio.gather(closing, return_exceptions=True)
        assert isinstance(result[0], asyncio.CancelledError)
        assert child.returncode is not None
        assert manager.process is None
        assert manager.status.state == 'stopped'
    asyncio.run(scenario())


def test_uncertain_reaping_keeps_ownership_and_prevents_replacement(tmp_path):
    class StalledProcess:
        returncode = None
        def terminate(self): pass
        def kill(self): raise ProcessLookupError()
        async def wait(self): await asyncio.Event().wait()
    async def scenario():
        manager = TunnelManager(lambda force: fixture_client(tmp_path), tmp_path/'run', terminate_timeout=.01)
        manager._process = child = StalledProcess()
        for operation in (manager.stop, lambda: manager.start(entry_data())):
            try:
                await asyncio.wait_for(operation(), .5)
            except RuntimeError as error:
                assert str(error) == 'owned_child_reaping_incomplete'
            else:
                raise AssertionError('uncertain cleanup was promoted to success')
            assert manager.process is child
            assert manager.status.state == 'cleanup_incomplete'
        # This fake owns no actual resources.
    asyncio.run(scenario())
