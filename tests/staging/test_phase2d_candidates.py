"""Real HA-MCP v8.6.0, patched only in isolated GitHub runner.

Requires the SHA-guarded upstream candidates in docs/security/phase2d to be
applied. All synthetic admin effects are local and harmless. No HA connection.
"""
from __future__ import annotations

import builtins
import importlib.util
import io
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from ha_mcp.policy.middleware import PolicyMiddleware
from ha_mcp.policy.model import Policy, Rule
from ha_mcp.policy.persistence import load_policy, save_policy
from ha_mcp.server import HomeAssistantSmartMCPServer

SECRET = "/private_synthetic_phase2d_secret_not_real"


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("HA_MCP_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("HA_MCP_REQUIRE_STRICT_POLICY", raising=False)
    from ha_mcp.utils.data_paths import get_data_dir
    get_data_dir.cache_clear()
    yield tmp_path
    get_data_dir.cache_clear()


def server_stub(enabled=True):
    stub = MagicMock()
    stub.settings.enable_tool_security_policies = enabled
    stub.settings.ha_tool_concurrency = 0
    return stub


def attach(stub):
    return HomeAssistantSmartMCPServer._apply_tool_security_policies(stub)


def test_normal_policy_initialization(env):
    stub = server_stub()
    attach(stub)
    assert stub.mcp.add_middleware.call_count == 1
    assert isinstance(stub.mcp.add_middleware.call_args.args[0], PolicyMiddleware)


def test_optional_disabled_keeps_legacy_default(env):
    stub = server_stub(False)
    attach(stub)
    stub.mcp.add_middleware.assert_not_called()


def test_import_failure_fails_startup(env, monkeypatch, caplog):
    stub = server_stub()
    original = builtins.__import__
    def injected(name, *args, **kwargs):
        if name.endswith("policy.middleware"):
            raise ImportError("synthetic_import_failure_" + SECRET)
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", injected)
    with pytest.raises(RuntimeError, match="Required MCP policy middleware unavailable") as e:
        attach(stub)
    assert SECRET not in str(e.value)
    assert SECRET not in caplog.text
    stub.mcp.add_middleware.assert_not_called()


def test_registration_failure_fails_startup(env, caplog):
    stub = server_stub()
    stub.mcp.add_middleware.side_effect = RuntimeError("synthetic_registration_" + SECRET)
    with pytest.raises(RuntimeError, match="Required MCP policy middleware registration failed") as e:
        attach(stub)
    assert SECRET not in str(e.value)
    assert SECRET not in caplog.text


def test_unexpected_listener_initialization_exception_fails_startup(env, monkeypatch):
    import ha_mcp.policy.decisions as decisions
    def explode(*args, **kwargs):
        raise RuntimeError("synthetic_listener_failure")
    monkeypatch.setattr(decisions, "ApprovalResponseListener", explode)
    with pytest.raises(RuntimeError, match="synthetic_listener_failure"):
        attach(server_stub())


def test_failure_bubbles_through_actual_server_initialization(env, caplog):
    stub = server_stub()
    def fail_only_policy(middleware):
        if isinstance(middleware, PolicyMiddleware):
            raise RuntimeError("synthetic_initialization_failure_" + SECRET)
    stub.mcp.add_middleware.side_effect = fail_only_policy
    stub._apply_tool_security_policies = lambda: attach(stub)
    with pytest.raises(RuntimeError, match="Required MCP policy initialization failed") as error:
        HomeAssistantSmartMCPServer._initialize_server(stub)
    assert SECRET not in str(error.value) + caplog.text
    stub.mcp.http_app.assert_not_called()
    stub.mcp.run.assert_not_called()
    # A partially registered object has not escaped into a serving transport.


def enable_strict(monkeypatch):
    monkeypatch.setenv("HA_MCP_REQUIRE_STRICT_POLICY", "true")


def test_strict_policy_requires_enabled_policy_engine(env, monkeypatch):
    enable_strict(monkeypatch)
    with pytest.raises(RuntimeError, match="policy enforcement is disabled"):
        attach(server_stub(False))


def test_strict_unknown_setting_rejected_before_registration(env, monkeypatch):
    monkeypatch.setenv("HA_MCP_REQUIRE_STRICT_POLICY", "tru")
    with pytest.raises(RuntimeError, match="Invalid mandatory MCP policy setting"):
        attach(server_stub())
    # Mistyped opt-in must not silently mean non-strict.


def test_strict_global_blanket_wildcard_is_rejected(env, monkeypatch):
    enable_strict(monkeypatch)
    save_policy(env, Policy(rule_effect="allow", rules=[Rule(tool_name="*")]))
    with pytest.raises(RuntimeError, match="policy unavailable or invalid"):
        attach(server_stub())


def test_strict_failed_policy_migration_stops_startup(env, monkeypatch):
    import ha_mcp.policy.persistence as persistence
    enable_strict(monkeypatch)
    save_policy(env, Policy(rule_effect="allow", rules=[Rule(tool_name="fixture_read")]))
    def broken_migration(*args, **kwargs):
        raise RuntimeError("synthetic_migration_problem")
    monkeypatch.setattr(persistence, "migrate_policy_any_semantics", broken_migration)
    with pytest.raises(RuntimeError, match="Required MCP policy migration failed"):
        attach(server_stub())


def test_switching_rule_effect_inverts_destructive_rule_meaning():
    # Explicitly document why production's existing approval rules cannot
    # be converted by toggling rule_effect to allow.
    from ha_mcp.policy.evaluator import evaluate, Verdict
    rules = [Rule(tool_name="ha_config_remove_automation")]
    assert evaluate("ha_config_remove_automation", {},
                    Policy(rule_effect="require_approval", rules=rules)) == Verdict.REQUIRE_APPROVAL
    assert evaluate("ha_config_remove_automation", {},
                    Policy(rule_effect="allow", rules=rules)) == Verdict.ALLOW


def test_strict_missing_file_does_not_start(env, monkeypatch):
    enable_strict(monkeypatch)
    with pytest.raises(RuntimeError, match="policy unavailable or invalid"):
        attach(server_stub())


def test_strict_empty_rule_list_does_not_start(env, monkeypatch):
    enable_strict(monkeypatch)
    save_policy(env, Policy(rule_effect="allow", rules=[]))
    with pytest.raises(RuntimeError, match="policy unavailable or invalid"):
        attach(server_stub())


def test_strict_requires_allow_list_to_protect_unknown_tools(env, monkeypatch):
    enable_strict(monkeypatch)
    save_policy(env, Policy(rule_effect="require_approval", rules=[Rule(tool_name="fixture_read")]))
    with pytest.raises(RuntimeError, match="policy unavailable or invalid"):
        attach(server_stub())


def test_strict_corrupt_policy_does_not_start(env, monkeypatch, caplog):
    enable_strict(monkeypatch)
    (env / "tool_policy.json").write_text("synthetic_{invalid}", encoding="utf8")
    with pytest.raises(RuntimeError, match="policy unavailable or invalid") as e:
        attach(server_stub())
    assert SECRET not in str(e.value) + caplog.text


def test_strict_valid_policy_allows_start(env, monkeypatch):
    enable_strict(monkeypatch)
    save_policy(env, Policy(rule_effect="allow", rules=[Rule(tool_name="fixture_read")]))
    stub = server_stub()
    attach(stub)
    assert stub.mcp.add_middleware.call_count == 1


@pytest.mark.anyio
async def test_runtime_policy_file_removal_blocks_actual_tool(env, monkeypatch):
    from ha_mcp._vendor.fastmcp.exceptions import ToolError
    enable_strict(monkeypatch)
    save_policy(env, Policy(rule_effect="allow", rules=[Rule(tool_name="fixture_read")]))
    stub = server_stub()
    attach(stub)
    mw = stub.mcp.add_middleware.call_args.args[0]
    ctx = MagicMock()
    ctx.message.name = "fixture_read"
    ctx.message.arguments = {}
    executed = AsyncMock(return_value="SYNTHETIC_ONLY")
    assert await mw.on_call_tool(ctx, executed) == "SYNTHETIC_ONLY"
    (env / "tool_policy.json").unlink()
    with pytest.raises(ToolError):
        await mw.on_call_tool(ctx, executed)
    executed.assert_awaited_once()


@pytest.mark.anyio
async def test_runtime_invalid_policy_update_blocks_actual_tool(env, monkeypatch):
    from ha_mcp._vendor.fastmcp.exceptions import ToolError
    enable_strict(monkeypatch)
    save_policy(env, Policy(rule_effect="allow", rules=[Rule(tool_name="fixture_read")]))
    stub = server_stub()
    attach(stub)
    mw = stub.mcp.add_middleware.call_args.args[0]
    ctx = MagicMock()
    ctx.message.name = "fixture_read"
    ctx.message.arguments = {}
    executed = AsyncMock(return_value="SYNTHETIC_ONLY")
    assert await mw.on_call_tool(ctx, executed) == "SYNTHETIC_ONLY"
    save_policy(env, Policy(rule_effect="require_approval", rules=[]))
    with pytest.raises(ToolError):
        await mw.on_call_tool(ctx, executed)
    executed.assert_awaited_once()


def load_addon_start():
    module_path = Path(__file__).resolve().parents[2] / "ha_mcp_pinned" / "homeassistant-addon" / "start.py"
    spec = importlib.util.spec_from_file_location("phase2d_pinned_addon_start", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_secret_log_error_paths_sanitize_values(tmp_path, capsys, monkeypatch):
    start = load_addon_start()
    start.get_or_create_secret_path(tmp_path, "bad://" + SECRET)
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    store = tmp_path / "secret_path.txt"
    store.write_text("bad://" + SECRET)
    start.get_or_create_secret_path(tmp_path)
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    def synthetic_error(*args, **kwargs):
        raise OSError("synthetic_" + SECRET)
    monkeypatch.setattr(start, "persist_addon_options", synthetic_error)
    start.maybe_persist_secret_path({"enabled": True}, SECRET, "synthetic-supervisor")
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err


def test_secret_log_filter_redacts_normal_encoded_and_json_forms(capsys):
    start = load_addon_start()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("fastmcp")
    logger.addHandler(handler)
    level = logger.level
    logger.setLevel(logging.INFO)
    try:
        start.install_secret_path_log_filter(SECRET)
        from urllib.parse import quote
        for value in (SECRET, quote(SECRET, safe=""), SECRET.replace("/", "\\/")):
            logger.info("synthetic backend URL %s", value)
        assert SECRET not in stream.getvalue()
        assert quote(SECRET, safe="") not in stream.getvalue()
        assert SECRET.replace("/", "\\/") not in stream.getvalue()
        assert "[MCP_SECRET_REDACTED]" in stream.getvalue()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


def test_secret_log_crash_withholds_exception_text(capsys):
    start = load_addon_start()
    def fail_run(**kwargs):
        raise RuntimeError("confidential_" + SECRET)
    fake = MagicMock()
    fake.run.side_effect = fail_run
    code = start._run_mcp_server(fake, "127.0.0.1", 9583, SECRET, {})
    assert code == 1
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err


def test_secret_log_has_no_interpolated_path_in_known_startup_fields():
    start = load_addon_start()
    text = Path(start.__file__).read_text(encoding="utf8")
    assert 'log_info(f"   Secret Path: {secret_path}")' not in text
    assert 'f"This addon will still run with secret_path={secret_path!r}"' not in text
    assert 'MCP endpoint configured; secret path withheld' in text


def test_secret_recovery_path_remains_persisted(tmp_path):
    start = load_addon_start()
    result = start.get_or_create_secret_path(tmp_path, SECRET)
    assert result == SECRET
    assert (tmp_path / "secret_path.txt").read_text() == SECRET
    assert start.get_or_create_secret_path(tmp_path) == SECRET


def test_secret_packaged_logging_disables_banner_and_access_log():
    start = load_addon_start()
    fake = MagicMock()
    assert start._run_mcp_server(fake, "127.0.0.1", 9583, SECRET,
                                 {"access_log": False}) == 0
    assert fake.run.call_args.kwargs["show_banner"] is False
    source = Path(start.__file__).read_text(encoding="utf8")
    assert '"access_log": False' in source


def test_secret_logging_filter_has_no_real_secrets_in_fixture():
    start = load_addon_start()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("fastmcp")
    logger.addHandler(handler)
    try:
        start.install_secret_path_log_filter(SECRET)
        logger.warning("Synthetic path passed through %s", SECRET)
        assert SECRET not in stream.getvalue()
    finally:
        logger.removeHandler(handler)


def test_secret_late_created_logging_handler_is_redacted():
    start = load_addon_start()
    original = logging.getLogRecordFactory()
    try:
        start.install_secret_path_log_filter(SECRET)
        late = logging.StreamHandler(io.StringIO())
        logger = logging.getLogger("phase2e.late_handler")
        logger.setLevel(logging.INFO)
        logger.addHandler(late)
        try:
            logger.warning("Synthetic startup URL http://localhost:9583%s", SECRET)
            assert SECRET not in late.stream.getvalue()
            assert "[MCP_SECRET_REDACTED]" in late.stream.getvalue()
        finally:
            logger.removeHandler(late)
    finally:
        logging.setLogRecordFactory(original)
