"""Pinned ha-mcp 8.6.0 *real source* staging tests.

Run exclusively against upstream fc54437a804858732e4bc927add98e202d879a09.
This is genuine HttpTransportFastMCP/PolicyMiddleware, but not an entire
Supervisor add-on nor the production HA-MCP tool catalog.

All credentials, tools and target paths are synthetic. Uses ASGI TestClient
(no network listener), with outbound IP connections refused.
"""
from __future__ import annotations

import builtins
import json
import socket
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.testclient import TestClient

from ha_mcp.http_transport import HttpTransportFastMCP
from ha_mcp.policy.approval_queue import ApprovalQueue
from ha_mcp.policy.evaluator import Verdict, evaluate
from ha_mcp.policy.middleware import PolicyMiddleware
from ha_mcp.policy.model import Policy, Predicate, Rule
from ha_mcp.policy.persistence import load_policy, save_policy
from ha_mcp.server import HomeAssistantSmartMCPServer

SECRET = "/private_synthetic_phase2c_no_production_access"
WRONG = "/private_wrong_test_value"
AUTHZ = [
    None,
    "Bearer incorrect-synthetic",
    "Bearer correct-synthetic",
    "Basic synthetic",
    "Bearer expired-like-synthetic",
    "Bearer",
]


@pytest.fixture(autouse=True)
def refuse_external_sockets(monkeypatch):
    """Refuse all external IPv4/v6 connects even if an imported library tries."""
    real_connect = socket.socket.connect

    def limited_connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            host = str(address[0])
            if host not in ("127.0.0.1", "::1"):
                raise AssertionError("OFFLINE_STAGING_NETWORK_DENIED")
        return real_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", limited_connect)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def staged_http(monkeypatch, tmp_path):
    monkeypatch.setenv("HA_MCP_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("HOMEASSISTANT_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("HOMEASSISTANT_TOKEN", "synthetic-unused-token")
    from ha_mcp.config import reset_global_settings
    from ha_mcp.utils.data_paths import get_data_dir

    reset_global_settings()
    get_data_dir.cache_clear()
    mcp = HttpTransportFastMCP("phase2c-synthetic", version="0.0.0-test")

    @mcp.tool(name="fixture_read_status")
    def read_status() -> str:
        return "SYNTHETIC_READ_ONLY_OK"

    app = mcp.http_app(path=SECRET, stateless_http=True, json_response=True)
    with TestClient(app, base_url="http://testserver") as client:
        yield client
    get_data_dir.cache_clear()
    reset_global_settings()


def call_http(client, path, method, authorization=None):
    headers = {"Accept": "application/json, text/event-stream"}
    if authorization is not None:
        headers["Authorization"] = authorization
    params = {}
    if method == "initialize":
        params = {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "synthetic-client", "version": "0.0.0"},
        }
    elif method == "tools/call":
        params = {"name": "fixture_read_status", "arguments": {}}
    return client.post(
        path, headers=headers, timeout=3,
        json={"jsonrpc": "2.0", "id": 7, "method": method, "params": params},
    )


@pytest.mark.parametrize("method", ["initialize", "tools/list", "tools/call"])
@pytest.mark.parametrize("authorization", AUTHZ)
def test_genuine_standard_mode_accepts_any_bearer_at_correct_secret_path(
    staged_http, method, authorization
):
    response = call_http(staged_http, SECRET, method, authorization)
    assert response.status_code == 200, (method, authorization, response.status_code)
    result = response.json()
    assert result.get("id") == 7 and "result" in result, result
    if method == "tools/list":
        assert [t["name"] for t in result["result"]["tools"]] == [
            "fixture_read_status"
        ]
    if method == "tools/call":
        assert "SYNTHETIC_READ_ONLY_OK" in str(result["result"])


@pytest.mark.parametrize("method", ["initialize", "tools/list", "tools/call"])
@pytest.mark.parametrize("authorization", [None, "Bearer correct-synthetic"])
def test_genuine_standard_mode_rejects_wrong_path(staged_http, method, authorization):
    response = call_http(staged_http, WRONG, method, authorization)
    assert response.status_code in (404, 405), response.status_code
    assert "SYNTHETIC_READ_ONLY_OK" not in response.text


def test_genuine_http_session_reuse_stateless_transport(staged_http):
    for _ in range(3):
        response = call_http(staged_http, SECRET, "tools/call")
        assert response.status_code == 200
        assert "SYNTHETIC_READ_ONLY_OK" in response.text


def test_actual_policy_evaluator_missing_policy_and_unmatched_tool(tmp_path):
    missing = load_policy(tmp_path)
    assert missing.rules == []
    assert evaluate("ha_call_service", {"domain": "lock"}, missing) == Verdict.ALLOW
    one_rule = Policy(rules=[Rule(tool_name="synthetic_lock_tool")])
    assert evaluate("ha_call_service", {"domain": "lock"}, one_rule) == Verdict.ALLOW


def test_actual_policy_evaluator_direct_tool_only_is_not_action_wide():
    policy = Policy(rules=[Rule(tool_name="synthetic_lock_tool")])
    assert evaluate("synthetic_lock_tool", {}, policy) == Verdict.REQUIRE_APPROVAL
    assert evaluate("ha_call_service", {"domain": "lock", "service": "unlock"}, policy) == Verdict.ALLOW
    assert evaluate("ha_bulk_control", {"action": "unlock"}, policy) == Verdict.ALLOW


def test_actual_policy_evaluator_generic_tool_rule_closes_named_alternative():
    policy = Policy(rules=[
        Rule(tool_name="synthetic_lock_tool"),
        Rule(tool_name="ha_call_service", when=[
            Predicate(path="args.domain", op="eq", value="lock")
        ]),
        Rule(tool_name="ha_bulk_control"),
    ])
    assert evaluate("ha_call_service", {"domain": "lock", "service": "unlock"}, policy) == Verdict.REQUIRE_APPROVAL
    assert evaluate("ha_bulk_control", {"action": "unlock"}, policy) == Verdict.REQUIRE_APPROVAL
    assert evaluate("ha_call_service", {"domain": "light"}, policy) == Verdict.ALLOW


def test_policy_reloads_between_calls(tmp_path):
    file = tmp_path / "tool_policy.json"
    assert evaluate("fixture_admin", {}, load_policy(tmp_path)) == Verdict.ALLOW
    save_policy(tmp_path, Policy(rules=[Rule(tool_name="fixture_admin")]))
    assert file.exists()
    assert evaluate("fixture_admin", {}, load_policy(tmp_path)) == Verdict.REQUIRE_APPROVAL


@pytest.mark.anyio
async def test_actual_policy_middleware_corrupt_config_denies_dispatch():
    from ha_mcp._vendor.fastmcp.exceptions import ToolError
    def invalid():
        raise ValueError("synthetic invalid policy")
    mw = PolicyMiddleware(policy_provider=invalid, queue=ApprovalQueue())
    ctx = MagicMock()
    ctx.message.name = "fixture_admin"
    ctx.message.arguments = {}
    next_call = AsyncMock(return_value="SHOULD_NOT_RUN")
    with pytest.raises(ToolError):
        await mw.on_call_tool(ctx, next_call)
    next_call.assert_not_awaited()


@pytest.mark.anyio
async def test_actual_policy_middleware_empty_policy_allows_dispatch():
    mw = PolicyMiddleware(policy_provider=Policy, queue=ApprovalQueue())
    ctx = MagicMock()
    ctx.message.name = "fixture_admin"
    ctx.message.arguments = {}
    next_call = AsyncMock(return_value="SYNTHETIC_DISPATCH")
    assert await mw.on_call_tool(ctx, next_call) == "SYNTHETIC_DISPATCH"
    next_call.assert_awaited_once()


def make_server_stub(monkeypatch, tmp_path):
    monkeypatch.setenv("HA_MCP_CONFIG_DIR", str(tmp_path))
    from ha_mcp.utils.data_paths import get_data_dir
    get_data_dir.cache_clear()
    stub = MagicMock()
    stub.settings.enable_tool_security_policies = True
    return stub


def test_actual_server_attaches_policy_middleware(monkeypatch, tmp_path):
    stub = make_server_stub(monkeypatch, tmp_path)
    HomeAssistantSmartMCPServer._apply_tool_security_policies(stub)
    assert any(
        isinstance(args[0], PolicyMiddleware)
        for args, _ in (call for call in [x for x in [c for c in
          [(c.args, c.kwargs) for c in stub.mcp.add_middleware.call_args_list]]])
    )


def test_actual_server_registration_exception_leaves_gate_absent(
    monkeypatch, tmp_path, caplog
):
    stub = make_server_stub(monkeypatch, tmp_path)
    stub.mcp.add_middleware.side_effect = RuntimeError("synthetic_registration_failure")
    HomeAssistantSmartMCPServer._apply_tool_security_policies(stub)
    assert "TOOL SECURITY GATING IS NOT ACTIVE" in caplog.text
    assert stub.mcp.add_middleware.call_count == 1
    # It returned (no raise), so outer server startup would continue.


def test_actual_server_import_failure_leaves_gate_absent(
    monkeypatch, tmp_path, caplog
):
    stub = make_server_stub(monkeypatch, tmp_path)
    real_import = builtins.__import__

    def fail_specific_import(name, *args, **kwargs):
        if name == "ha_mcp.policy.middleware" or name == ".policy.middleware":
            raise ImportError("synthetic_middleware_missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_specific_import)
    try:
        HomeAssistantSmartMCPServer._apply_tool_security_policies(stub)
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
    assert "TOOL SECURITY GATING IS NOT ACTIVE" in caplog.text
    stub.mcp.add_middleware.assert_not_called()


def test_addon_startup_synthetic_secret_logging_source(tmp_path, capsys):
    """Load real add-on startup module, but NEVER run main/Supervisor calls."""
    import importlib.util
    path = Path(__file__).resolve().parents[2] / "ha_mcp_pinned" / "homeassistant-addon" / "start.py"
    spec = importlib.util.spec_from_file_location("pinned_addon_entry", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    value = "/private_synthetic_do_not_reuse_abc123"
    module.log_info(f"   Secret Path: {value}")
    captured = capsys.readouterr().out
    assert value in captured, "demonstrates startup logger exposes secret if passed"
    # The real add-on source includes this same interpolated logging call.
    source = path.read_text()
    assert 'log_info(f"   Secret Path: {secret_path}")' in source
    assert "log_info(f\"🔐 MCP Server URL:" in source


def test_pinned_revision_marked_in_staging_receipt():
    import subprocess
    root = Path(__file__).resolve().parents[2] / "ha_mcp_pinned"
    sha = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=3, check=True,
    ).stdout.strip()
    assert sha == "fc54437a804858732e4bc927add98e202d879a09"
