"""Phase 2F real pinned HA-MCP policy & supported add-on preflight tests."""
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from ha_mcp.policy.model import Policy, Rule
from ha_mcp.policy.evaluator import evaluate, Verdict
from ha_mcp.policy.persistence import save_policy, load_policy
from ha_mcp.server import HomeAssistantSmartMCPServer

ORIGINAL_APPROVALS = [
 "ha_config_remove_automation","ha_config_remove_script",
 "ha_config_remove_scene","ha_delete_file","ha_write_file",
 "ha_remove_helpers_integrations","ha_config_delete_dashboard_resource",
 "ha_remove_area_or_floor","ha_set_entity","ha_remove_entity",
 "ha_config_delete_dashboard","ha_remove_zone","ha_set_device",
 "ha_remove_device","ha_config_set_label","ha_config_remove_label",
 "ha_config_set_category","ha_config_remove_category",
]
SENSITIVE_ALTERNATIVES = [
 "ha_call_service","ha_bulk_control","ha_restart","ha_manage_addon",
 "ha_manage_backup","ha_manage_hacs","ha_config_set_automation",
 "ha_config_set_script","ha_config_set_yaml","ha_manage_updates",
 "ha_set_integration","ha_eval_template",
]
ROOT = Path(__file__).resolve().parents[2] / "ha_mcp_pinned"


def start_module():
    p=ROOT/"homeassistant-addon/start.py"
    spec=importlib.util.spec_from_file_location("phase2f_start",p)
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def stage(tmp_path,monkeypatch):
    monkeypatch.setenv("HA_MCP_CONFIG_DIR",str(tmp_path))
    monkeypatch.setenv("HA_MCP_REQUIRE_STRICT_POLICY","true")
    from ha_mcp.utils.data_paths import get_data_dir
    get_data_dir.cache_clear()
    yield tmp_path
    get_data_dir.cache_clear()


def options(stage, strict=True, engine=True):
    p=stage/"options.json"
    p.write_text(json.dumps({"require_strict_tool_policy":strict,
                             "enable_tool_security_policies":engine}))
    return p


def safe(stage):
    save_policy(stage,Policy(rule_effect="allow",rules=[Rule(tool_name="ha_get_overview")]))


def test_original_approval_policy_never_automatically_allows_destructive_rules():
    policy=Policy(rule_effect="require_approval",
                  rules=[Rule(tool_name=t) for t in ORIGINAL_APPROVALS])
    assert len(ORIGINAL_APPROVALS)==18
    for tool in ORIGINAL_APPROVALS:
        assert evaluate(tool,{},policy)==Verdict.REQUIRE_APPROVAL


def test_naive_switch_to_allow_exposes_all_18_and_must_fail_acceptance():
    naive=Policy(rule_effect="allow",rules=[Rule(tool_name=t) for t in ORIGINAL_APPROVALS])
    assert all(evaluate(tool,{},naive)==Verdict.ALLOW for tool in ORIGINAL_APPROVALS)


def test_new_policy_requires_approval_for_all_sensitive_paths():
    policy=Policy(rule_effect="allow",rules=[Rule(tool_name="ha_get_overview")])
    assert evaluate("ha_get_overview",{},policy)==Verdict.ALLOW
    for name in ORIGINAL_APPROVALS+SENSITIVE_ALTERNATIVES+["new_tool_after_upgrade"]:
        assert evaluate(name,{},policy)==Verdict.REQUIRE_APPROVAL, name
    for args in [
        {"domain":"lock","service":"unlock","entity_id":"lock.synthetic"},
        {"domain":"light","service":"turn_on","entity_id":"light.synthetic"},
        {"ws_command":{"type":"call_service","domain":"lock","service":"unlock"}},
        {"domain":"alarm_control_panel","service":"alarm_disarm"},
    ]:
        assert evaluate("ha_call_service",args,policy)==Verdict.REQUIRE_APPROVAL
    for args in [
        {"selector":{"area_id":["synthetic_room"]},"action":"turn_on"},
        {"operations":[{"entity_id":"lock.synthetic","action":"unlock"}]},
    ]:
        assert evaluate("ha_bulk_control",args,policy)==Verdict.REQUIRE_APPROVAL


def test_nested_proxy_names_are_never_auto_allowed():
    policy=Policy(rule_effect="allow",rules=[Rule(tool_name="ha_get_overview")])
    for tool in ["ha_search","ha_tool_search","ha_search_tools","ha_find_and_call_tool"]:
        assert evaluate(tool,{"tool_name":"ha_call_service"},policy)==Verdict.REQUIRE_APPROVAL
    # This checks evaluator only: nested dispatch must still be tested separately.


def test_supported_schema_contains_opt_in_and_false_default():
    s=(ROOT/"homeassistant-addon/config.yaml").read_text()
    assert "  require_strict_tool_policy: false" in s
    assert "  require_strict_tool_policy: bool?" in s


def test_first_opt_in_writes_durable_marker_with_restrictive_mode(stage):
    m=start_module();safe(stage);p=options(stage)
    assert m.configure_supported_strict_policy(stage,p) is True
    marker=stage/"strict_policy_required.v1.json"
    assert json.loads(marker.read_text())=={"schema_version":1,"required":True}
    assert (marker.stat().st_mode & 0o777)==0o600


def test_legacy_without_opt_in_does_not_create_marker(stage):
    m=start_module();p=options(stage,strict=False,engine=False)
    assert m.configure_supported_strict_policy(stage,p) is False
    assert not (stage/"strict_policy_required.v1.json").exists()


@pytest.mark.parametrize("bad",["null","1","[]","{}","\"yes\""])
def test_invalid_option_types_fail_preflight(stage,bad):
    m=start_module();p=stage/"options.json"
    p.write_text('{"require_strict_tool_policy":'+bad+', "enable_tool_security_policies":true}')
    with pytest.raises(ValueError):
        m.configure_supported_strict_policy(stage,p)


def test_missing_options_after_opt_in_fail_closed(stage):
    m=start_module();safe(stage);p=options(stage)
    assert m.configure_supported_strict_policy(stage,p)
    p.unlink()
    with pytest.raises(ValueError,match="unavailable"):
        m.configure_supported_strict_policy(stage,p)


def test_corrupt_options_after_opt_in_fail_closed(stage):
    m=start_module();safe(stage);p=options(stage)
    assert m.configure_supported_strict_policy(stage,p)
    p.write_text("{invalid")
    with pytest.raises(json.JSONDecodeError):
        m.configure_supported_strict_policy(stage,p)


def test_marker_prevents_downgrade_but_restored_configuration_recovers(stage):
    m=start_module();safe(stage);p=options(stage)
    assert m.configure_supported_strict_policy(stage,p)
    options(stage,strict=False)
    with pytest.raises(ValueError,match="cannot be downgraded"):
        m.configure_supported_strict_policy(stage,p)
    options(stage,strict=True)
    assert m.configure_supported_strict_policy(stage,p)


def test_interrupted_marker_write_fails_closed(stage):
    m=start_module();safe(stage);p=options(stage)
    marker=stage/"strict_policy_required.v1.json"
    marker.write_text('{"required":tru')
    with pytest.raises(json.JSONDecodeError):
        m.configure_supported_strict_policy(stage,p)
    assert marker.read_text()=='{"required":tru'


def test_marker_symlink_rejected(stage):
    m=start_module();safe(stage);p=options(stage)
    (stage/"strict_policy_required.v1.json").symlink_to(stage/"options.json")
    with pytest.raises(ValueError,match="type invalid"):
        m.configure_supported_strict_policy(stage,p)


def test_bad_strict_policy_does_not_commit_marker(stage):
    m=start_module();p=options(stage)
    save_policy(stage,Policy(rule_effect="require_approval",
                             rules=[Rule(tool_name="ha_config_remove_automation")]))
    with pytest.raises(ValueError):
        m.configure_supported_strict_policy(stage,p)
    assert not (stage/"strict_policy_required.v1.json").exists()


@pytest.mark.parametrize("tool",ORIGINAL_APPROVALS + ["ha_call_service","ha_bulk_control","ha_restart","*"])
def test_dangerous_auto_rule_not_allowed_at_opt_in(stage,tool):
    m=start_module();p=options(stage)
    save_policy(stage,Policy(rule_effect="allow",rules=[Rule(tool_name=tool)]))
    with pytest.raises(ValueError,match="unreviewed automatic"):
        m.configure_supported_strict_policy(stage,p)


def test_allow_policy_cannot_be_widened_after_enable(stage):
    m=start_module();p=options(stage);safe(stage)
    assert m.configure_supported_strict_policy(stage,p)
    # Register middleware with a known-good policy first.
    stub=MagicMock()
    stub.settings.enable_tool_security_policies=True
    HomeAssistantSmartMCPServer._apply_tool_security_policies(stub)
    middleware=stub.mcp.add_middleware.call_args.args[0]
    save_policy(stage,Policy(rule_effect="allow",rules=[Rule(tool_name="ha_call_service")]))
    # Preflight rejects on restart.
    with pytest.raises(ValueError,match="unreviewed"):
        m.configure_supported_strict_policy(stage,p)
    # The already-installed middleware also rejects a widened policy.
    with pytest.raises(ValueError):
        middleware._policy_provider()


def test_option_flag_disabled_engine_fails(stage):
    m=start_module();safe(stage);p=options(stage,engine=False)
    with pytest.raises(ValueError,match="engine"):
        m.configure_supported_strict_policy(stage,p)
