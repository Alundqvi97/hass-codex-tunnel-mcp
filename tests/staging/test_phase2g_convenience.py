"""Separate Phase 2G convenience policy. Synthetic targets; NOT production config.

Validate actual pinned policy evaluator, not a custom copied matcher. All
automated control operations remain behind approval until an operation-aware
guard independently validates the COMPLETE final target and service payload.
"""
import pytest
from ha_mcp.policy.model import Policy, Rule, Predicate
from ha_mcp.policy.evaluator import Verdict, evaluate

READ_IDS=[
    "light.synthetic_living",
    "light.synthetic_dining",
    "cover.synthetic_living",
    "media_player.synthetic_tv",
]


def candidate():
    return Policy(rule_effect="allow",rules=[
        Rule(tool_name="ha_get_overview"),
        Rule(tool_name="ha_get_state",when=[
            Predicate(path="args.entity_id",op="in",value=READ_IDS)]),
        Rule(tool_name="ha_list_services",when=[
            Predicate(path="args.domain",op="in",
                      value=["light","cover","media_player"])]),
    ])


@pytest.mark.parametrize("name,args",[
    ("ha_get_overview",{}),
    ("ha_get_state",{"entity_id":"light.synthetic_living"}),
    ("ha_get_state",{"entity_id":"light.synthetic_dining"}),
    ("ha_get_state",{"entity_id":"cover.synthetic_living"}),
    ("ha_get_state",{"entity_id":"media_player.synthetic_tv"}),
    ("ha_list_services",{"domain":"light"}),
    ("ha_list_services",{"domain":"cover"}),
    ("ha_list_services",{"domain":"media_player"}),
])
def test_bounded_read_operations_auto_allow(name,args):
    assert evaluate(name,args,candidate())==Verdict.ALLOW


@pytest.mark.parametrize("name,args",[
    ("ha_get_state",{"entity_id":"lock.synthetic_front_door"}),
    ("ha_get_state",{"entity_id":"camera.synthetic_private"}),
    ("ha_get_state",{"entity_id":"light.synthetic_living,lock.synthetic_front_door"}),
    ("ha_get_state",{"entity_id":"all"}),
    ("ha_get_state",{}),
    ("ha_get_state",{"entity_id":["light.synthetic_living","lock.synthetic_front_door"]}),
    ("ha_list_services",{"domain":"lock"}),
    ("ha_list_services",{}),
    ("ha_call_service",{"domain":"light","service":"turn_on","entity_id":"light.synthetic_living"}),
    ("ha_call_service",{"domain":"lock","service":"unlock","entity_id":"lock.synthetic_front_door"}),
    ("ha_call_service",{"ws_command":'{"type":"call_service"}'}),
    ("ha_bulk_control",{"selector":{"domain":"light"},"action":"on"}),
    ("ha_restart",{}),
    ("ha_manage_backup",{"scope":"snapshot","action":"restore"}),
    ("ha_manage_addon",{"slug":"synthetic","action":"stop"}),
    ("ha_manage_security_policy",{"action":"set"}),
    ("ha_dev_manage_server",{"action":"restart"}),
    ("ha_config_set_automation",{"config":{"alias":"synthetic"}}),
    ("new_tool_after_upgrade",{}),
])
def test_write_security_and_unscoped_reads_need_approval(name,args):
    assert evaluate(name,args,candidate())==Verdict.REQUIRE_APPROVAL


def test_naive_light_service_rule_cannot_restrict_additional_target_fields():
    # Real policy evaluator proves an ARGUMENT-ONLY whitelist of domain,
    # service and entity_id can still match a call with arbitrary extra data.
    # This is an evaluator-level gap, NOT proof that HA would accept the
    # final extra target or dispatch it. It disqualifies this proposed rule.
    tempting=Policy(rule_effect="allow",rules=[Rule(
        tool_name="ha_call_service",when=[
            Predicate(path="args.domain",op="eq",value="light"),
            Predicate(path="args.service",op="in",value=["turn_on","turn_off"]),
            Predicate(path="args.entity_id",op="eq",
                      value="light.synthetic_living"),
        ])])
    args={"domain":"light","service":"turn_on",
          "entity_id":"light.synthetic_living",
          "data":{"area_id":["synthetic_all_other_areas"],"device_id":["other"]}}
    assert evaluate("ha_call_service",args,tempting)==Verdict.ALLOW
    assert evaluate("ha_call_service",args,candidate())==Verdict.REQUIRE_APPROVAL


@pytest.mark.parametrize("name",[
    "ha_call_service","ha_bulk_control","ha_call_event","ha_manage_backup",
    "ha_manage_addon","ha_restart","ha_config_set_yaml","ha_set_entity",
    "ha_remove_entity","ha_manage_security_policy",
])
def test_no_unsafe_automatic_control_rule_is_present(name):
    assert all(rule.tool_name!=name for rule in candidate().rules)


def test_future_unlisted_tool_is_never_auto_allow():
    assert evaluate("ha_tool_added_in_2027",{},candidate())==Verdict.REQUIRE_APPROVAL
