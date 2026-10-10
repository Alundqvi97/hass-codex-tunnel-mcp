# Phase 2F — Safe replacement-policy migration (review candidate only)

**Date:** 2026-10-08. Production status: **UNCHANGED**. Pinned source: `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09`.

## Live mode and evidence

The administrator's latest screenshot shows the **Require approval** mode selected. This confirms policy configuration as displayed in the authenticated UI, not middleware registration or enforcement on actual MCP tool calls. Two earlier screenshots show 18 unconditional single-shot approval rules (0-minute retention). No production policy, secret, account or access setting was read or changed.

The actual v8.6.0 evaluator confirms:
- `require_approval`: matched rules require approval; unmatched tools are automatically allowed.
- `allow`: matched rules automatically execute; unmatched tools require approval.
- Neither mode provides an unconditional HARD DENY.

**Decision:** NEVER toggle the existing 18-rule policy to `allow` unchanged; that would invert those sensitive protections.

## Old policy vs new separate policy

| Existing 18 configured rule names | Old require_approval | Naive switch to allow (FORBIDDEN) | New positive allow-list |
|---|---|---|---|
| `ha_config_remove_automation` | Approval | **Auto allow** | Approval |
| `ha_config_remove_script` | Approval | **Auto allow** | Approval |
| `ha_config_remove_scene` | Approval | **Auto allow** | Approval |
| `ha_delete_file` | Approval | **Auto allow** | Approval |
| `ha_write_file` | Approval | **Auto allow** | Approval |
| `ha_remove_helpers_integrations` | Approval | **Auto allow** | Approval |
| `ha_config_delete_dashboard_resource` | Approval | **Auto allow** | Approval |
| `ha_remove_area_or_floor` | Approval | **Auto allow** | Approval |
| `ha_set_entity` | Approval | **Auto allow** | Approval |
| `ha_remove_entity` | Approval | **Auto allow** | Approval |
| `ha_config_delete_dashboard` | Approval | **Auto allow** | Approval |
| `ha_remove_zone` | Approval | **Auto allow** | Approval |
| `ha_set_device` | Approval | **Auto allow** | Approval |
| `ha_remove_device` | Approval | **Auto allow** | Approval |
| `ha_config_set_label` | Approval | **Auto allow** | Approval |
| `ha_config_remove_label` | Approval | **Auto allow** | Approval |
| `ha_config_set_category` | Approval | **Auto allow** | Approval |
| `ha_config_remove_category` | Approval | **Auto allow** | Approval |

In the new policy, the 18 names are **not** repeated as allow rules. They are **absent**, so under `rule_effect=allow` they all require approval.

| Other operation | Old (if unmatched) | New proposal | Hard deny? |
|---|---|---|---|
| `ha_get_overview` | Auto allow | **Auto allow** (verified read-only tool) | No |
| Lighting, blinds and media via `ha_call_service` | Possibly auto allow | Approval until all argument paths reviewed | No |
| `ha_bulk_control` including selectors | Possibly auto allow | Approval | No |
| Raw WS via `ha_call_service(ws_command=...)` | Possibly auto allow | Approval | No |
| Tool proxy/search/meta dispatch | Depends on nested tool and installed middleware | No blanket auto allow; nested path separately gated | **Not yet proven** |
| HA restart, add-ons, HACS, backup restore/delete, security editing | Possibly auto allow | Approval, and recommend removing tools that must be impossible to invoke | No |
| Unknown tool after an update | Auto allow if unmatched | Approval | No |

### Concrete new policy (synthetic, NOT for immediate import)

```json
{
  "schema_version": 2,
  "rule_effect": "allow",
  "rules": [
    {"tool_name": "ha_get_overview", "when": [], "remember_minutes": 0}
  ]
}
```

The genuine v8.6.0 `Policy` serializer supplies other operational defaults (`wait_seconds`, `approval_ttl_minutes`, etc.). The actual candidate writes the full validated model, never replaces live policy contents or secrets.

This baseline **intentionally does not auto-allow lighting**. The generic service tool has multiple argument forms, and allowing only `args.domain=light` could approve unexpected services or compound calls. Later convenience rules must match the exact installed tool schema, service name, canonical target entity IDs and all alternative target/selector forms, with negative tests. If a route cannot be constrained reliably, keep it approval-required or remove its registration.

### Strict-mode enforcement boundary

Phase 2F patches the pinned v8.6.0 add-on source to expose `require_strict_tool_policy: bool?` in Supervisor schema (default false), export a validated runtime setting and persist a `strict_policy_required.v1.json` marker to the existing add-on `/data` volume when first opted in.

The actual strict runtime policy provider reevaluates every request and requires the sole initial read-only auto-allowed tool name `ha_get_overview` with no predicates. A new tool or policy rewrite to broad auto-allow fails closed; the startup preflight and on-call provider separately enforce it. This is a restrictive starting policy, not a general syntax for expressing all future convenience allowances.

**Not an unbreakable security marker:** A local administrator with write access to the entire `/data` volume can remove both the marker and security option. This is trusted administrative storage, not a TPM-backed anti-rollback mechanism. Damaged/missing marker contents fail startup only when an invalid marker remains; deletion of both marker and option cannot be detected from a single store. Protect backups and access to the marker, and use separate policy/version attestation if adversarial rollback is in scope.

### Test plan and status

Real pinned evaluator tests reproduce all 18 original approval outcomes, explicitly show how a naive mode switch would automatically allow those destructive calls, verify the separate positive list keeps them approval-required, and test the known generic/raw WS/bulk/unknown tool names. This is **evaluator behavior**, not a full nested-proxy authorization or real HA permission test.

Supported-option tests cover type validation, legacy opt-out, marker creation, corrupt/missing options, policy migration interruption, marker corruption, downgrade attempts and runtime policy changes. Actual packaged entrypoint tests with no external network use a disposable synthetic Supervisor data volume.

For counts and final CI conclusions, consult `STRICT_MODE_TEST_RESULTS.md`. No result is considered passing merely because a test has been written.

**Acceptance limitations:** full nested proxy dispatch, approval expiry/replay, HAOS Supervisor boot, independent local restore, hosted OpenAI attachment denial, IPv4/IPv6 reachability and full effective live policy remain separate gates. No production operations allowed.
