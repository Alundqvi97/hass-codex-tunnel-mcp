# Phase 2E — Effective configured policy inventory from official administrator UI

Evidence date: 2026-10-08. Source: two authorized administrator UI screenshots supplied as PDFs (`HA Rules.pdf`, `HA rules 2.pdf`) on this conversation. **Do not commit the screenshots:** their Home Assistant interface and local details are private.

## Evidence classification and limits

**VERIFIED LIVE, USER-SUPPLIED VISUAL EVIDENCE:** Home Assistant MCP Server 8.6.0 administrator screen, policy section `Gated tools`. Both PDF pages show contiguous portions of the tool-policy editor with overlap. The following **18 distinct rule names** are legible:

1. `ha_config_remove_automation`
2. `ha_config_remove_script`
3. `ha_config_remove_scene`
4. `ha_delete_file`
5. `ha_write_file`
6. `ha_remove_helpers_integrations`
7. `ha_config_delete_dashboard_resource`
8. `ha_remove_area_or_floor`
9. `ha_set_entity`
10. `ha_remove_entity`
11. `ha_config_delete_dashboard`
12. `ha_remove_zone`
13. `ha_set_device`
14. `ha_remove_device`
15. `ha_config_set_label`
16. `ha_config_remove_label`
17. `ha_config_set_category`
18. `ha_config_remove_category`

Each visible editor card says `(always — gates every call to this tool)`, with no argument-condition rows, `Remember approval for: 0 minutes (0 = single-shot)`. This is **configured intent**, not a demonstrated complete enforcement trace. The screenshots do **not** show the policy's overall `rule_effect`, last successful PolicyMiddleware registration, or rules outside the captured editor.

The available authenticated HA-MCP connector exposes **79 tool method names** in this session, including the broad administrative routes noted below. This 79 is the **available connector tool catalog**, not an independently proven count of the running add-on's registered tools. A smaller scoped live catalog and runtime enablement/disabled status need to be checked before claiming an exact coverage percentage.

## High-impact administrative paths not represented in the captured rule list

| Operation | Named entry point(s) | Current screenshot coverage | Risk if default mode is `require_approval` |
|---|---|---|---|
| Broad service calls / locks / alarm / media | `ha_call_service` | NOT LISTED | Potential ungated action if no other rule or guard |
| Bulk state/control changes | `ha_bulk_control` | NOT LISTED | Potential ungated updates |
| Raw HA WebSocket through service tool | `ha_call_service(ws_command=...)` | NOT LISTED | Broad alternative admin operation path |
| HA restart or reload | `ha_restart`, `ha_reload_core` | NOT LISTED | System disruption may be ungated |
| Add-on management / updates | `ha_manage_addon`, `ha_manage_updates` | NOT LISTED | Update/restart/integration control may be ungated |
| Backup create/restore/delete | `ha_manage_backup` | NOT LISTED | Restore/delete requires separate safe guard |
| HACS/integration/automation/script edits | `ha_manage_hacs`, `ha_set_integration`, `ha_config_set_automation`, `ha_config_set_script` | NOT LISTED | Alternate configuration paths not matched |
| YAML/config editing, raw template | `ha_config_set_yaml`, `ha_eval_template` | NOT LISTED | Config mutation via alternate route or expression requires audit |
| Door lock/camera/privacy entity actions | generic service and direct tools | No domain-aware rules shown | Sensitive actions not protected by individual deletion-only rules |
| Tool search/proxy/meta-tools | `ha_search` and inner dispatch | NOT LISTED | Need verify per-destination and nested policy checks |

**Do not claim these are definitely unprotected.** Default mode and runtime middleware registration remain unknown. The screenshots themselves warn: `Policies apply to individual tools. Other tools may perform the same action.`

## Critical strict-mode migration warning

In exact `ha-mcp@fc54437a804858732e4bc927add98e202d879a09`:
- Under `rule_effect="require_approval"`, the 18 matching rules **require approval** and unmatched calls run.
- Under `rule_effect="allow"`, the same 18 matching rules instead **run automatically**, with unmatched calls requiring approval.

Therefore **never flip the existing production rule_effect to allow without rebuilding the entire rule list from reviewed positive permissions**. In particular, allowing rules named `ha_delete_file` or `ha_config_remove_automation` would be unsafe. A real pinned-source regression test documents this inversion; strict mode is NOT ready for migration by toggling the mode.

## Remaining required evidence

- Policy's exact `rule_effect` (not in screenshot).
- Full installed tool catalog and disabled-tool list, not just connector methods.
- Middleware initialization success, alerting when middleware is missing and actual approval path.
- Server-side evaluation for generic `ha_call_service`, `ha_bulk_control`, raw WebSocket and nested proxy tools with synthetic operations.
- Approved/expired/replayed approval token behavior after policy invalidation.
- No user should provide secret URL, keys, policy file raw content or system PIN for further review.

**Disposition:** Configured list documented. Actual effective authorization for administrative operations remains **PARTIAL/BLOCKED**. No rules were changed.


## Phase 2F mode confirmation and safe-migration result

The subsequently supplied official administrator screenshot shows **Require approval** selected. This resolves the earlier **policy-mode visibility** gap, but does not establish whether the configured middleware loaded successfully.

All 18 captured unconditional rules therefore require approval for their exact names under the documented current mode; any unmatched names may run without approval under pinned evaluator semantics. Broad `ha_call_service`, `ha_bulk_control`, `ha_restart`, backup, add-on and integration routes absent from the pictured rules need immediate future coverage review. Do not infer no other saved rules exist beyond the screenshots.

The actual pinned 8.6.0 evaluator regression tested the complete 18-rule names. A naive `require_approval`→`allow` mode toggle automatically allows **all 18 destructive/configuration names**, and is explicitly prohibited. New replacement policy has only `ha_get_overview` as an automatic allow; all 18 old names and unknown tools now require approval. See `../phase2f/POLICY_MIGRATION.md` and `../phase2f/STRICT_MODE_TEST_RESULTS.md`.

No production setting, policy file or middleware was modified.
