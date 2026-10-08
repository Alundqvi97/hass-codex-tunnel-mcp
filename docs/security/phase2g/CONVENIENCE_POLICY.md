# Phase 2G — Separate, everyday-use convenience policy (NOT FOR IMPORT)

The Phase 2F hardening candidate allows **only** `ha_get_overview` automatically and revalidates this exact tiny list at every call. This separate policy is a **proposal**, not a replacement of that tested enforcement. Enabling any further read-only tool requires a separately reviewed change to the Phase 2F allow-list validator and fresh full regression tests.

## Proposed operator experience

| Capability | Proposed action | Reason |
|---|---|---|
| `ha_get_overview` read-only overview | AUTO-ALLOW | Bounded non-destructive status |
| `ha_get_state` for explicitly selected non-sensitive light, blind and media entities only | AUTO-ALLOW (candidate) | Exact target IDs, read-only tool; never `all`, comma targets, cameras, security devices or presence trackers |
| `ha_list_services` for `light`, `cover`, `media_player` only | AUTO-ALLOW (candidate) | Read-only service catalogue scoped by domain |
| Ordinary lighting/scenes, blinds, media state changes | APPROVAL REQUIRED initially | The broad generic dispatch tool carries arbitrary nested data and multiple target forms |
| Script/automation/helper/dashboard/config edits | APPROVAL REQUIRED | Side effects, alternate tool entrypoints |
| Locks, alarms, security cameras/privacy and occupancy/presence logic | APPROVAL REQUIRED, prefer HARD DENY of sensitive commands where possible | Safety and privacy critical |
| Backups, add-ons, updates, restart, security policies, credential/config files | APPROVAL REQUIRED or tool DISABLED | Recovery/admin boundary |
| Unknown new tools | APPROVAL REQUIRED | No implicit expansion after update |

**A hard deny is not synonymous with approval-required.** Existing policy evaluator has `ALLOW` and `REQUIRE_APPROVAL`, and no comprehensive irreversible deny. To prevent any action entirely, remove/unregister its tool or add an operation-aware server-side DENY guard after schema/dispatch normalization and before HA side effects.

## Proposed synthetic test model (not a deployment file)

`tests/staging/test_phase2g_convenience.py` defines the draft:
- `rule_effect="allow"`, `ha_get_overview` automatically allowed.
- `ha_get_state` permitted only for `light.synthetic_living`, `light.synthetic_dining`, `cover.synthetic_living`, `media_player.synthetic_tv`.
- `ha_list_services` permitted only when `args.domain` is one of `light`, `cover`, `media_player`.
- All other tool names and entity targets require approval.

These are **synthetic example IDs**, not your HA entity names, and this document must never be imported into production as-is.

## Why not auto-allow `light.turn_on` yet?

Pinned `ha_call_service` accepts `domain`, `service`, `entity_id`, additional `data`, and a `ws_command` escape hatch. A superficially attractive `allow` rule checking only `args.domain=light`, `args.service in [turn_on,turn_off]`, and `args.entity_id=light.synthetic_living` also evaluates **ALLOW** for an envelope containing additional `data.area_id` and `data.device_id`. The current evaluator does **not** reject unmentioned keys. This is a **policy-expression limitation**, not proof the underlying HA service handler would dispatch to those additional targets.

A safe automatic actuator should instead be a purpose-built, registered, typed wrapper such as `household_control_light(entity_id, action, brightness?)` with fixed target IDs, explicit on/off/brightness service mappings, exact allowed argument keys, no raw WS/data/selector escape, a final target-resolution check, and verified negative tests of all alternative routes. Likewise for blinds and media, after exact schema inspection. Only register the wrapper when the full final authorization path can be proved and undo/verification behavior is bounded.

**Security over convenience:** avoid adding generic `ha_call_service`, `ha_bulk_control`, tool-discovery proxies, wildcard `*`, or `ha_manage_backup` to automatic allow rules.

## Status and user action

Source-level tests of this proposal should be evaluated against genuine 8.6.0 `Policy`/`evaluate` implementation. No actual household action was permitted or tried. No production policy changed. A future convenience expansion requires separate code review and exact entity IDs from authorized read-only inventory, not guesses.

## Executed policy proposal acceptance

[CI #37849095384](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37849095384) **39 passed** using actual pinned `Policy` and `evaluate`: exact synthetic read targets and service catalogue domains automatically allowed; security/read state, mixed targets, generic control/backup/admin and future tools require approval. An intentionally tempting `ha_call_service` whitelist accepts an extra nested `data` field in the evaluator, so that rule is NOT safe for automatic device changes. Neither actual HA backend nor real entity IDs were used. The proposal is not yet accepted by Phase 2F's strict runtime whitelist and must not be imported.
