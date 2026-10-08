# Phase 2E — Supported strict-policy option and migration safety (proposal, NOT DEPLOYED)

Upstream exact source: `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09`.
The current Phase 2D source candidate recognizes `HA_MCP_REQUIRE_STRICT_POLICY` as a process environment variable. The production HA-MCP add-on does not expose it in its Supervisor options schema. Setting it manually inside the container is not supported/persistent.

## Minimum supported upstream implementation, separate from logging patch

1. Add stable add-on `options.require_strict_tool_policy: false` and `schema.require_strict_tool_policy: bool?` in `homeassistant-addon/config.yaml`, mirroring the development add-on if appropriate. This is opt-in; do not silently enable for existing users.
2. In `homeassistant-addon/start.py`, parse only an actual boolean option, **reject an unknown type or a corrupt options.json when a previously required setting was enabled**, and export `HA_MCP_REQUIRE_STRICT_POLICY=true|false` to the server before importing/constructing `ha_mcp`. Do not honor an untrusted or arbitrary string as truthy. A wrapper around options updates should verify strict-mode changes before saving.
3. Maintain an authoritative persisted mandatory-policy marker outside the mutable per-start options fallback. Otherwise, deleting/invalidating `options.json` can silently fall back to `enable_tool_security_policies=false` and `require_strict_tool_policy=false`, removing both guards. Marker writes/migrations require local-admin approval; direct policy/tool calls must not disable them.
4. Preflight: validate a **new reviewed positive allow-list**, check strict mode opt-in, verify policy middleware loads and all risky routes are either approval-required or independently hard-denied, then start serving. Store only sanitized error codes.
5. Never switch the 18 existing bare approval rules to `rule_effect="allow"` unchanged. The same names would become automatically allowed destructive tools. Use a new reviewed policy snapshot, approve the migration through authenticated admin UI, and preserve exact prior semantics for rollback.
6. Under opt-in strict `allow` mode, an unmatched action requires approval; that is **not** hard denial. Reject unconditional `* + no conditions` in the strict candidate; external action hard-deny/least-privileged HA identity must be reviewed separately.
7. On restart/upgrades, validate that the stable schema accepts the flag; the add-on startup exports it; the effective policy and mandatory marker agree; the authorized local admin recovery path remains available. If the option or marker disappears, fail closed with a repair status rather than fallback to unrestricted tools.
8. Reversible change: approved restore of previous add-on image/options/policy via independent HA/Supervisor UI, preserving a secure-disabled remote MCP state until deliberate security risk acceptance.

## Test matrix (not yet verified in Supervisor)

- Valid strict option persisted across reboot; invalid/missing strict option with marker remains fail closed.
- Old schema roundtrip and upgrade to new option; unknown flag rejected; no default change on legacy installations.
- Atomic config update/crash between writes; concurrent policy reload; policy content substituted after validation.
- Approved read-only allow-list, new tool introduction, dedicated destructive tool and generic-call alias.
- HAOS host reboot; add-on supervisor rollback; no secret logs and no unauthenticated reveal.
- Full packaged add-on with fake Supervisor (distinct from genuine Supervisor boot).

**Current state:** Design only. Patch candidate's environment flag works in isolated staging, but deployable supported option and durable mandatory marker are **BLOCKED**, not implemented.


## Phase 2F actual supported-option candidate (not installed)

Implemented as a reproducible, exact-source-checked review candidate: `docs/security/phase2f/strict_addon_candidate.py`. It adds a stable `require_strict_tool_policy: bool?` option with `false` default to pinned add-on `config.yaml`; `start.py` checks types/config via standard-library-only preflight (avoids early runtime imports), creates a durable root-only `strict_policy_required.v1.json` marker in existing `/data`, blocks missing/corrupt options or downgrade when marker is present, and exports the opt-in runtime flag. The patched `server.py` revalidates the positive allow-list at startup and per middleware policy check.

**Design limit:** No unconditional hard-deny or per-user isolation is added. Initial strict list permits only `ha_get_overview` automatically; all writes/control remain approval-required. An administrator able to remove both marker and option can clear evidence of prior opt-in, so this is fail-closed configuration persistence for intact trusted storage, not tamper-proof anti-rollback. A supported offline-admin marker recovery/disable procedure needs real Supervisor/HAOS validation.

Tested with real pinned source and isolated Docker entrypoint using synthetic data: [CI #37846398572](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37846398572), 42 new migration tests, 9 packaged cases, source rollback passed. **No production add-on option was changed.**
