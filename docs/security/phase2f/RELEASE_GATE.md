# Phase 2F release gate — Security architecture decision

**Disposition:** Phase 2F engineering **PARTIAL** (supported option and restrictive migration implemented/tested in isolated source and Docker, but nested-dispatch/approval lifecycle and complete recovery gates remain). Overall Phase 2 **PARTIAL/BLOCKED**; Phase 3 **NO-GO**; Phase 4 deployment **NOT AUTHORIZED**.

## Security boundaries

1. **Existing HA-MCP:** Standard-mode secret URL is the effective inbound credential. Additional tunnel-side bearer header is not validated independently. Hosted OpenAI workspace/Tunnels Read+Use controls are documented, but unauthorized attachment has not been independently tested.
2. **Live current policy:** Administrator screenshot shows Require approval; 18 unconditional matching approval rules, 0-minute retention. Unmatched tools can run automatically if policy middleware is installed. Actual runtime middleware status unknown; the authorized root endpoint previously returned 403.
3. **Safe future strict policy:** The new separate positive allow-list auto-permits only `ha_get_overview`. It does **not** convert any of the 18 destructive rules into allow rules. Broad generic, raw WS, bulk and security-sensitive writes require approval under evaluator semantics. **Approval ≠ HARD DENY.**
4. **Supported opt-in engineering:** `homeassistant-addon/config.yaml` candidate adds `require_strict_tool_policy: bool?` default false. `start.py` independently validates options and durable `/data/strict_policy_required.v1.json` marker, rejects corruption/downgrade and exports strict setting. Patched server provider validates a conservative auto-allowed tool set at startup **and for each policy-checked call**.
5. **Operational boundary:** Marker is protected inside trusted add-on storage; an administrator who deletes both marker and options can bypass its history. It is not hardware-backed anti-rollback. Safe recovery requires separate local/Supervisor administration, not the same remote ChatGPT tunnel. Do not enable this on the installed add-on merely by writing an env var.

## Release-blocking acceptance gates

| Gate | Status |
|---|---|
| Pinned-source tests 26 + 42 + 20; packaged nine scenarios; log checks; exact rollback | **PASS — isolated** |
| Production effective policy mode | **VERIFIED UI: require_approval** |
| Production actual middleware registered, tool catalog and alternate admin routes | **UNKNOWN / BLOCKED** |
| Nested tool-proxy dispatch and approval expiry/replay/denial | **NOT VERIFIED for Phase 2F** |
| Hard-deny for locks, alarms, camera privacy, backup restore/delete and credentials | **NOT AVAILABLE in existing policy model** |
| Stable add-on settings interface option roundtrip in actual Supervisor | **NOT VERIFIED** |
| Real HAOS restart, update, rollback and independent local recovery | **NOT VERIFIED** |
| Protected current-installation backup and tested restore | **NOT VERIFIED** |
| Hosted OpenAI unauthorized attachment/cross-workspace denial | **NOT VERIFIED — separate approval and cost review** |
| TCP 9583 same-LAN and IPv6 isolation | **NOT VERIFIED** |

## Architecture and user action

**Recommendation:** Finish the exact live installed policy inventory and approval handling through authorized HA-MCP administrator interface, then separately stage an HAOS/Supervisor instance and test supported option persistence/rollback. No production policy flip, merge, upgrade, add-on restart, router change or credential rotation is authorized.

If one thing is needed from the operator now: evidence that Tool Security Policies shows the current mode and 18 rules is already provided. **No additional manual action is unavoidable for preserving the current system**. Future HAOS staging or production promotion requires explicit approval and confirmed independent local recovery.

## PR boundaries

- [Draft PR #1](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/pull/1): tunnel hardening remains separate, unmerged.
- [Draft PR #2](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/pull/2): review-only HA-MCP pinned source patch generators, tests and tracking; base is PR #1's branch, not main. New HA-MCP source modifications belong upstream in `homeassistant-ai/ha-mcp` **only after separate authorization**. No new forks, upstream PR or public vulnerability disclosure.

**Never deploy from this repository's patch builder directly.** It is an offline candidate that first needs code review, upstream integration, full Supervisor support and an approved production manifest.


## Phase 2G release-gate addendum (2026-10-08)

**NO-GO.** Read-only VM feasibility [#37847835408](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37847835408): KVM present but inaccessible; QEMU/UEFI absent; no VM installed. Genuine HAOS/Supervisor acceptance needs separate permission for ephemeral runner modifications/VM creation; normal Docker image tests do not qualify.

**New in-process finding and fix candidate:** Real `PolicyMiddleware` let a waiting and later-approved fake admin action reach dispatch after the policy file became corrupt. Original reproduction failed intentionally [#37848286990](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848286990). Separate review-only middleware revalidation patch passed [#37848485823](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848485823): 196 original pinned tests, 13 new scenarios, 194 applicable upstream tests with 2 intentionally changed-semantics tests excluded, exact patch rollback. Upstream requires new matching assertions for changed approval-on-policy-update semantics. No production changes.

The separate convenience proposal keeps generic service/bulk writes gated. Explicit whitelist policy rules for `ha_call_service` cannot constrain all nested `data` keys via ordinary predicates; require typed operation-aware execution control for real automatic lights/media/blinds. See `phase2g/CONVENIENCE_POLICY.md`.

Backups: `homeassistant_version` comes from backed-up Core metadata. Core+DB recovery point exists in inventory but add-on `/data`, HACS tunnel integration and local restoreability unverified. Update pin and manifest details in `phase2g/RECOVERY_BACKUPS.md` and `RELEASE_MANIFEST.md`. Phase 3 remains **NO-GO**.
