# Phase 2G — Actual middleware, approval and nested-dispatch assessment

Pinned genuine HA-MCP: `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09`. All tests use synthetic actions, no HA connection or exposed listeners.

## Results and discovered issue

[Failing reproduction CI #37848286990](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848286990) reported **11 passed / 1 failed**. The failing test deliberately corrupted `tool_policy.json` *after* a request entered the approval wait but *before* the approval was granted. The pinned real middleware continued to the fake final action; no revalidation occurred after the wait.

[Patched approval CI #37848485823](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848485823) **SUCCESS**:
- Original unmodified upstream policy suites: **196 passed**.
- Real FastMCP + new synthetic final dispatch scenarios: **15 passed** after patch.
- Remaining upstream middleware/queue/allow-list/handler/overlap tests: **194 passed; 2 intentionally deselected**.
- Exact `src/ha_mcp/policy/middleware.py` source Git blob `5b431906fe7a37bbc19e466ca92a34b491289298` restored using `git apply -R`.

The 2 old upstream cases intentionally expect calls already approved before/while a policy change to execute under previous policy semantics. This behavior conflicts with a new fail-closed guarantee, so they need **revised upstream assertions**, not silent exclusion before a merge. The unmodified baseline still passed all 196.

## New narrowly scoped patch

`docs/security/phase2g/middleware_revalidation.py` generates a separately reversible patch against only the pinned `middleware.py`. After a waiting request claims its specific approval and before calling its fake terminal action, it rereads the policy; unreadable/corrupt policy fails closed, and changed rule-effect/rule-list requires a **new** approval. Static calls that were already approved and are re-called go through the current provider at the start of the new invocation. The patch does not enable new tools or privilege a proxy.

**Limitation:** this is a guard immediately before `call_next`, not an atomic lock held through every Home Assistant REST/WebSocket operation or across a changing HA entity graph. Later topology changes, device membership and external side effects require action-level guards. It also does not change user identity or create unconditional hard-deny rules.

## Scope and evidence matrix

| Scenario | Evidence | Result |
|---|---|---|
| Unmatched synthetic admin action | New real FastMCP client/server | PASS |
| Direct `ha_call_service` and nested `ha_call_write_tool` | New genuine FastMCP transform | PASS, no dispatch before approval |
| Exact token approval, one-use consumption, replay | New + upstream | PASS |
| Denied approval | New + upstream | PASS |
| Changed arguments after approval | New + upstream | PASS: new approval needed |
| Raw WS service argument (synthetic) | New FastMCP middleware test | PASS: approval needed |
| Bulk selector (synthetic) | New plus upstream dynamic-specific tests | PASS: no stale token reuse after timeout |
| Concurrent identical calls | Genuine upstream `test_approval_overlap.py` | PASS: one click, one execution |
| Pending expiry, remembered TTL, policy TTL, token expiry | Genuine upstream queue/middleware tests | PASS in selected source suites |
| Corrupt policy while approval pending | Reproduced failing original, patched real middleware | PASS after patch |
| Rule list changes during pending approval | New patched regression | PASS: previously approved call refused |
| Tool search/write proxy outer bypass | Source architecture + genuine nested FastMCP test | PASS for tested write route; all nested routes not exhaustively tested |
| Delete proxy + arbitrary nested meta-tools and tool discovery | Additional dynamic-route coverage required | PARTIAL |
| Genuine hard deny at every final HA privileged operation | Not provided by `PolicyMiddleware` | NOT AVAILABLE |
| Production middleware actually loaded | Not observed | NOT VERIFIED |

## Intentional bypass boundaries

The pinned `PolicyMiddleware` exempts the outer `ha_call_read_tool`, `ha_call_write_tool`, `ha_call_delete_tool` and `ha_search_tools` envelopes so the nested call can re-enter the middleware under its final tool name. These are **not** themselves authoritative permission checks. The actual tested write-proxy route performs the nested enforcement. A non-write-capable read proxy and delete proxy remain release gate items.

Approval management through `ha_dev_manage_server` has a special middleware bypass to avoid queue deadlock, but the actual tool is **not registered by default**: it requires Developer Mode. Its `approve`/`deny` functions additionally require `dev_tools_security_policy_access` enabled, a separate default-off guard. Do not infer it is enabled in production; verify disabled-tool inventory through an authorized read-only route before release.

The normal Settings UI approve/deny POST endpoints have separate ingress/session access controls, not per-user authorization from the MCP policy middleware itself. Real live authorization and possible approval misuse by a compromised session remain NOT VERIFIED.

**Deployment: NO-GO; remediation not submitted upstream or deployed.**

## Expanded final tested routes

[Final code-equivalent receipt #37849095384](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37849095384): **196 original upstream**, **39 synthetic convenience evaluator**, **15 genuine FastMCP**, **194 patched upstream (two intentional exclusions)** and exact middleware source rollback all passed. Added genuine `ha_call_delete_tool` dispatch (approval required; one click one synthetic delete) and `ha_call_read_tool` refusal of a synthetic privileged write. No actual file was created/deleted. This closes tested read/write/delete proxy examples in-process, not all real installed service/backend variants.
