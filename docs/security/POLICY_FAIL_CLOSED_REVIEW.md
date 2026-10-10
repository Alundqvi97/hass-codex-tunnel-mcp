# Fail-closed tool-security review — HA-MCP v8.6.0

**Component:** upstream `homeassistant-ai/ha-mcp`, commit `fc54437a804858732e4bc927add98e202d879a09`. **No patch deployed or submitted upstream.** Changes in this document are a separate review proposal, not tunnel PR code.

## Reproduced failure mode — HIGH

[`HomeAssistantSmartMCPServer._apply_tool_security_policies`](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/server.py#L1269-L1467) catches `ImportError` and middleware-registration exceptions, emits a critical-sounding error message, but then **returns normally**, allowing subsequent initialization to continue without `PolicyMiddleware`. Tested against the real pinned method via synthetic import-failure and registration-failure injection: log appears but caller did not fail; no middleware attaches.

[`PolicyMiddleware.on_call_tool`](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/policy/middleware.py#L77-L169) reloads the policy and **fails closed on ValueError** from invalid/corrupt policy file. Pinned `Policy` defaults to `rule_effect=require_approval`, with empty list permitting all unmatched calls. Tests confirm both behaviors. This latter outcome is **policy default**, not failure to register the middleware.

## Minimal upstream remediation for review (NOT committed as HA server code)

If `ENABLE_TOOL_SECURITY_POLICIES=true` is a **mandatory security boundary**, the smallest defensible change is to raise a sanitized startup error on an import/registration exception instead of returning to a fully accessible server. For example, at both existing catch branches in `server.py::_apply_tool_security_policies`:

```python
logger.exception("Required policy security middleware unavailable; refusing startup")
raise RuntimeError(
    "Required tool security policy middleware failed to initialize"
) from None
```

Do not print policy contents, tokens or file locations in the public error. Install the middleware and validate it before any externally reachable MCP transport begins accepting requests. Treat invalid on-disk configuration **and missing policy configuration when mandatory gating is expected** as separate failures; consider a new explicit `require_policy_file` or `require_sensitive_gates` option rather than retroactively changing default on systems with no rules.

**Availability trade-off:** startup abort preserves security but disrupts remote ChatGPT administration. HA and Supervisor must still be independently accessible over local UI/console. Under a mandatory policy regime, failing closed is preferable to exposing administrative tools without enforcement. Staged break/recovery, Health/Repair warnings and rollback must be verified before any upgrade.

## Alternative: always-on deny-all guard

A minimal, dependency-light **deny-all** middleware placed earlier than the optional policy module can keep the server up for health endpoints, but requires proving middleware ordering, unknown-tool and proxy tool handling, administrative routes outside MCP, and tests that a missing policy does not cause hidden privilege bypasses. Because adding another middleware enlarges the trust surface, fail-fast startup is the preferred first review candidate, subject to independent local recovery.

## Default rule semantics and routes

| Scenario | Pinned result | Target |
|---|---|---|
| No policy file / empty rules, require_approval default | All unmatched tool calls execute | With strict option enabled, fail or hold all sensitive operations |
| Explicit direct-tool rule only | Equivalent generic tool may execute | Gate all equivalent names and argument forms |
| `allow` rule mode unmatched | Approval required, not irreversible deny | Separate hard-deny capability or remove tool at registry |
| Bad policy file at request time | Middleware denies underlying call | Preserve this fail-closed behavior |
| Middleware import failure | Logs error, continues without gate | Abort startup or deny privileged calls |
| Middleware registration failure | Logs error, continues without gate | Abort startup or deny privileged calls |
| Raw `ws_command`, selector, discovery proxy | Some special-case safeguards exist | Real nested-dispatch and parameter coverage tests still required |
| Policy editing UI | Separate HTTP ingress surface | Independent auth/access controls required |

## Proposed upstream test cases

Unit: synthetic import and registration failures require startup exception, check no leaked secret; corrupt/missing file, allow/approval policy behavior, unknown tools, policy changes. Staging: actual packaged startup failure with fake Supervisor data, service denied ingress, local recovery and reversible deployment. Do not publish a security patch upstream without separate approval.

**Decision:** Keep HA-MCP server remedy in the correct upstream project/review workflow, **not** in `hass-codex-tunnel-mcp`. A new fork/repo or upstream PR requires separate authorization.


## Phase 2D implementation candidate

Review-only `phase2d/patch_candidates.py policy --apply` modifies **only** pinned HA-MCP `src/ha_mcp/server.py`.

- When policy enforcement is enabled, both middleware import and registration failures now **raise sanitized errors** instead of returning normally. The normal `_initialize_server` call wraps all unexpected policy initialization failures with a sanitized top-level startup abort.
- Optional `HA_MCP_REQUIRE_STRICT_POLICY=true` requires enabled engine, existing `tool_policy.json`, nonempty rules and `rule_effect=allow`; missing/empty/invalid settings prevent startup. Per-request policy provider reevaluates file, so removal or invalid edits later cause errors instead of allowing new calls.
- Backward-compatible baseline semantics for healthy non-strict deployments are unchanged. Behavior during *failure* when security policies are enabled intentionally changes from availability-over-security to fail closed.
- This does not introduce hard-deny or identity scopes. The new strict environment switch has no existing add-on UI schema wiring, and must not be enabled on production without a separately tested configuration and recovery path.
- The strict/allow mode prevents unreviewed future tools being silently **allowed**, but unknown tools remain **approval-required**, not absolutely prohibited.
- Exact modified code is reproducibly generated from two known Git source blob hashes and reversed via Git. Synthetic fault-injection tests cover successful registration, imported dependency missing, registration failure, server initialization abort, incomplete/invalid strict files and live reload.
- **No upstream source committed to tunnel runtime, no upstream PR, no deployment.**
