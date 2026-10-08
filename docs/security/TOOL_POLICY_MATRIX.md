# HA-MCP v8.6.0 administrative tool-policy matrix

**VERIFIED SOURCE** against pinned `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09`; **production effective rules NOT VERIFIED**.

Relevant exact files: [server.py](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/server.py#L1269-L1467), [policy/middleware.py](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/policy/middleware.py#L77-L169), [policy/evaluator.py](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/policy/evaluator.py#L359-L436), [policy/persistence.py](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/policy/persistence.py), [policy/model.py](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/policy/model.py).

## Crucial implementation semantics

- `tool_policy.json` supplies persistent rules; `Policy.rule_effect` defaults to `require_approval` and **unmatched tools are allowed** in that mode. Merely enabling `enable_tool_security_policies` does not create useful rules.
- Alternative `allow` mode approves matches; unmatched calls are *approval-required*, **not automatically denied**. Distinguish approval requirements from irrevocable deny/RBAC.
- `PolicyMiddleware.on_call_tool` enforces decisions, but selected proxy meta-tools and approval-management calls bypass direct gating; follow their nested dispatch to ensure inner call is gated. Explicit raw WebSocket `ws_command` mitigation applies only with matching rule coverage.
- If middleware cannot import or register, `server.py` logs `TOOL SECURITY GATING IS NOT ACTIVE` and continues startup without gates. Policy-file parse errors fail closed if middleware *is* registered.
- Corrected alias names and dynamic selector safeguards have dedicated code but require branch-specific tests when writing rules.
- Tool-policy UI administration is a separate ingress surface; do not equate MCP tool disabling with access to the settings UI being denied.
- **Live read-only attempted:** `GET /api/policy/config` through Supervisor add-on ingress returned HTTP **403**. The effective policy and rule count remain **UNVERIFIED**; no values were exposed or changed.

## Proposed classes (do not deploy)

| Class | Intended treatment | Enforcement | Alternative route to review |
|---|---|---|---|
| 0 — Read-only inspection | Allow under least privilege, redact logs and secrets | HA-MCP per-tool catalog and server-side policy | Generic configuration/diagnostics tools may include data-write options |
| 1 — Ordinary household control | Allow selected light/blind/media operations | Evaluate service domain, entity IDs, and tool parameters server-side | `ha_bulk_control`, device tools, generic `ha_call_service`, raw WS commands |
| 2 — Administrative configuration | Explicit independent approval per exact operation | Stateful server policy queue, limited TTL, durable audit | YAML, helper/script/automation, HACS, integration management, backup helpers |
| 3 — Security/destructive | Deny by default, then brokered case-by-case explicit approval | Needs stronger server-side scope/RBAC or a separate privileged path; HA-MCP approval list does **not** implement unconditional irreversible deny | Door lock, camera privacy, restart, backup deletion/restoration, credentials, filesystem and network |

Before setting policy: obtain sanitized effective rule names, rule-effect mode, bypass tool names, and audit log events; demonstrate negative calls against disposable HA mock. Protect policy editing UI separately. **Do not** call security-sensitive tools in production for this audit.
