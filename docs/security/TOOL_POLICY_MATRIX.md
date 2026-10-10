# Administrator capability, security and reliability evidence

Current candidate: Core2026.10.0/Python3.14.2, scoped `/api/hass_codex_admin/mcp`, existing official tunnel clientv0.0.10, one custom administrator and SQLite. **CANDIDATE INCOMPLETE.** See the committed [evidence receipt](NATIVE_ADMIN_EVIDENCE.json) and [implementation plan](IMPLEMENTATION_PLAN.md). Historical evidence follows unchanged.

| Outcome | Connected evidence in this assignment | Remaining limit |
|---|---|---|
| Investigate/repair automations and scripts | Actual native trace/fault/CRUD, approved multi-step repair, fresh readback, reverse rollback | Arbitrary dynamic/custom/YAML effect/dependency completeness; physical behavior |
| Create/modify/delete helpers | All eight storage families; exact definitions, rollback, local post-check ID collision remains uncertain; no automatic unrelated deletion | No supported atomic ID reservation or native conditional writes |
| Dashboard administration | Actual stored views/cards and metadata create/update/delete/restore | Native owner panel browser and card rendering acceptance blocked locally |
| Device operation | Real HA synthetic light/switch/cover/media service/state interfaces, explicit elevated consent | Synthetic hardware does not prove household physical effects |
| Integration/config/backup | Calculated integration reload, config validation, native local backup and actual Core restore/restart | Credential/reauth/reconfigure/Supervisor/add-on/OS adapters absent; HAOS acceptance absent |
| One task approval | Up to20 exact operations; owner WS decision, effects consent, every-send scope check; useful repair after invalid/replayed requests | ChatGPT confirmation is additional; hosted/mobile total prompt count untested |
| Alternate route isolation | Old native admin and read-only token nonentity bypass reproduced; new capability rejected by REST/WS/base/alternate MCP/Assist/SSE; local owner still works | Actual production reachability, hosted tunnel/workspace custody and ingress not inspected |
| Caller/session control | Capability expiry/revoke/wrong caller/modified plan; actual native OAuth discovery/PKCE/code exchange/refresh/revoke; debug secret suppression | Connection identity is not a human; actual hosted account/browser consent still separate |
| Recovery | Owned child crash/exhaustion/concurrent start/cancellation, disconnect/provider/backend outage, actual subsequent MCP; known-good update rollback; late stop/close cannot revive | Official OpenAI control plane substituted by a local transport fixture; outage telemetry aging/long soak and host reboot not accepted |
| Crash/restore durability | Twelve owned Core processes at four abrupt-death boundaries; four-process native backup/restore; helper buffered-save loss detected; no blind retry | Disk-full/power loss/host reboot/HAOS restore untested; out-of-band old auth/DB copy cannot preserve revocation without independent recovery |
| Routine operation/updates | Native owner session validation replaces routine reenrollment; stable local connection ID renews volatile bearer after ordinary restart; default automatic updates unchanged | Owner login renewal/connection expiry and after-restore new connection remain genuine setup steps; only one Core release exercised |

Final dispatch binds a verified scoped connection and exact approved plan, not caller headers or OAuth client metadata. The native backend credential remains confined to this process's fixed loopback adapter. Definitions are untrusted data; no service/URL/shell proxy exists. Native owners remain trusted and independent local management is available. The application boundary is not kernel confinement against a compromised HA process.

Snapshot checks narrow conflicts but do not supply CAS. Unknown YAML/custom/dynamic references remain uncertainty. SQLite intent durability is distinct from HA configuration persistence. Supported restore retires delegations via the native backup manager event; arbitrary copying of old state is not accepted as safe remote restore.

Evidence labels: actual application development = real Core HTTP/WS/MCP/auth/entities/SQLite/backup; substituted boundary = local transport/control telemetry, spawn/reap faults, lost acknowledgment or delayed persistence; synthetic physical entity = real HA service with in-memory hardware; unexecuted = official control plane, hosted ChatGPT/iPhone, actual browser here, household/HAOS/Supervisor/kernel privileged acceptance. No synthetic evidence is promoted to trusted runtime PASS.

## Historical upstream policy evidence — preserved

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


## Phase 2C real-middleware evidence and bypass coverage

The pinned HA-MCP source, not a custom evaluator, ran in 38 passing staged tests ([run](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37838397155)). These are synthetic administrative functions; no user devices were touched.

| Protected operation | Direct entry point | Alternative routes | Source enforcement | Staging evidence / bypass |
|---|---|---|---|---|
| Lock/device security | `synthetic_lock_direct` / real `ha_call_service` | generic `ha_call_service`, `ha_bulk_control`, raw WS | Policy matches **name+args**, not underlying action | **VERIFIED STAGING:** direct-only rule gates direct call, equivalent generic synthetic call passes |
| Light/blind/media controls | service domain/entity | bulk selectors, device controls, generic calls | evaluate each route and selector targets | **VERIFIED SOURCE** rules include selector special cases; production rule coverage **UNVERIFIED** |
| Automations/scripts/YAML | dedicated editing tools | filesystem, script/config tools, generic WS | individual names/args | **UNVERIFIED** live; requires multi-route allow/approval in staging |
| HA restart/host management | dedicated admin tool | generic service, add-on manager, WS, config action | per registered tool | **UNVERIFIED** effective rules; no production calls |
| Backup/delete/restore | `ha_manage_backup` | add-on, filesystem, config | scope/action-level rule necessary | **UNVERIFIED** effective rules |
| Policy administration | settings UI policy routes | potential management tool | separate HTTP ingress and Supervisor proxy | Read-only `GET /api/policy/config` returned 403; no bypass attempted |
| Discoverability and proxy dispatch | search/proxy meta-tools | nested call to actual tool | some `PROXY_META_TOOLS` bypass outer gate | **VERIFIED SOURCE**, nested route validation NOT VERIFIED |
| Guard import/registration | `_apply_tool_security_policies` | all tools when guard absent | startup wrapper catches exceptions | **VERIFIED STAGING: FAIL OPEN** |
| Corrupt policy at call time | all calls routed by installed middleware | none under that middleware | `ValueError` causes `ToolError` | **VERIFIED STAGING: FAIL CLOSED** |

**Important:** This policy model implements allow/approval-required, not irrevocable hard-deny/RBAC. In default `require_approval` mode, unmatched calls run. In `allow` mode, unmatched calls require approval (not permanent deny). Only a stronger hard-deny/visibility guard or independent privilege boundary can enforce “never execute Class 3.” See `POLICY_FAIL_CLOSED_REVIEW.md`.

Neither the stage's synthetic bypass nor its middleware initialization test proves which rules are in force on the user's production add-on; effective rules remain blocked behind HTTP 403. Mandatory policy initialization must fail closed in a separate **upstream** remediation and be staged with independent recovery before deployment.


## Phase 2D proposed strict baseline (not configured)

See `phase2d/POLICY_BASELINE.md` for per-operation classes and alternative routes. The candidate strict startup mode is only available in a reviewed upstream source patch, not live 8.6.0. It enforces **nonempty allow-list + middleware initialization** and per-request strict policy revalidation. Existing engine only supports allow vs approval-required; hard-deny of privileged writes needs a server-side canonical action guard, removed tool registration, or separate least-privileged backend.
