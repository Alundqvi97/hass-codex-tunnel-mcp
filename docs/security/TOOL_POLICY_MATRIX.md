# Administrator capability, security and reliability evidence

Current target: Core2026.10.0/Python3.14.2, native `/api/mcp/hass_codex_admin`; source details in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md). **CANDIDATE INCOMPLETE.** This table records development evidence, not HAOS, household or hosted acceptance. The historical HA-MCP matrix follows unchanged.

| Blueprint outcome | Connected development evidence | Remaining limit/gate |
|---|---|---|
| UX-01 automation investigation | Actual synthetic native automation fault, definitions, trace list and exact trace with division-by-zero diagnosis; minimized health/state/log reads require no change prompt | Whole-HA log privacy, unloaded/include dependency visibility; no real household trace read |
| UX-02 creation | Native automation/script and eight storage helper families, immutable plan → native owner WS approval → fixed API → fresh readback | Native helper ID allocation race; browser approval rendering untested |
| UX-03 bounded repair | Native automation repair/rollback; same script changed twice with one approval and reverse restoration; helper partial edit becomes full approved replacement and restores added fields | No native CAS against concurrent local editors; observed definitions do not prove physical effects |
| UX-04 exact deletion | Native helper/dashboard destructive decision, loaded definition/dashboard references, absence readback and exact captured restoration; renamed helper restores original ID | Unloaded YAML/other collections and uncaptured metadata incomplete; not full arbitrary-object deletion acceptance |
| UX-05 dashboards | Native views/cards stored and read back with title/icon/sidebar/admin flags; deletion and restoration; panel JS serves and parses | Actual browser/card rendering and frontend user journey untested |
| UX-06 integrations/maintenance | Actual calculated Sun integration reload and loaded readback, native Core config validation, fixed local backup job/archive metadata | Reconfigure/reauth/credential/Supervisor/add-on/restart/restore adapters explicitly blocked; backup is not restore proof |
| UX-07 one task approval | Up to20 exact ordered operations, one approval, repeated-target reverse order and applied-prefix rollback, including dependency checks for inverse deletion; fixed TTL30–900sec | Every indirect/config/device effect is conservatively elevated; no dynamic risk classification claimed |
| UX-08 wrong identity/injection | Actual native caller/session mismatch, token expiry/refresh/revocation, owner logout, hash/target alteration, literal-secret rejection, replay/expiry/revoke denial | Native auth-manager token refresh tested; actual hosted PKCE/consent/refresh flow, workspace/account isolation untested |
| UX-09 alternate routes | Finite six-tool catalog, wrong route and unknown/generic tool/selector/argument denial; per-send grant check after WS handshake and intermediate reads; unrelated supported calls remain usable | Admin bearer remains valid on broader HA APIs; ingress/identity isolation is a release blocker, not proved by catalog tests |
| UX-10 independent recovery | One durable intent, bounded SQLite held-lock denial/recovery, interrupted readback consumed/uncertain, read-only reconciliation, reverse restoration, late-thread completion rejected; two actual HA processes resume definitions/consumption | Graceful shutdown/start only; abrupt kill, host reboot, disk-full/power loss and production backup restore untested; boot revokes stored grants |
| UX-11 latency/compatibility | Fixed official release/hash lock, bounded tool55sec/backend8sec/lock1sec; repeated four schedules of three actual concurrent executions with one dispatch; final suite duration in receipt | No captured pre-upgrade household inventory, multi-day soak, cross-version upgrade, supported patch series matrix or maintenance-time promise |
| UX-12 useful closeout | Durable per-operation pending/dispatching/applied/uncertain/rolling_back/rolled_back states, exact snapshots and essential audit; replay freshly checks last object state; no blind uncertain retry | Reconciliation proves present definition, not mutation attribution; device feedback is HA state, not physical evidence |

Ordinary device controls retain exact light/switch/cover/media verbs. Actual synthetic native Switch and Light entities exercise state, brightness and temperature once without replay. Unsupported attribute selectors are rejected before approval. Disjoint devices work in one task; overlapping device entity scopes are rejected before mutation. Cover/media asynchronous behavior remains untested. Devices can affect household security, so explicit elevated approval applies.

## Final-dispatch boundary and provenance

Actual native HTTP request + LLM user + refresh-token identity must agree; NORMAL active admin tokens from explicit caller lists only. Owner WS approval uses an independent NORMAL active owner frontend session, explicit enrollment, exact immutable hash and effects confirmation. All mutations check it again at the send boundary. MCP cannot approve itself. Definitions/traces/logs are untrusted data, not new rights. Static bearer injection into the native endpoint is rejected in both tunnel command construction and probing, including encoded paths.

SQLite intent precedes the one write attempt. Before-state comparison, durable consumption, cancellation state, conditional terminal transitions, fresh readback and reconciliation compose recovery; they do not establish exactly-once kernel/device effects or native atomic CAS. Restoring DB/config at boot retires saved approvals. Trusted filesystem owners and HA owners remain trusted; this is not kernel confinement against a compromised admin process.

Evidence labels: **actual application development** = native Core/MCP/WS/storage/SQLite under synthetic identities; **substituted boundary** = injected lost acknowledgment/delayed thread or loopback malformed/redirect server; **synthetic physical entity** = real HA entity/service with in-memory hardware; **unexecuted** = hosted identity, HAOS/Supervisor, physical devices, live access/firewall. None is a trusted Probe A PASS.

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
