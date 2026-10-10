# Current release-candidate threat boundary

Keep scoped connection → native MCP/custom LLM → independent native owner task approval → fixed trusted loopback backend → durable acknowledgment/readback/recovery. An attacker holding the connector credential can inspect/propose but cannot approve, call general native APIs or widen the exact accepted task. Owner identities derive from current native sessions, not supplied headers, client_id or platform tunnel delegation.

New durable deny intents prevent SQL revocation failure and cancelled late issuance from reviving a connection on ordinary restart. Pending issuance is retired at boot; task RAM deny blocks dispatch even if its SQL revocation fails. Failures of every durable medium still require independent local recovery. Supported native backup restoration retires authority; unsupported copying of old auth/SQLite files is not treated as preserving later revocation.

HA-assigned creations bind returned canonical ID/definition to the original task/index and fresh prior inventory; same-task references cannot substitute arbitrary targets. Backend acknowledgment is persisted before readback; absent attribution cannot be recovered from merely identical configuration. Rollback never adopts or deletes an unexpected object's name match.

Unconditional HA editing APIs are a platform constraint: real independent final-check-gap editing can still be overwritten. The proposed optional short named-object owner window is explicit, disabled by default and awaits owner acceptance; it is human cooperation, not atomicity. Loaded configuration/group/dashboard dependency coverage remains bounded; unknown dynamic/custom references are disclosed for destructive consent.

Finite native flow/Supervisor adapters do not open arbitrary service/URL/shell routes. Native owner input stays outside MCP and diagnostics. Flow lock order is engine→flow; final authorization occurs inside the acquired flow lock; cleanup after grant retirement still requires fresh owner session. Terminal flow success requires observed reload, not already-loaded state. Reauth obtains its initialized form through the same bounded public API as native GET. Core restart uses a new kernel-derived process incarnation and persisted acknowledgment; host reboot requires native boot facts for the same host. Shutdown/disconnect and unobserved external flow outcomes stay uncertain. Actual Supervisor and hosted control plane remain external acceptance boundaries.

The retained official client uses verifiedv0.0.16 binaries and filtered settings; no extra inherited transport channel is activated. Local synthetic control-plane protocol tests are not official hosted identity/access evidence. Organization/workspace tunnel-use delegation is not a human identity, and NoOAuth does not replace local capabilities or owner decisions.

Production-only ZIP checksums establish candidate integrity, not vendor signature or independent certification. SQLitev2 intentionally refuses vulnerable old software downgrade; local HA remains independent and tested reinstall recovery restores the candidate. Two source reviewers found/corrected retained-path defects; the failed quota-blocked scanner is not a clean review. No privileged, production, Probe A or VM operation occurred.

## Previous native model and historical analysis — preserved

# Current native administrator threat model

The active boundary is verified scoped connection → custom credential adapter to native MCP/LLM → exact native owner task decision → fixed own-loopback backend → readback/consumed intent/recovery. Only explicit configuration enables it. Official OpenAI transport is retained; the community manager and custom administrator are not vendor-certified. Retired Probe A has no runtime dependency or fallback.

| Principal/asset | Authority and credential custody | Negative proof / remaining boundary |
|---|---|---|
| Remote connection/attacker reusing connector credential | Opaque hash-backed connection capability; MCP inspect/propose/status plus only exact owner-approved execute/rollback | Same credential fails native REST/WS/base MCP/Assist/SSE and native JWT fails scoped route; production external/internal reachability not inspected |
| Official tunnel workspace/client | Official runtime key stays in existing local transport environment; scoped backend header injected locally, stable ID lookup in trusted HA process | Workspace access is not human approval; no new OAuth provider; hosted NoOAuth/routing/account/iPhone not accepted |
| Independent native human owner | Active owner native session from configured frontend-client allowlist; explicit exact hash/effects consent; normal HA local APIs retained | Client_id/header/URL alone is not proof; actual local OAuth HTTP tested, owner panel browser blocked |
| Custom administrator/backend | Native owner JWT minted only at own-loopback backend request; fixed typed APIs, no arbitrary service/URL/WS/shell proxy | Broad native JWT never supplied to connector; trusted HA/component compromise remains outside this application isolation |
| SQLite and restart/restore | Intent before dispatch; consumed uncertainty, scope/replay/expiry checks; boot grants retired; bearer bytes rotate; supported restore retires stable connections via retained native event | DB receipts can outlive HA saves; out-of-band old auth/DB copy is an unsupported authority-revival risk without independent non-restored recovery |
| Tunnel lifecycle/update | One process owner/lease, bounded backoff, permanent auth/config denial, Core-stop/unload cleanup, bounded TERM/KILL, generation checks | No process tree/kernel confinement claim; local transport fixture is not official control-plane evidence; uncertain reap retains lease and blocks replacement |
| Local edits/dependencies | Post-intent final snapshot/dependency checks; reference guard and ID mismatch uncertain; no unrelated automatic deletion | No native CAS/ID reservation; arbitrary dynamic/YAML dependencies and all-writer coordination unresolved |
| Logs/untrusted definitions | Strict bounded JSON/IPC, duplicate keys rejected, backend redirect/proxy denial, native WS debug auth/issue suppression, omitted child payloads, textContent panel | Redaction is not global HA secret classification; reviewed owner effects required for scripts/automations; sandboxed browser unavailable |
| Versions/persistence/artifacts | Exact Core source and unchanged hash lock; checked-in fresh setup; source/protected bytes checksummed | Private MCP helper seam version-sensitive; future patches need staging; no actual power-loss/production/HAOS restore acceptance |

No root helper, privileged probe, cgroup/firewall mutation, VM, production or household operation occurred. Source review is not independent certification. Missing hosted/physical/kernel evidence remains missing; this candidate does not claim full administration is complete.

## Historical threat model — preserved

# Tunnel security threat model

## Assets and trust boundaries

`ChatGPT user/session -> OpenAI hosted attachment -> authenticated tunnel client -> HA-MCP backend -> Home Assistant administrative tools`. A second ingress path may expose TCP 9583 to trusted LAN. OpenAI runtime API key and backend HA bearer are separate credentials; the static backend bearer does **not** authenticate individual ChatGPT users. This repository is separate from the proposed Home Infra Control Plane/Auth0 identity broker.

## Threats and mitigations

| Threat | Evidence / mitigation | Residual risk |
|---|---|---|
| Header forwarding through backend probe redirects | `_NoRedirects` denies 3xx; loopback regression covers same- and cross-port redirects | Actual tunnel-client request redirect policy not established |
| False-positive backend authentication health | GET 401/403 with configured bearer now rejected | 200/400/405/406 may still be unauthenticated or inconclusive |
| Cleartext external MCP backend | Reject public HTTP based on DNS classification | DNS rebinding, egress/proxy behavior and public HTTPS validation require staging |
| Unauthorized OpenAI hosted tunnel attachment | No proven ingress user identity/RBAC yet | High priority validation gate, cannot be solved in `mcp_url.py` |
| Direct backend LAN access | Known TCP 9583 exposure from trusted LAN | VLAN-specific and WAN tests + safe rollback before restrictions |
| Excessive HA administrative authority | Existing security policies enabled, read-only mode disabled | Review tool list, execution approvals, HA service account permissions |
| Logs / process leakage | Integration uses environment-backed secrets for tunnel-client | Child-process logs, exception chains, query strings and crash diagnostics need review |
| Update/restart outages | Updater has its own binary fallback | HA integration source rollback and cold-start/reboot recovery remain to be exercised |

No observed exploit is claimed. All tests use fake credentials and loopback-only HTTP. No production endpoints or keys may enter this repository.

## Future Auth0 relationship

Evaluate an authorization gateway only after separate staging proves signed token validation, expiry/revocation, audience, scopes, per-user identity and proper fail-closed behavior. Do not simply reuse the Control Plane's root-level authorizations for Home Assistant. Use independently scoped HA-specific permissions, independently recoverable deployment paths, and separate acceptance/rollback plans.


## Phase 2 refined trust assumptions

- OpenAI documents organization/workspace associations and Tunnels Read+Use to create/select/use a tunnel. **This is documented intent, not a test that a separate user/account is denied**. Production is kept unchanged.
- The `No Auth` ChatGPT app setting concerns app-to-backend authentication, not proof of an anonymously accessible OpenAI-hosted attachment.
- HA-MCP in standard/secret-URL mode is single-tenant. Treat the complete secret path as an access credential, potentially permitting the same admin-backed functions to every holder. The separate forwarded bearer is **not confirmed to be enforced** by that mode.
- `enable_tool_security_policies=true` says the policy mechanism is available; it does not establish actual rules or complete coverage for aliases, WebSocket commands, filesystem, configuration or backups.
- Risks remain for DNS rebinding/TOCTOU, explicit proxy interception, HTTP-to-HTTPS downgrade, IPv6 differing from IPv4, child stdout/stderr, exception chains, inherited proxy environment, and malicious URL query strings.
- The HA-MCP add-on's Supervisor `manager` role and server's admin authority are broader than ordinary lighting control. Use separate capability classes and explicit independent approval for door locks, surveillance privacy, system administration, security-policy changes, backups/restores and raw service calls.
- A tunnel-client exit watcher does not self-heal a crashed subprocess at source level. A health-file sentinel is not end-to-end health. Preserve an out-of-band local recovery path.

**Mitigation priority:** 1) hosted negative auth proof, 2) real backend POST authorization and exact server-side policy rules, 3) host-port restriction with verified rollback, 4) crash recovery and logging hygiene. A production install is not justified by unit tests alone.

See `AUTHENTICATION_ARCHITECTURE.md` and `PHASE3_READINESS.md`.
