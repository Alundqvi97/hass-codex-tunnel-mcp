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
