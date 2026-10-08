# Phase 2: authentication and authorization architecture

Assessment date: 2026-10-08. **Status: PARTIALLY VERIFIED — no hosted negative access test.** No production credentials, URLs or identifier values are included.

## Flow and trust boundaries

```text
[ChatGPT human identity + workspace] 
    │ [A: ChatGPT session, workspace and custom-app policy]
    ▼
[OpenAI hosted tunnel attachment/dispatch]
    │ [B: tunnel association + Tunnels Read/Use for eligible client contexts]
    │ [runtime key authenticates *separately* in the outbound direction]
    ▼
[tunnel-client v0.0.15 on Home Assistant host]
    │ [C: env-backed backend Authorization header + secret-path URL]
    ▼
[HA-MCP app, published TCP/9583 on trusted LAN]
    │ [D: secret URL path — standard-mode trusted principal]
    │ [E: HA-MCP tool policies / exposed tool catalog]
    ▼
[Supervisor / HA API with service-admin authority]
    │ [F: HA permissions, tool-level service calls]
    ▼
[Home Assistant devices, configuration, automations and backup]
```

The direct LAN route to TCP/9583 bypasses OpenAI boundary A/B/C and reaches boundary D. “No Auth” is an app-backend setting; it neither proves OpenAI accepts anonymous attachment nor supplies per-user downstream identity.

## Boundary inventory

| Boundary | Identity/credential | Authentication | Authorization and scope | Expiry/revocation | Evidence | Residual risk |
|---|---|---|---|---|---|---|
| A ChatGPT caller | ChatGPT account/workspace session | OpenAI-controlled | Workspace access to custom MCP apps | Session/user lifecycle, exact policy NOT independently tested | OpenAI tunnel guide; existing connector | Account-sharing, plugin-sharing and workspace controls uninspected |
| B Hosted attachment | OpenAI product principal + `tunnel_id` association | OpenAI hosted service | Tunnels Read+Use and org/workspace association documented | Changes to RBAC/associations; existing sessions behavior UNKNOWN | OpenAI official Secure MCP Tunnel guide | **HIGH-Priority BLOCKER:** cannot prove cross-account, replay, revoked, or missing authorization denial |
| C Runtime polling | OpenAI Platform runtime API key via environment `CONTROL_PLANE_API_KEY` | Key presented to OpenAI by `tunnel-client` | Tunnel Read/Use to establish/poll/reply; **not a per-user MCP access token** | Platform key lifecycle; active in-flight request effect UNKNOWN | Source `tunnel.py`; official guide | May be overbroad if key permissions exceed Read/Use; no production key inspected |
| D Backend ingress | Secret endpoint URL; additional configured backend bearer | Standard-mode high-entropy secret URL acts as credential; bearer passed as `Authorization` by tunnel-client | Identical access for any holder of secret URL; **no per-user identity** | Secret changes require coordinated client changes; runtime bearer validity/actual checking UNKNOWN | HA-MCP SECURITY.md + Add-on DOCS; HA config flags checked without exposing values | Is bearer *actually enforced* on every MCP request? Not established. Treat secret path as real credential. |
| E HA-MCP tools | Single MCP principal / configured tool policy | Server-enforced policy engine when enabled | Allow/hold/deny policies per tool and argument; alternative routes require coverage | Policy/version-dependent; approval lifetime not read | HA-MCP security-policy documentation; add-on `enable_tool_security_policies=true`, `enable_security_policy_tool=false`, `read_only_mode=false` | Exact rules and bypass coverage NOT reviewed; tool manager may still be overly broad |
| F HA admin access | HA-MCP Supervisor/app service token or admin-scoped authority | HA/Supervisor backend auth | Manager/admin equivalent operations depending on tool and server scopes | HA installation and backend service token lifecycle | HA-MCP add-on docs describe Supervisor manager role; live app options and available tools | Avoid treating natural-language confirmation as authoritative approval |

## Hosted attachment test matrix (not executed against production)

| Case | Expected outcome | Status |
|---|---|---|
| No ChatGPT authentication | Deny before MCP dispatch | NOT VERIFIED |
| Incorrect or unknown `tunnel_id` | Deny without leaking tunnel existence | NOT VERIFIED |
| Known `tunnel_id` in unassociated Platform org / workspace | Deny | NOT VERIFIED |
| Valid identifier but missing Tunnels Use | Deny | NOT VERIFIED |
| Invalid/expired/revoked Platform credential | Deny; examine already connected caller separately | NOT VERIFIED |
| Different ChatGPT account / enterprise identity | Only authorized workspace and principal may attach | NOT VERIFIED |
| Replayed auth and insufficient scope | Deny | NOT VERIFIED |

**Required approval:** disposable hosted tunnel or test identity, separate from production, with known zero-cost budget and explicit permission for creation and negative attachment tests. This cannot be derived from a working plugin connection or docs alone. No secret or tunnel id should enter CI.

## Current source evidence and official references

- OpenAI: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels — Tunnels Read/Use, association, outbound HTTPS and distinction from ChatGPT permissions.
- HA-MCP: https://github.com/homeassistant-ai/ha-mcp/blob/master/SECURITY.md — standard-mode single-tenant secret URL, trusted clients and admin token model.
- HA-MCP Add-on: https://github.com/homeassistant-ai/ha-mcp/blob/master/homeassistant-addon/DOCS.md — generated secret path, supervisor integration, TCP 9583.
- HA-MCP policy FAQ: https://github.com/homeassistant-ai/ha-mcp/blob/master/docs/FAQ.md — per-tool rules and alternative tool paths.
- Fork source: `custom_components/hass_codex_tunnel_mcp/tunnel.py` builds env-backed runtime key/header; `mcp_url.py` performs GET probe only.
- HA-MCP standalone OIDC is **not** an automatic solution to per-user Home Assistant scopes: https://github.com/homeassistant-ai/ha-mcp/blob/master/docs/oidc.md documents shared backend identity.

## Architecture recommendation (not deployed)

Use the current working path until safe testing is approved. Do not assume the backend Authorization header adds another layer of security unless the receiving mode proves enforcement with real MCP POST. If hosted authorization does not meet requirements, design a separate narrow HA authorization proxy — *not* simply sharing the Home Infra Control Plane root privileges. Phase 5 Auth0 is an option for ingress authentication, not a substitute for per-tool access control.


## Phase 2B correction to backend-auth boundary

Pinned v8.6.0 source establishes that the add-on's standard HTTP mode is **secret-path authenticated**: `start.py` mounts the FastMCP server at the secret path and supplies `SUPERVISOR_TOKEN` as **outbound** `HOMEASSISTANT_TOKEN`. The extra bearer sent by fork `tunnel.py` is **not recipient-side validated in this standard mode**. Therefore replace “bearer enforcement unknown” in the earlier Phase 2 snapshot with **“backend bearer non-enforcement established from pinned source, but exact deployed image not attested and runtime POST not tested”**. See `BACKEND_AUTH_VERIFICATION.md`. Hosted association and workspace permissions remain DOCUMENTED ONLY, not VERIFIED HOSTED.
