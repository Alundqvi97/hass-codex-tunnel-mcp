# Backend authorization verification — Phase 2B (2026-10-08)

## Pinned implementation — VERIFIED SOURCE

Upstream `homeassistant-ai/ha-mcp` release tag `v8.6.0` is annotated Git tag `64a01e065bf8736c5745afb617e4315297b3ca6c`, resolving to commit `fc54437a804858732e4bc927add98e202d879a09`. It matches the deployed version label 8.6.0, but image digest/content provenance of the **running** add-on was not independently attested.

**Conclusion:** The standard-mode HA-MCP add-on authenticates access by unguessable MCP URL path, **not** by independently validating the extra Authorization bearer passed by the tunnel integration. The add-on `SUPERVISOR_TOKEN` is an **outbound** credential for HA/Supervisor API access, not an HTTP inbound MCP bearer-validator. Thus the additional tunnel backend bearer is **not a second security boundary** in this installed mode. A holder of the secret path able to reach the service may invoke allowed administrative tools. Severity: HIGH risk conditional on URL disclosure and network reachability.

Evidence:
- [pinned `homeassistant-addon/start.py`](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/homeassistant-addon/start.py#L767-L798) resolves and persists the secret path; [lines 905–1002](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/homeassistant-addon/start.py#L905-L1002) assign outbound supervisor bearer, mount server at `secret_path` and bind `MCP_HOST`, normally `0.0.0.0`.
- [pinned `__main__.py`](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/__main__.py#L960-L1009) sets HTTP bind/path. [`http_transport.py`](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/http_transport.py#L84-L118) delegates HTTP path routing to FastMCP; no bearer-token validator is installed by add-on startup. Routing path is not a per-user authorization decision.
- [`SECURITY.md`](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/SECURITY.md) documents single-tenant secret URL standard-mode trust model.
- [fork `tunnel.py`](../../custom_components/hass_codex_tunnel_mcp/tunnel.py) passes `Authorization: env:HA_MCP_AUTH_HEADER` in extra/discovery headers but does not enforce recipient validation.

### What has *not* been verified

Actual pinned v8.6.0 process serving synthetic `initialize`, `tools/list`, `tools/call` without bearer remains **NOT STAGING VERIFIED**; it should be tested with an ephemeral real HA-MCP server, no real HA URL or token, and synthetic read-only tool. Previous `test_phase2_protocol_contract.py` only tests a **mock** that *does* validate bearer: it demonstrates that a successful GET is not proof of POST authorization but is not evidence about production HA-MCP.

### Recommended actual staging tests (separately isolated)

Construct pinned HA-MCP FastMCP `HttpTransportFastMCP` with synthetic `/private_example_only` route and one read-only echo tool. Use Starlette `TestClient`/httpx ASGITransport with *no external socket*; test correct path with missing/bad/good bearer, and incorrect path with correct bearer for `initialize`, `tools/list`, `tools/call`. Verify that all three bearers yield equivalent results at the correct path, wrong path returns 404, and no HA admin tools are registered. That test verifies FastMCP standard-mode transport in pinned code, not the full Supervisor-installed runtime.

**Risk remediation:** Never count additional backend bearer as enforcement until actual recipient middleware validates it. Preserve secret-path secrecy, tighten inbound port 9583 after verifying local tunnel route and recovery, and implement distinct real token enforcement only if a supported architecture requires it.


## Phase 2C STAGING VERIFIED — Supersedes earlier source-only status

Real pinned upstream `HttpTransportFastMCP` and its bundled FastMCP JSON-RPC transport were executed in CI; full evidence and scope are in `ACTUAL_HA_MCP_STAGING.md`. On the correct synthetic endpoint all `initialize`, `tools/list` and harmless `tools/call` requests returned successful MCP results **regardless of whether incoming bearer header was absent, incorrect, arbitrary, malformed, or expired-like**. Requests on an incorrect path did not execute the tool. The term “expired-like” is only an inert string, not a verified expiry/revocation test because standard mode has no bearer validation provider configured.

**Result:** secret-path capability governs access; the tunnel-side extra bearer has no independent enforcement at backend. The running Docker image digest is still unverified, and the tests do not exercise production admin tools, HA Supervisor or OpenAI hosted attachment.
