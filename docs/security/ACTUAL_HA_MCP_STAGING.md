# Phase 2C — Actual HA-MCP 8.6.0 staging test receipt

**Date:** 2026-10-08 · **Evidence:** VERIFIED STAGING (pinned transport + middleware), VERIFIED SOURCE (add-on startup); **not** production and **not** full Supervisor/add-on runtime.

## Provenance and execution

- Official annotated upstream `homeassistant-ai/ha-mcp` tag `v8.6.0` resolves to **fc54437a804858732e4bc927add98e202d879a09**. Exact SHA checked by Git in CI; `pyproject.toml` also asserts version 8.6.0.
- [First fully passing run 37838351730](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37838351730): staging **36 passed**; tunnel tests **57 passed, 1 skipped, 2 subtests**.
- [Expanded passing run 37838397155](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37838397155), commit `ef86dfdb6752c5a40cbee88d32e809e5d04093f3`: staging **38 passed, 0 failed, 0 skipped in 3.52s**; tunnel suite **57 passed, 1 skipped, 2 subtests passed in 4.61s**.
- One earlier staging run at `7c8fe23cd1d1f2dfd55c652e562b9786503bdfb8` **FAILED (33 passed, 1 failed)** because the test's synthetic import-failure monkeypatch did not intercept the relative import. Corrected test and reran green. This was a **test harness mistake**, not evidence that the server correctly failed closed.
- The unrelated original Home Assistant config-flow selector test still skips because full Home Assistant Python dependencies are not installed; it is not an auth-path test.
- [Workflow](../../.github/workflows/offline-security.yml): `pinned-ha-mcp-staging` checks out exact commit; Python 3.13; `uv==0.12.20`; `uv sync --locked --no-dev --python 3.13`; `uv pip install --python .venv/bin/python pytest==8.4.2`. Then `ha_mcp_pinned/.venv/bin/python -m pytest -q -rs -x tests/staging/test_real_ha_mcp_860.py`. Results link above.
- **No public network at application test time:** Starlette `TestClient` invokes ASGI in process, no bound listener; socket-connect guard rejects external IPv4/IPv6; non-routable `HOMEASSISTANT_URL` and synthetic `HOMEASSISTANT_TOKEN`; proxy env redirected to loopback reject port. Public package/source downloads only in the pre-test setup job.
- Temporary pytest directories are discarded with the GitHub runner; no real credentials, path, tokens or HA devices. This staging executes upstream FastMCP transport and policy code, not our mock fixture.

## Real transport tests and observations

App is constructed with **real** `ha_mcp.http_transport.HttpTransportFastMCP`, mounted at an isolated synthetic path with `stateless_http=True`, `json_response=True`, and one synthetic harmless `fixture_read_status` tool. Incoming `Authorization` has **no configured validator** in standard-mode transport.

| Correct path? | Synthetic bearer | HTTP / MCP result | Status |
|---|---|---|---|
| Yes | No header | `initialize`, `tools/list`, `tools/call` succeed | VERIFIED STAGING |
| Yes | Incorrect bearer | Same tool result | VERIFIED STAGING |
| Yes | “Correct” arbitrary value | Same tool result | VERIFIED STAGING |
| Yes | Malformed Basic / bare Bearer | Same tool result | VERIFIED STAGING |
| Yes | “Expired-like” value | Same tool result | VERIFIED STAGING — **no expiry semantics exist to test** |
| No | Missing or arbitrary bearer | Wrong-path requests do not execute tools | VERIFIED STAGING |
| Yes | Three repeated calls | Read-only function executes as expected | VERIFIED STAGING, stateless only |

**Precise conclusion:** The standard-mode server recognizes the **path as a bearer capability**. Bearer-header strings are ignored without an explicit `auth` provider. The arbitrary “expired-like” string never undergoes expiry validation; do not misreport it as evidence of revocation handling. A configured tunnel-side `Authorization` header is not an additional protection in this mode.

## Real policy tests and observations

Tests use the pinned `Policy`, `Rule`, `PolicyMiddleware`, `HomeAssistantSmartMCPServer._apply_tool_security_policies`, evaluator and disk persistence. Synthetic administrative tool behaviors are harmless functions. No actual Home Assistant devices or administrative operations involved.

- Empty or missing `tool_policy.json` → default require-approval rule mode with no rules → unlisted/administrative call permitted.
- Rule gating synthetic dedicated lock tool does not also gate generic `ha_call_service` or `ha_bulk_control`. A real `PolicyMiddleware.on_call_tool` dispatch confirmed the alternate synthetic call executes and the direct call requires approval.
- Explicit generic-tool coverage with matching predicates can gate that route; updates to persisted policy are reread by the middleware for later calls.
- Corrupt policy after middleware successfully registered → `ToolError`, underlying synthetic operation not dispatched (fail closed).
- Dependency import and `add_middleware` failure at initialization → helper logs `TOOL SECURITY GATING IS NOT ACTIVE` and returns, without registration or raising (fail open when mandatory).
- This is **not** proof of an actionable bypass against your actual effective rules: read-only `GET /api/policy/config` previously returned HTTP 403 and the production policy file was not accessed.

## Actual add-on startup log source

The test loads pinned `homeassistant-addon/start.py` without executing `main()` or contacting Supervisor. The real source's `log_info` function was called with a known synthetic path matching its startup log format; output contains the synthetic secret. Static source validation confirms `main()` interpolates its actual `secret_path` in startup messages. This is **VERIFIED SOURCE + offline logging sink reproduction**, not a boot of the entire add-on.

## Scope and limitations

- **Not tested:** exact deployed Docker image digest; actual Supervisor routing/mounting, real non-synthetic admin tool backends, hosted OpenAI authorization, DNS/IPv6/Proxy behavior, tunnel binary v0.0.15, restart/cold reboot, real key expiry/revocation.
- The server code is real and pinned, but one safe artificial tool is registered instead of the 8.6.0 production catalog. Synthetic `tools/call` execution proves inbound transport semantics without device risk.
- Real binding `MCP_HOST` and Supervisor port 9583 should be tested in a future isolated image / HAOS runtime, never in current production.
- User's production running add-on claims 8.6.0, but its image digest was not exposed by authorized read-only Supervisor metadata.

**Verdict:** Phase 2C real transport and policy gates met **within stated scope**. Overall Phase 2 remains blocked on hosted unauthorized-attachment and live policy/transport-boundary verification. Phase 3 **NO-GO**.
