# Phase 2D — Isolated HA-MCP v8.6.0 remediation candidates

**Status:** Engineering candidate; **not approved for production**. Exact upstream `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09`. Existing tunnel PR #1 remains independent. Date: 2026-10-08.

## Candidate provenance and reproducibility

`patch_candidates.py` is a deterministic, source-hash-checked **patch builder**, not an installed HA add-on. It refuses any upstream commit other than `fc54437a804858732e4bc927add98e202d879a09` and any source file whose Git blob differs:

| Candidate | Source file | Original Git blob |
|---|---|---|
| policy | `src/ha_mcp/server.py` | `bf848dcec8345eba603295933768fca6724c913b` |
| logging | `homeassistant-addon/start.py` | `88e926a59f568dc9a9bf7bcd719b518b42f52baa` |

Each candidate changes only its own upstream file. A disposable checkout executes the builder, produces a conventional `git diff`, verifies the reverse patch with `git apply --check -R`, reverses it, checks `git diff --exit-code`, and compares exact baseline Git blobs. A new upstream repo/fork is **not** created, nor is an upstream PR submitted.

Exact runtime test setup: Ubuntu 24.04 runner, Python 3.13, `uv==0.12.20`, upstream `uv.lock` applied with `uv sync --locked --no-dev`, `pytest==8.4.2`, `pytest-asyncio==1.4.0`, immutable SHA-pinned GitHub checkout/setup-python actions. The application uses synthetic credentials and no bound listener; no production environment variables or secrets are read.

### Candidate 1: fail-closed policy initialization — HIGH

- **Prior behavior (VERIFIED STAGING Phase 2C):** With `enable_tool_security_policies=true`, `HomeAssistantSmartMCPServer._apply_tool_security_policies` logs and returns on `ImportError` or a middleware registration exception. That permits server initialization to continue with privileged tools not gated by policies.
- **Changed behavior:** These two paths raise a sanitized `RuntimeError` rather than return. Import failure, registration failure, and earlier unhandled listener/queue exceptions stop the normal application setup path, before the server's external `mcp.run` is reached. No fallback to ungated tool access.
- **Opt-in strict default:** Environment `HA_MCP_REQUIRE_STRICT_POLICY=true` additionally requires `enable_tool_security_policies=true`, a persisted `tool_policy.json`, at least one rule, and `rule_effect="allow"`. All are checked before middleware registration and again within the live per-request policy provider. Removal, corruption, emptying, or switching back to require-approval mode makes subsequent calls fail closed.
- **Legacy compatibility:** Without the new strict environment flag, a valid/default policy's rule semantics remain unchanged; when policies are deliberately enabled, initialization failures now stop startup rather than silently opening access. When policy engine is disabled and strict flag unset, behavior remains unchanged.
- **Important limitation:** An unmatched call in `allow` mode *requires approval*, which is NOT an irreversible hard deny. These patches do not add per-user identity, RBAC, or hard deny. Changes to strict env values require another explicit startup and secure deployment path; the current add-on UI does not expose this new setting.
- **Operator diagnostic:** Sanitized static message suitable for a HA repair/alert integration. Fail-fast can make remote ChatGPT administration unavailable; HA/Supervisor local UI or console must remain independently operable.

### Candidate 2: startup secret-log suppression — HIGH conditional

- **Prior behavior (VERIFIED SOURCE/STAGING):** Add-on emits `secret_path` in startup URL and separate path lines, in invalid-path logs, and in persistence errors. Generic crash tracebacks and FastMCP startup banners may include secret URL contents.
- **Changed behavior:** Removes known interpolated credential disclosures from own startup/validation/persistence/crash messages; preserves the persisted secret path. A bounded filter redacts the exact configured secret, its URL-encoded representation and escaped form on *existing* standard Python logging handlers at bootstrap.
- **Limitation:** Cannot claim Supervisor-wide secret safety: future third-party handlers, direct stderr writes, loggers with separate sinks, and reverse proxies may still expose secret path. Generic crash traceback is suppressed (reduces troubleshooting detail); diagnostics need a separate admin-only error-correlation channel. Do not merge without packaged add-on boot and captured synthetic logging review.
- **Recovery:** The existing stored path and authenticated add-on Configuration interface are retained. No unauthenticated reveal endpoint or credential rotation.

## Security test scope and result records

Tests execute pinned real policy evaluation, middleware, server initialization helper and add-on logging functions. Staging is not a full Supervisor add-on image. The existing Phase 2C in-process MCP app tests establish exact HTTP secret-path behavior; they must be run on the clean unpatched source before patches, because historical tests intentionally expect legacy fail-open behavior.

Independent tests and all rollback results must be recorded from GitHub Actions job logs; no test pass may be claimed based on code review. First candidate-run failures from test harness targeting earlier middleware and from a missing upstream pytest-asyncio dependency were diagnosed as test configuration issues; later runs must demonstrate full success.

## Operational rollback layers

- Patches reverse only their own exact source files; tested `git apply -R` is code rollback, not production deployment.
- Production approval later requires pinning the upstream HA-MCP image, Home Assistant backup and independent HA/Supervisor recovery, then staged restart, watchdog and out-of-band rollback.
- The tunnel-client crash-recovery design and OpenAI hosted attachment validation stay outside this patch.

## Remaining critical unknowns

Actual deployed image digest and effective policy rules; upstream add-on packaging/entrypoint compatibility; backend native inbound bearer; hosted attachment authorization; unrestricted generic tool paths; startup logging from third-party FastMCP/uvicorn and Supervisor; IPv6/LAN ingress and end-to-end reboot/update rollback.

**Deployment decision: NO-GO.** No running system, credentials, router, OpenAI apps, Auth0, or Control Plane modified.
