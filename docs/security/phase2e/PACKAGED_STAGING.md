# Phase 2E — Real packaged HA-MCP 8.6.0 staging receipt

Date: 2026-10-08. **VERIFIED PACKAGED, within explicitly isolated scope. NOT full Supervisor/HAOS.**

## Immutable source and packaging

- Pinned upstream HA-MCP `fc54437a804858732e4bc927add98e202d879a09` (8.6.0); exact original `server.py`/`start.py` Git blobs checked by SHA-guarded patch builder; real `homeassistant-addon/Dockerfile` built with upstream `uv.lock`, pinned uv/Python base images and version label 8.6.0.
- Disposable GitHub Actions `ubuntu-24.04` runner, Docker image `ha-mcp-phase2e:local` (not published); actual image runtime `python3 /start.py`.
- **No network access:** `docker run --network none --cap-drop ALL --security-opt no-new-privileges`. No published host ports, no production HA/Supervisor endpoint; fake Supervisor token, a synthetic `/data/options.json`, synthetic `tool_policy.json` and local loopback `127.0.0.1:9583` only.
- In-container MCP `initialize` accepted for healthy configurations using the actual FastMCP Streamable-HTTP transport. The harness handles either JSON or SSE response formats.
- No real physical device/tool commands, API keys, Auth0, OpenAI tunnel resources, HAOS reboot, real token revocation or production policy reads.

## Final exact verified CI receipt

[Packaged run #37843820868](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37843820868), source commit `71fefde8df76f2fb60414d41c7f72263a534a14f`, **SUCCESS**.

| Scenario | Real packaged entrypoint result | Synthetic log check |
|---|---|---|
| Valid strict policy | MCP READY | PASS |
| Strict policy missing | MCP startup REFUSED | PASS |
| Strict policy empty | MCP startup REFUSED | PASS |
| Strict policy corrupt | MCP startup REFUSED | PASS |
| Strict required but engine disabled | MCP startup REFUSED | PASS |
| Invalid config using persistent synthetic volume | MCP startup REFUSED | PASS |
| Same volume with valid policy restored | MCP READY | PASS |

The last two cases prove recovery after restoring the **same** persistent synthetic configuration volume, not a clean fresh-directory substitution.

[Source regression + rollback run #37843820900](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37843820900), **SUCCESS**: pinned unmodified baseline **38 passed**; policy alone **18 passed, 8 deselected**; logging alone **8 passed, 18 deselected**; both together **26 passed**; selected upstream tests **20 passed**; exact independent and combined source reversal / Git blob restoration **PASSED**. The other final run [#37843827906](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37843827906) also succeeded.

## Findings and remediation history

- **FAILED, intermediate packaged check:** Initial log-filter-only candidate left a **synthetic** secret path in container stdout/stderr although the server itself could start. This disproved reliance on pure Python isolated logger tests.
- **VERIFIED SOURCE:** FastMCP transport's `run_http_async` logs the HTTP URL/path to its own logger after the startup banner; Uvicorn access logging can also reproduce URLs.
- **TESTED CHANGE:** Add-on candidate suppresses FastMCP startup banner (`show_banner=False`), disables Uvicorn request access logging, removes explicit startup/error path fields, and installs both an existing-handler filter and a Python `LogRecordFactory` scrubber that handles handlers registered later. Added late-handler unit regression.
- **VERIFIED PACKAGED:** No exact synthetic secret was found in the collected startup/request logs for any of the seven final scenarios. Log checking includes literal, URL-encoded and escaped slash variants. This does **not** establish immunity from arbitrary third-party direct stderr writes, future logging implementations, all Unicode/ANSI transformations, Supervisor logging, real credentials or proxy access logs.
- **VERIFIED OFFLINE/SOURCE:** Strict policy rejects malformed strict-option flag, middleware import/registration failures, policy migration failure, missing/empty/corrupt file, no policy engine, bare global allow wildcard; per-request revalidation blocks changes to invalid policy. A recorded evaluator regression proves `require_approval`->`allow` in-place mode switch would turn existing destructive approval rules into automatic allows. No auto-migration is supported or authorized.

## Production readiness, safety and rollback

- **Missing:** HA Supervisor-managed container, actual packaged integration with HAOS, supported strict option wiring in `config.yaml`/startup, durable mandatory-policy marker across corrupt options, real installed image digest, local admin recovery, real hosted authorization, IPv6/LAN negative reachability, full log sink/exception coverage, backup restoration, and updates.
- Any supported production implementation must include a reviewed migration from **approval rules** to a **new positive allow list**; do not flip current rule effect in place.
- Tests prove source-level reverse patch with exact pinned blobs and same-volume *synthetic* recovery only. **Do not claim production rollback tested.**
- CI teardown removes test containers/image; no hosted tunnel, user credential, production file, router or HA setting was changed.

**Overall Phase 2: PARTIAL/BLOCKED. Phase 3 deployment: NO-GO.** No PR merged.
