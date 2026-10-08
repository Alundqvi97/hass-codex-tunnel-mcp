# Phase 2F — Supported strict-policy test evidence

**Date:** 2026-10-08. **Result: VERIFIED SOURCE + VERIFIED ISOLATED PACKAGED**, not full Supervisor/HAOS or production. Pinned genuine `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09`.

## Final code acceptance

[Phase 2F successful GitHub CI #37846398572](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37846398572), commit `36a011523bc05fe1328a2b5f6fc1e4564865bb91`.

| Gate | Outcome | Scope |
|---|---|---|
| Phase 2D source patch regression | **26 passed** | Original policy/logging candidates *before* stricter opt-in |
| Phase 2F migration / supported options | **42 passed** | Real pinned policy evaluator, add-on preflight, marker and runtime provider |
| Selected upstream compatibility | **20 passed** | Server-policy wiring and add-on server metadata |
| Packaged 8.6.0 entrypoint scenarios | **9 passed** | Real pinned Dockerfile, `/start.py`, fake Supervisor data |
| Log checks | **9 passed** | Synthetic secret absent from all collected container startup/request logs |
| Source rollback | **PASS** | Combined reverse patch; exact original `server.py`, `start.py`, `config.yaml` Git blobs |

These figures are separate test groups, **not** 97 distinct tests.

### Packaged outcomes

| Scenario | Expected and observed |
|---|---|
| Legacy opt-out with policies disabled | MCP READY |
| Unsafe original approval list offered for strict opt-in | MCP REFUSED |
| Valid strict positive read-only allow-list | MCP READY |
| Mandatory marker present, options file missing | MCP REFUSED |
| Mandatory marker present, options JSON corrupt | MCP REFUSED |
| Mandatory marker present, option changed to false | MCP REFUSED |
| Mandatory marker present, policy file missing | MCP REFUSED |
| Mandatory marker present, policy JSON corrupt | MCP REFUSED |
| Valid options/policy restored on same persistent volume | MCP READY |

Marker `strict_policy_required.v1.json` was verified root-owned with mode `0600`. Its content was checked using a separate network-isolated container with the test data volume read-only. Synthetic repair of root-owned policy files was conducted through a separate offline container, **without relaxing file permissions**.

Docker used `--network none`, no published host port, a dummy Supervisor token, real pinned installed HA-MCP 8.6.0, fake policies and isolated disposable storage. No production devices, tokens, links, Auth0, OpenClaw, routers or hosted resources were accessed.

### Source test coverage

- The old 18 configured approval names each require approval under `require_approval`.
- Merely changing the same rules to `allow` automatically authorizes all 18; the acceptance test explicitly demonstrates why this approach is prohibited.
- New separate policy auto-allows only `ha_get_overview`. All 18 destructive names, broad service call, bulk, restart/add-on/backup/config/admin names and new unknown tool names require approval.
- Known synthetic lock/unlock, WS-service request, bulk selector and media/light examples remain approval-required under actual pinned evaluator.
- Test of persisted mandatory marker, malformed/missing options, corrupt marker, symlink marker, policy file conversion, opt-out attempt, invalid allow names and unexpected policy changes.
- On-call policy provider refuses widened automatic authorization after middleware was installed under a safe policy.
- The old Phase 2D policy initialization and logging tests continue passing before intentional Phase 2F narrowing.

### Failures corrected during engineering

- An initial migration test initialized the middleware after replacing the policy with a dangerous one. The implementation correctly aborted; fixed test ordering.
- Original Phase 2D tests were intentionally incompatible with the new read-only-only strict policy; CI now checks Phase 2D **before** Phase 2F changes.
- First supported packaged opt-in refused startup after early import of the HA-MCP package. The preflight was changed to standard-library-only parsing; actual pinned Policy validation remains at server startup and each MCP request.
- Packaged fixture could not read a root-owned marker from the unprivileged GitHub runner. Test now reads it inside a separate offline read-only container.
- Packaged fixture could not rewrite a root-owned migrated policy. Synthetic local repair now uses a separate network-isolated administrator container, not broad filesystem permissions.
- Intermediate CI failures remain visible in Actions; **do not treat them as passing**. The final code acceptance above passed.

### Unverified acceptance dimensions

Real nested proxy dispatch and potential meta-tool bypass under strict mode; denied/expired/replayed approvals; exact production installed 8.6.0 tool catalog and policy middleware registration; separate production hard-deny / least-privileged HA identity; real Supervisor schema/option roundtrip, HAOS reboot and installation rollback; cross-account OpenAI hosted attachment; LAN/IPv6 reachability; restore from existing protected HA backup. This is why **overall Phase 2 remains blocked**, even with a successful packaged test.

After documentation commits, a fresh final-HEAD CI must be recorded separately. Neither PR may be merged or deployed.
