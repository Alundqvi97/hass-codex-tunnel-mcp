# Phase 3 readiness and independent recovery

As of 2026-10-08: **NO-GO for production deployment; Phase 2 PARTIAL/BLOCKED.** Phase 3 design can continue offline, but its deployment gates must not be bypassed.

## High-impact blockers
1. Hosted OpenAI tunnel attachment denial not independently verified for cross-account, disassociated workspace, missing scope or replay.
2. No end-to-end authenticated MCP POST checks against the **real** HA-MCP implementation; configured backend bearer may not add any server-enforced security on standard-mode secret-URL ingress.
3. Real tool policies / alternative call paths not inventoried: device locks, cameras, admin config, filesystem, automation editing, raw service calls, restarts, backups, security-policy UI.
4. Host-network TCP/9583 listener, IPv6 and same-LAN exposure not independently bounded; no safe off-box reachability or rollback test.
5. Unexpected tunnel-client crash appears not to trigger automatic relaunch from the integration's local watcher; mere health-URL-file readiness is insufficient. Child stderr/stdout not intrinsically redacted.
6. Only source-level and simulated protocol tests executed; no real HA Core reboot, Supervisor add-on, stale-token or tunnel-client binary failover tests.

## Recovery path independence

Before deployment, establish and **test** an out-of-band path: physically accessible HA host / local console, and Home Assistant LAN UI / Supervisor admin path that does not rely on this OpenAI tunnel. Also preserve local network access and verified recent HA backup plus the exact HACS integration version and install archive. Do not store credentials, secret endpoint paths, tokens, or backups in this public repository.

## Phase 3 acceptance sequence

- Security: hosted deny tests and real MCP backend auth; server-enforced least-privilege policy matrix; verify no policy-escape through alternate tools or WebSocket raw commands.
- Transport: inspect actual tunnel-client v0.0.15 and any newer candidate, including redirect, proxy, TLS, DNS, log/error and argv/environment paths.
- Resilience: isolated HA/HACS version-pin; staged cold start, HA restart, add-on restart, client crash, DNS outage, OpenAI outage, failed token, failed update, partial upgrade, failed rollback.
- Network: explicit bind/listen/IPv6/port forwarding assessment; tested local-only path, timed-revert plan and independent restoration.
- Review: dependency/CI pinning, negative tests, reviewer approval, provenance checks, full CI pass and documented 1 skipped HA dependency test.
- Delivery: exact SHA/manifest, signed or pinned archive, protected backup, change window, manual authorization and health-gated automatic rollback.

**Rollback order:** do not break the last independently working administrative path. Stop deployment and preserve local console access. Return to pinned known-good code/config only if a security exception is explicitly accepted; otherwise disable remote administration while retaining local recovery. Verify HA, tunnel, tool scopes, denial, logs and routing following restore.

## Future Control Plane/Auth0 (Phase 5)

Do not merge repositories or share privileged broker identities during this phase. The Home Infra Control Plane uses its own authentication and elevation design. A future HA proxy may use Auth0 OIDC for user identity while preserving *separate HA-scoped authorization*, with additional server-side approvals for security-sensitive actions. OIDC may authenticate users but use a single shared HA backend identity, so it is not inherently per-user HA authorization.


## Phase 2B decision (2026-10-08)

**NO-GO remains.** Two newly source-confirmed high-priority findings now require explicit remediation: (1) HA-MCP standard-mode backend does not independently validate the extra bearer, and (2) policy middleware registration failure can leave administrative tools ungated while the server continues. Do not disable the current working remote path before proving an independent admin recovery path.

Require a real staged backend/authorization test (not the existing simulated fixture), a read-only sanitized effective tool-policy inventory, hosted isolation tests with explicit approval and cost cap, exact v0.0.15 binary inspection, and a separately reviewed recovery implementation. See `RECOVERY_DESIGN.md` and `HOSTED_AUTH_TEST_PLAN.md`.


## Phase 2C decision (2026-10-08)

**Staging gate improved, overall NO-GO unchanged.** Tested exact v8.6.0 standard transport and policy functions successfully against 38 synthetic offline cases, including a confirmed startup policy fail-open and absence of additional incoming bearer validation. See `ACTUAL_HA_MCP_STAGING.md`.

Before any production deployment, require an upstream HA-MCP fail-closed policy initialization remediation (separate project), a secret-path logging remediation, authenticated operator-only policy inventory, a genuine least-privilege gate across every alternative admin tool, and an out-of-band recovery route. Existing HA-MCP add-on auto-update and watchdog being enabled does not independently guarantee tunnel-client crash recovery, source compatibility, or update rollback. A source-level watchdog design remains separate in `RECOVERY_DESIGN.md`.

OpenAI-hosted negative attachment and exact deployed add-on image digest still need verification. Maintain the draft unmerged; do not restart, reconfigure or rotate production.


## Phase 2D readiness (review-only)

**NO-GO** persists after successful isolated source tests: the candidate fail-fast policy can intentionally stop MCP startup, meaning the OpenAI tunnel cannot serve as its own repair route. Preserve and independently exercise local HA/Supervisor admin, pinned images and backups, plus a tested reversal before any upgrade. Confirm actual rule coverage and a strict-mode deployment mechanism; stage packaged HA-MCP boot and synthetic logging; hosted attachment negative tests and LAN/IPv6 isolation remain unverified. The tunnel crash/recovery design remains separate from HA-MCP policy/log patches.


## Phase 2E gates — production still NO-GO

The user supplied administrator UI screenshots of 18 approval rules; generic service, bulk, add-on/backup and HA restart tools are not listed in the visible rules. Source semantics and runtime middleware status still need to be correlated before claiming effective protection. Most critical is that switching these rules unchanged to allow-list mode would automatically allow destructive named operations.

A disposable pinned add-on Docker image has been built and exercised with fake Supervisor token. Initial packaged acceptance detected startup log disclosure of a synthetic secret despite the first redaction patch; suppressing the actual FastMCP banner/HTTP access logger is now being retested. This is not full Supervisor/HAOS validation.

Existing backup list shows 39 snapshots, but newest backups are labeled HA 2026.9.4 while running Core reports 2026.10.0. Require a verified protected current-version backup and independently tested recovery before any update.

The strict-mode option is NOT implemented in stable Supervisor schema, does not survive add-on reboot reliably under a supported path, and could silently disappear if configuration defaults. `phase2e/STRICT_OPTION_DESIGN.md` identifies a durable opt-in and migration marker requirement. **No deployment approval.**


### Final Phase 2E packaged result and gating decision

The real pinned 8.6.0 Dockerfile image passed seven synthetic network-isolated entrypoint scenarios including same-volume invalid-policy to valid-policy recovery and no synthetic path exposure in collected startup/request logs ([run #37843820868](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37843820868)). Selected source and rollback CI also passed ([#37843820900](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37843820900)).

This is **VERIFIED PACKAGED without Supervisor**, not HAOS/Supervisor integration nor production restore. Strict startup now fails closed within the tested container. Automatic updates, independent host recovery, persistent strict option/marker, current-version backup, real permission coverage, hosted attachment authorization and IPv6/LAN ingress remain unverified or incomplete. Do not deploy or merge. Phase 3 remains **NO-GO**.


## Phase 2F gate decision (2026-10-08)

**NO-GO remains.** Pinned source and isolated packaged Docker tests passed: initial legacy opt-out, strict-mode opt-in, fail-closed missing/corrupt options/policy, no silent downgrade after marker, same-volume recovery and no synthetic path in collected logs. Exact source reversal passed. See `phase2f/STRICT_MODE_TEST_RESULTS.md`.

Current live rule effect confirmed `require_approval` by official administrator screenshot. Destructive bare rules would automatically allow operations if naively switched to `allow`; candidate instead constructs a fresh positive read-only allow-list. No hard-deny exists in original policy model, and nested proxy + approval expiry/replay remain separate tests.

Production gates still block: real HAOS/Supervisor option persistence/recovery, current-version backup restore, least-privilege/risky route audit, middleware registration status, hosted unauthorized attachment, LAN/IPv6 isolation and tunnel-client crash recovery. The durable marker is not a guarantee against an administrator deleting both marker and options; trusted admin recovery must be independent of tunnel.


### Phase 2G read-only feasibility and approval dispatch result

Genuine Supervisor/HAOS staging is **BLOCKED**, not 'tested': public GitHub runner had /dev/kvm inaccessible and lacked QEMU/UEFI. New VM / ephemeral runner privilege changes require separate user authorization; no VM created. Verified [preflight #37847835408](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37847835408).

Genuine FastMCP synthetic approval sequence uncovered a pinned upstream race: an approval pending before policy corruption could execute afterward. Separate single-file patch rechecks policy immediately before the privileged tool's `call_next`, stopping the tested race (13 new cases passed, 194 selected upstream after 2 intentional old-semantics exclusions, original 196 passed; exact reverse patch). [CI #37848485823](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848485823). Must update excluded upstream expectations and perform final nested/real backend review before merge.

A more convenient native policy only auto-allows verified bounded reads. Generic `ha_call_service` light rules do not reject additional data/target payloads, so writes stay approval-required. Neither per-tool approval nor server middleware is a universal hard deny. Full Supervisor, independent local restore, hosted unauthorized attachment, add-on update survival, backup integrity and IPv4/IPv6 boundaries remain **BLOCKED/NOT VERIFIED**.

**Production NO-GO.** No production/service/router/credential change.


## Phase 2H — actual acceptance and regression boundary

Security-code regression [#37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013) PASS: 196 original tests, 211 revised/patched tests with ZERO exclusions, exact original source and tests restored. The two old test expectations were actively rewritten for stricter no-stale-approval semantics. This proves in-process gate behavior only.

Real HAOS VM first preflight #37851700140 FAILED before any guest/image was used due old OVMF firmware name, cleanup PASS. Actual authorized one-guest run #37851915146 **IN PROGRESS** as of this note; its Supervisor start/configuration, watchdog, policy corruption/deny, host reboot, complete rollback and recovery are NOT VERIFIED unless independently documented in the final run log.

Even if a guest boots, Phase 3 stays **NO-GO** until the full 16 acceptance cases, hosted attachment boundary, independent production restore, auth and direct LAN/IPv6 exposure gates pass; no production changes, merge, Auth0 or router settings authorized.


### Phase 2H FINAL gate disposition: REAL HAOS ACCEPTANCE BLOCKED

One authorized GitHub-hosted HAOS VM [#37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) downloaded and verified official image SHA256, staged review-only local add-on files into guest disk, configured loopback host forwards and one rootless QEMU guest. **PASS:** image hash, QEMU KVM ACL, staged source, guest teardown and private files removal. **BLOCKED:** observer not seen, Home Assistant HTTP timed out after 780s; no real Supervisor login/install/options/policy/recovery. **NOT VERIFIED:** kernel boot completion, actual add-on image, log secret-path behavior, host reboot, watchdog and real restore. Do not claim Docker equivalence.

Full actual-middleware source [#37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013): 196 original tests and **211 revised/patched passing without exclusions**, original file rollback PASS. The actual guest does not validate these runtime invariants. Static harness improvement [#37853632264](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37853632264) PASS only for Bash/Python syntax and hostforward firewall-rule ordering. Last guest experiment authorization exhausted; no further VM without a new approval. All high-impact deployment gates remain outstanding: **PRODUCTION NO-GO**.


## Phase 2I offline follow-up (2026-10-09; not part of original guest result)

Phase 2I adds only synthetic diagnostics, guard and cleanup models in `docs/security/phase2i/offline_harness.py` and `tests/offline/test_phase2i_harness.py`, with a dedicated no-QEMU Python-only workflow. The historical run #37851915146 stays FAILED/BLOCKED. Classifiers do not contact a socket, boot a VM, validate kernel conntrack or prove Supervisor. See `docs/security/phase2i/REVIEW_AND_FUTURE_ACCEPTANCE.md`. No new guest authorization; any later acceptance must pin reviewed commit/hashes and obtain separate explicit approval. Phase 3 production NO-GO.


### Phase 2I subsequent offline runtime-observer addendum (not historical VM evidence)

Review-only commit `6617d6cded7cb6edb712c79af9f95045aab574c2` improved the *future* guest script's fixed-label transport observations (`HTTP_404`, `TCP_REFUSED`, `TCP_TIMEOUT`, absent listener vs no response), explicit QEMU user network `ipv6=off` and defensive no-body/no-exception-text outputs. The pure classifier and mock regression suite passed **13/13** in GitHub Actions [#37913475390](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913475390) and [#37913479830](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913479830); static syntax/isolation [#37913475242](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913475242) SUCCESS. The original failed run has no new findings. No guest/network experiment was started; these are code-only outputs, not runtime proof. The runner shell cleanup, real DNS resolver and supported Supervisor data seeding remain under review. No further VM authorized. Production NO-GO.
