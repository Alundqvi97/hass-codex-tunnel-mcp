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
