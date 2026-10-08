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
