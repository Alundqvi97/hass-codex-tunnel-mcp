# Administrator operator runbook — candidate only

**CANDIDATE INCOMPLETE: do not deploy this as production.** Use one normal package with the optional native administrator component plus the existing tunnel component; no Probe A actors, policy daemon or watchdog service. HA owns startup/shutdown and the local frontend. Supported tested target: Core2026.10.0/Python3.14.2; other2026.10 patches require the same staging checks, other series fail explicitly.

## One installation/configuration path

For separately authorized disposable staging, install the reviewed release's `custom_components/hass_codex_admin` directory into HA's `custom_components`; retain the existing tunnel integration only if its separately reviewed ingress/OAuth path passes acceptance. The development lock installs a test fixture, not production requirements. The administrator manifest uses Core/native MCP dependencies and no parallel package service. Preserve the known-good release archive/hash and a verified configuration backup before enabling anything.

Central configuration is one `hass_codex_admin` YAML block: `backend_url` must be a literal loopback URL with this HA server's port; `caller_user_ids`, `caller_client_ids`, `approver_client_ids` must be explicit nonempty lists; caller and approver client IDs must be disjoint. `approval_panel` defaults true. Do not put passwords/tokens into that block. Account IDs and registered OAuth client IDs come from separately reviewed actual HA/connector configuration; synthetic `.invalid` fixture IDs are not production settings. Backend HTTPS retains normal verification. Only explicit configuration activates the component.

Remote native endpoint: `/api/mcp/hass_codex_admin`. Static backend bearer injection is rejected. HA's supported OAuth discovery/authorization/PKCE/token/revoke paths also need a reviewed reachable route design; exposing only MCP cannot make login work. Native admin tokens grant broader HA APIs. A demonstrable route/identity isolation policy and wrong-account/alternate-route hosted acceptance are mandatory before remote use; no configuration here silently solves or accepts that blocker.

After separately authorized HA startup, inspect local health/version first. Open the local **Administrator** panel as HA owner, enroll that frontend session and refresh pending tasks. Review the exact before/operation/indirect-effects/rollback definition and expiry; tick the effects confirmation and approve the exact hash once, or revoke. The assistant can inspect/propose/status, but cannot approve. Panel JavaScript serving/syntax is tested; actual browser interaction still needs acceptance. Configuration normalization makes helper full replacement fields visible before approval.

## Health, faults and reconnect

Use ordinary local HA UI/configuration/logs independently of ChatGPT. The MCP `admin_inspect` system health result distinguishes HA version/state from transport reachability; an open process/health file alone is not end-to-end readiness. Unsupported Core series gives a compatibility error; missing adapter gives a specific unsupported result without affecting unrelated commands. An authentication denial stops that request and does not restart HA or retry anonymously.

Normal token refresh follows native HA OAuth, retaining the refresh-token session identity. Revocation requires genuine new consent and new task scope; refreshing login never renews an expired approval. Tests mint refreshed native access tokens and exercise HTTP reconnect, not actual hosted PKCE/consent. Retry safe reads once; never repeat a timed-out write blindly. Actual tool deadline55sec, backend8sec, executor acquisition1sec, task30–900sec and DB lock0.1sec are bounded, not promised household latency.

Read `admin_status` after interruption. `dispatching`, `rolling_back` or `uncertain` means mutation may have occurred. `admin_reconcile` reads configurations only; it can verify the desired current definition without proving who caused it. Device/restart/backup uncertainties require local owner investigation. Ambiguous state remains blocked. Do not edit ledger status to manufacture completion. Review a new exact recovery task if needed. Reverse rollback uses captured before-definitions only while grant is valid and current state matches the recorded result; it restores an applied prefix and never overwrites intervening edits. Services and maintenance have no automatic inverse.

HA startup retires every saved pending/approved grant and approver enrollment. After restart, inspect/reconcile results, reenroll and approve a fresh bounded recovery task if required. A saved receipt is history: replay checks live last-object state and reports drift without mutation. Graceful HA process stop/start and SQLite reopen were tested. Hard kill/power-loss/helper buffered-save durability, real host reboot and production reconnect remain unproved.

## One update and rollback path

Keep the target stable. For each reviewed upgrade, install the fixture from `requirements/admin-test.lock.txt` with `--require-hashes` in a disposable venv; run native connected tests, retained offline tests, compilation and panel syntax. Capture installed capability inventory and compare UX01–12 before changing the supported range. Stage the exact release/configuration with synthetic state, then independently verify local recovery, actual OAuth isolation and backup restore under separate authorization. Do not auto-adopt a breaking update or elevate an unsupported route.

Back up through HA's native backup system and independently verify an authorized restore in disposable acceptance before relying on it. Core local backup creation is tested, Supervisor/HAOS restore is not. If copying the SQLite/configuration directly, cleanly stop the separately authorized HA instance and copy the complete task-owned configuration/store with private ownership/mode; do not copy only an active DB's main file or invent status changes. Task snapshots may contain private definitions; treat them as configuration secrets, not public diagnostics. Keep known-good package and backup outside Git.

For rollback, use the independent local HA UI/console, stop only the authorized HA service through its existing lifecycle manager, restore the reviewed known-good component/package and verified matching backup, then start normally. Future DB schema versions are rejected without overwrite; do not downgrade against an unknown schema. Current store is v1, with no destructive automatic migration; restoring matching v1 backup requires fresh approvals after boot. This is the documented path; full release/backup rollback and HAOS acceptance remain unexecuted gates.

## Costs and recurring work

This adds no paid service, root component or daily maintenance helper. Existing HA host, ChatGPT and tunnel costs remain whatever the owner independently contracts; no price or maintenance-hour estimate is asserted. Recurring work: one release/update review with reproducible staging, verified backups/restore, owner session reenrollment after restart, and one task approval per bounded change. Existing tunnel unexpected-child-exit behavior needs independent local restart; automatic crash recovery remains the unimplemented historical design below. No healthy-service-killing watchdog is introduced.

Before a live change provide one bounded proposal with exact artifacts/hash/configuration, identity/route permissions, verified backup and independent recovery, acceptance checks, time/resource budget and rollback triggers. Missing critical source adapters, native CAS/helper allocation gaps and dependency visibility must be closed or explicitly accepted first. No live access, VM, HAOS, merge or production authorization follows from this runbook.

## Historical tunnel recovery proposal — preserved

# Tunnel-client v0.0.15 crash resilience — isolated follow-up design

**Status:** Architecture review only; no recovery source change in authentication PR #1. Implementation should be an independently reviewed follow-up draft PR because restart orchestration touches update, shutdown, process ownership and reliable administration. Distinct approval gates.

## Verified existing behavior

`custom_components/hass_codex_tunnel_mcp/tunnel.py` starts one child process, monitors health URL-file presence and watches exit code. On an unexpected process exit, `_watch_process()` records `exited` and does not relaunch. The existing source-level fake child test documents that behavior. Binary updater `updater.py` implements its own candidate/last-known-good activation and rollback; neither automatically guarantees HACS integration source rollback.

## Bounded single-owner recovery state machine

```text
STOPPED → STARTING → READY
             ↓          ↓
          FAILED ← NOT_HEALTHY
             ↓ (crash/network)
        BACKOFF (max 5 attempts in 15 min, 1/2/4/8/16s + bounded jitter)
             ├─ on success → STARTING
             ├─ auth/config permanent → BLOCKED (manual action)
             └─ exhausted → DEGRADED + HA Repair notification
STOPPING / SHUTDOWN: cancel backoff and terminate single owned process.
```

Design requirements:
1. Use per-entry async mutex, instance generation counter, explicit intentional-stop flag; preserve ownership of exactly one process, check/reap PID before relaunch, avoid stale health URL files.
2. Separate process-exit vs transport-not-ready vs real MCP backend unavailable; HTTP readiness endpoint / health-file event is insufficient. Require bounded, authenticated backend protocol checks **only after supported transport semantics are known**; never log token or URL path.
3. Backoff with maximum tries and wall-clock budget, monotonic delays and bounded jitter; no rapid infinite loop. Cancel timers on clean HA shutdown, user stop, updater takeover or integration unload.
4. Classify permanent errors (`401/403`, key revocation, config invalid, checksum/asset wrong) as BLOCKED; retry network interruptions, transient DNS and 5xx, preserving last known-good binary.
5. Never alter active binary during recovery; updater owns candidate switch and rollback. Distinguish retrying same binary from controlled updater health rollback.
6. Surface `state`, `last_failure_class`, counts, sanitized timestamps and health gates. Structured repair notice after exhaustion, never raw child stdout/stderr or process environment.
7. Ensure no support service inadvertently reexecutes the child with a duplicated bearer or new `--mcp.extra-headers` flags.
8. Fail closed if independent backend auth is rejected; do not bypass backend security or retry under an anonymous URL.

## Required isolated tests before merge

- Immediate and repeated child exit, retry backoff cap, delay budget, jitter bounds, intentional stop, shutdown, concurrent restart operations.
- Unreachable backend, stale health URL, DNS outage/recovery, OpenAI outage, state transitions and real MCP authorization failure classification.
- Updater activation failure, previous binary recovery, stuck child, partial source upgrade and recovery-mechanism rollback.
- Check HA Core stop/unload hooks actually cancel all tasks; expose a separate independently operable local HA UI recovery path.
- Never use production identifiers, production HA URL or physical devices.

## Deployment and restore layering

Binary rollback restores only the `tunnel-client` image. HACS integration source rollback restores the Python integration and dependencies; HA-MCP add-on rollback restores the server and relevant settings; Home Assistant/Supervisor backup restores configuration/data; UniFi rule reversal restores network access. None substitutes for a separately tested local console / HA UI administration path.

**Decision:** Keep crash-recovery implementation out of PR #1 until server-side authentication and hosted-attachment behavior are established; add source/testing in separate reviewable work stream, not a complicated patch touching production without approval.
