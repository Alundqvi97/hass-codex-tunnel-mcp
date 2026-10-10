# Administrator operator runbook — candidate only

**CANDIDATE INCOMPLETE.** This is a development/review path, not authorization to configure a live connection or install in production. Source setup and sanitized evidence are committed; workspace environment publication is separate and was not performed.

## Reproducible development and selected connection

Follow [scripts/development/start.md](../../scripts/development/start.md). Use Core2026.10.0/Python3.14.2 and the existing hash lock. The installer checks reviewed PR2 source ancestry and required files, accepts later reviewed descendants and dirty work, and never fetches/reset/stashes/switches the project. External temporary state/caches are mandatory. It installs no permanent HA service or actual tunnel.

Under a separately approved staging proposal, enable only the native component with own literal-loopback `backend_url` and explicit native owner `approver_client_ids`. The scoped route is **`/api/hass_codex_admin/mcp`**. Do not use the old `/api/mcp/hass_codex_admin` or hand the remote connection a normal HA admin bearer. The local native owner panel issues a stable connection ID and optional one-time scoped bearer; use the stable ID in the retained wrapper's `admin_connection_id`, the exact own-loopback scoped URL and no legacy static bearer. Only trusted in-process transport lookup obtains the current secret. Never log/store a real bearer in Git. Hosted official tunnel NoOAuth routing/workspace eligibility is still an untested gate; do not expose general HA auth/API routes to make it work.

The owner panel reviews exact definitions/arguments/indirect effects/rollback/expiry and requires explicit effects consent. Native current owner session validation handles enrollment internally; ordinary restart does not require reenrolling. Explicit task approval remains necessary. MCP cannot approve. A ChatGPT confirmation, if shown, is an additional client control, not server authority; mobile/browser total prompts were not tested.

## Disconnect, failure, restart and uncertain work

Use local HA normally even when ChatGPT is unavailable. The existing manager distinguishes provider outage, transport-not-ready, backend-unavailable, authentication denial, invalid configuration, crash/backoff and recovery exhausted. Readiness is real health plus authenticated tools/list, never a PID/stale file. Local crashes retry the same known-good installed binary at1/2/4/8 seconds; no download per failure. Exhaustion or revoked credentials require an owner diagnosis and explicit restart/new credential, not an endless retry. User stop/unload/Core shutdown close ownership and cannot be undone by stale updater callbacks. Uncertain child reaping keeps ownership and reports cleanup_incomplete; investigate only the owned process through authorized lifecycle, never numeric-PID scans/killing unrelated services.

Normal restart rotates raw capabilities and lets the same unexpired stable connection ID reconnect through the existing local manager. Saved grants retire, consumed operations remain consumed and interrupted writes are never automatically replayed. Native owner logout/connection expiry requires genuine local reauthorization. Inspect `admin_status`; use read-only `admin_reconcile` to compare actual configurations. It cannot attribute who wrote them. An uncertain or drifted result needs a new exact owner recovery task; do not edit SQLite status or repeat a timed-out write blindly.

Supported Core backup restore retires all stable connections and saved grants, even when the result is failed. Issue a new connection explicitly after restore. The native backup manager's retained event avoids racing its deleted marker. Do not treat copying an old configuration/auth/SQLite file as equivalent: restored-only state cannot preserve later revocations. Such an out-of-band restore requires independent local retirement/reissue before remote reconnection and is not accepted automatically.

## Update, rollback and practical limits

Default automatic-update settings remain unchanged. Review a release, install its verified asset once, test readiness/actual MCP and keep the known-good version. Failed activation rolls back under the same lifecycle generation; a later user stop wins. Update/restart/download/rollback services now require native admin authority. Recovery never changes the version on each failure. Stage compatibility from the existing lock before widening the supported Core range; only2026.10.0 has passed this suite.

Native Core local backup creation and restore were exercised with owned processes, including restored script state, retired delegations/grants and old-bearer rejection. This is not Supervisor/add-on/HAOS, disk/power-loss or physical recovery acceptance. Use an independently verified authorized backup and existing HA lifecycle for a future production rollback. DBv1 additions are non-destructive; unknown schema versions fail without overwrite. Preserve private file ownership and whole consistent stores; never copy only an active SQLite main file.

Final snapshot checks cannot supply native conditional writes or atomic helper allocation. Keep local conflicts explicit; no exclusive-edit policy is assumed. Unexpected ID/partial mutation stays uncertain and does not delete unrelated objects. Loaded script/automation/dashboard/group references are checked; unknown YAML/custom/dynamic dependencies remain a release decision. Missing credential/reconfigure/Supervisor adapters are not implemented via manual YAML instructions.

Routine steps: native owner login renewal when genuinely expired; one scoped task decision; new connection after expiry/revocation/restore; reviewed update/backup verification. No additional watchdog, root service, public ingress, paid service or routine restart reenrollment was added. A local transport fixture demonstrated subsequent real MCP after crashes/disconnect/backend outage/update rollback; official control-plane/hosted/iPhone/browser/physical/HAOS acceptance remain separate. Production and Probe A/VM execution: NOT AUTHORIZED / NOT PERFORMED.

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
