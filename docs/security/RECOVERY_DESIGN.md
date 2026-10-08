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
