# Native administrator release-candidate operator runbook

**Owner accepted isolated staging scope/coordination; hosted/target acceptance remains pending. Production NOT AUTHORIZED / NOT PERFORMED.** No Probe A/HAOS/VM execution. Full administration remains the goal; the capability matrix states the remaining gaps.

## One install and connection path

Use the committed `artifacts/native-admin-0.2.0.zip` and its SHA256 file at the immutable reviewed source SHA. Verify the digest and per-file release manifest. This archive contains only `custom_components/hass_codex_admin` and the community `hass_codex_tunnel_mcp` wrapper plus manifest; it contains no development dependencies, tests, Probe A, credentials, databases or toolchain. After separately approved staging/cutover, install these two component directories into HA's configuration `custom_components`, preserving existing unrelated components and private state; restart Core through independent native owner management. Production never runs the development installer or follows moving GitHub HEAD.

Selected tested set: administrator0.2.0, wrapper0.1.0 source from this candidate, Python3.14.2/Core2026.10.0, MCP1.28.1, official tunnelv0.0.16. The supported gate is2026.10.x; other patches must be staged, not blindly upgraded. This changes the previous candidate tunnel pinv0.0.10; no installed production versions were inspected or altered. Never downgrade an unknown newer production version to match fixtures.

Explicit component configuration needs own literal-loopback `backend_url`, allowed native `approver_client_ids`, optional owner panel, and `edit_coordination: owner_window` ONLY after accepting the policy below; its default `unaccepted` blocks configuration mutation consent. The scoped route is **/api/hass_codex_admin/mcp**. Native owner panel issues stable connection ID and one-time optional opaque credential. Configure retained wrapper `admin_connection_id` with exact own-loopback scoped URL; trusted in-process lookup injects its volatile capability. Never supply a broad HA token, expose additional REST/auth routes or put secrets in ChatGPT, Git or logs.

Official OpenAI tunnel runtime keys/organization/workspace rights remain separate from our backend credential. NoOAuth requires separately verified platform access/sharing/operator isolation. A tunnel delegation does not authenticate a human owner. Hosted connection/ChatGPT/iPhone compatibility is pending; no subscription change, ingress or cloud service is implied.

## One update path

Before an authorized update, protect a consistent native backup and independently verify local owner access. Verify reviewed archive/checksum, stage it with the intended Core and test permitted/denied tasks. Stop the connection; replace only verified component assets, preserving `.storage` and unrelated files; restart Core locally. SQLitev1→v2 migration and boot grant retirement are automatic. Existing stable connections rotate raw tokens on ordinary boot; owner session must remain current. Review/install verified official client once through the existing updater, whose known-good rollback shares the lifecycle owner. Existing auto-update enablement remains unchanged; crash recovery never downloads or switches versions.

Core restart is acknowledged once and reconciled read-only after a new actual process identity; missing acknowledgement stays uncertain. Host reboot requires supported native Supervisor features and changed boot facts for the same host. Shutdown cannot be verified from lost connectivity and remains uncertain. These contracts never repeat the mutation or restore a consumed grant.

Native add-on update tasks approve **latest at execution** with `backup:true`, not a falsely pre-reserved version. Core update contract binds exact version. These adapters are source/contract-tested against a synthetic Supervisor service; actual target acceptance is still required.

## One independent recovery path

Local native owner management works without ChatGPT/tunnel. Stop the owned connection, inspect status and actual state; use read-only reconciliation before any retry. Consumed/interrupted writes are never replayed automatically. A missing create receipt cannot attribute an identical object: approve a fresh exact recovery task after local investigation. Drift/dependencies block inverse deletion instead of erasing local changes.

For component failure, reinstall the retained verified **current0.2.0 archive** through independent local HA access and restart. Actual old0.1→new0.2 upgrade, refusal of old0.1 on schema2, independent local access during refusal and current reinstallation were tested with four owned Core processes. **Downgrade to0.1.0 is unsupported** because it lacks the new revocation safeguards. Restoring old software/auth/DB is not a security-preserving rollback. Future schema-compatible known-good candidates must be staged before adoption.

Actual supported Core local backup restore was tested. It retires saved grants and stable connections even on failed restore: explicitly issue a fresh connection afterward. A copied historical auth/DB directory is not the supported restore path; disconnect first, retire all imported authority through independently authenticated local owner management, revoke imported native sessions as needed, then issue new authority. Never reconnect copied authority merely because it loads. Real HAOS/Supervisor restore remains pending.

## Everyday behavior and recurring work

Exactly one existing manager owns the child. Crash backoff1/2/4/8s then exhausted; permanent auth/config denial stops retries. Intentional stop/unload/shutdown or late updater cannot revive it. Healthy means actual transport readiness plus authenticated tools/list, not PID/stale file. Provider/backend outage is distinct from local crash; do not restart HA for tool errors. Uncertain reaping retains ownership and blocks replacement. Exhaustion/storage failure requires local diagnosis and explicit authorized restart/reissue, never a hidden watchdog.

Routine manual work: native owner login when genuinely expired; complete exact task/effects approval; proposed configuration tasks additionally acknowledge the short edit window; new connection after expiry/revoke/supported restore; reviewed updates and verified backup. No daily enrollment, shell helper, permanent broker/lock service, public ingress or purchased service added. No zero-maintenance/uptime promise. Password/MFA remains native secure input; standard native menu/select/multiline/password/number/bool inputs are supported; external OAuth/progress/custom-selector flows remain frontend coverage limits. Restart acknowledgments without incarnation evidence remain uncertain.

## One consolidated acceptance/approval sheet

Rows are separate authorizations; accepting one does not authorize the others.

| Decision/gate | Concrete proposal, limit and recommendation | Current authority/evidence |
|---|---|---|
| Supported-object coordination and release scope | Accept a maximum15-minute owner-approved edit window for only the named objects/new-resource contract; keep other local editors away until expiry/revocation/completion. Our own writes serialize and recheck, but HA cannot enforce the cooperation or eliminate the final-check race. Accept the matrix's complex provider/native frontend, external OAuth/custom-provider frontend/additional high-impact physical types and uncertain add-on restart/shutdown limits only as a defined staging scope; full product remains unfinished until those gaps are accepted or implemented. Add-on updates explicitly select latest. | Proposed mode tested with synthetic owner's consent; real owner explicitly ACCEPTED this maximum15-minute named-object policy and defined scope for isolated staging in this assignment. Production remains unaccepted; source default remains unaccepted. |
| Browser/toolchain and repository access | Existing public nonprivileged CI uses sandboxed system Chromium, locked Playwright and synthetic native login/real panel. No cloud sandbox disabling or host setting change. | The final immutable source receipt records successful actual sandboxed menu/password/selectors and full owner task flow in both native jobs. Cloud Chromium sandbox is unavailable, but the existing public Ubuntu24 CI runner launches sandboxed Chrome. Repository access recovered without authentication/security changes. Private log downloads remain proxy403; sanitized GitHub annotations expose failures without secrets. No additional browser/toolchain permission or paid runner is requested. |
| Isolated hosted tunnel/ChatGPT/iPhone | One separately approved organization/workspace/operator account, existing official clientv0.0.16, only scoped loopback MCP, synthetic script/helper/dashboard, no household devices or extra HA/auth routes. Verify authorized account connect, unauthorized workspace/share denial, unapproved/wrong/expired/revoked/changed task denial, useful multi-step repair/readback/rollback and disconnect recovery; same tests in intended ChatGPT conversation and iPhone. Budget $0 incremental: stop rather than purchase eligibility/capacity. Remove test connection/key/objects after preserving sanitized evidence. | NOT AUTHORIZED / NOT PERFORMED. Exact organization/workspace identity and current plan eligibility must be supplied/verified before provisioning. |
| HAOS/Supervisor target acceptance | Separately approved disposable nonprivileged/supported target and synthetic add-ons/config; verify supported maintenance, backup restoration, update/recovery and independent local management. No historical VM permission, QEMU or paid runner is reused. | NOT AUTHORIZED / NOT PERFORMED; actual Supervisor service and HAOS evidence missing. |
| Production cutover | Separate explicit target/version inspection and accepted scope; protected verified native backup, independent local owner access, stopped connection, reviewed assets/checksums, bounded permitted/denied validation, rollback by retained verified current archive and separately accepted backup restore. | NOT AUTHORIZED / NOT PERFORMED; no live home/tunnel/network/account changes. |

The owner accepted the explicit named-object staging scope/window. The smallest next decision is separate exact authorization for the isolated hosted test row. It is not permission to deploy or a request to repeat completed source engineering.

## Codex Cloud disposable staging receipt — 2026-10-10

Recovered PR2 at `d3dd1e41d60320e13b1758abbc7f681d721360b3`, open/draft/unmerged,
with no intervening changes or dirty work. The actual GitHub0.2.0 archive was
downloaded again from immutable source `d0983cbdb422bb4089a846f1aa34d814432aa735`
and verified as `deb0a0507f8a3105c4c5f14fcb7eabb3952a5dd5d48fabcdff180548df3981d8`.
Application/components, dependency lock and release archive are unchanged.

The existing125-package Python3.14.2/Core2026.10.0 environment passed dependency
checking. Final checked-in setup reproduced59 installed-archive native tests in133.699s, including
script/helper/dashboard operations, denial/replay/expiry/revocation, actual
process restarts, interruption/reconciliation and native backup restoration.
Actual officialv0.0.16 client contract passed in1.984s against the local fake
control plane. Five scheduling iterations had0failures/0duplicate writes; this
is bounded fault coverage, not a stability soak. The same setup also passed489
Phase2L tests in0.703s and633 broader regressions in5.11s, with one optional
legacy selector skip in the separate security venv. Setup preserved the working
tree/index and used the existing hash lock/TLS; it did not create a second installer.
No retained historical counts
are added to these fresh results.

`scripts/development/staging.py` reuses the existing installed-archive fixture
and manager. One bounded foreground invocation creates loopback-only Core,
native frontend/panel assets and only `codex_staging_fault`,
`codex_staging_script`, `codex_staging_helper`, `codex-staging-board` and the
synthetic switch fixture. It creates a0700 temporary directory with a0600
random synthetic native login file. All runtime auth/storage stays outside Git.
Synthetic preconfigured onboarding metadata avoids activating unrelated native
onboarding Internet integrations; real owner onboarding is not claimed.

Actual ready listener inspection showed only127.0.0.1. A fresh native HTTP PKCE
login issued a distinct connector, which failed privileged REST. The deliberate
division-by-zero automation was diagnosed through actual traces, denied before
approval, repaired after one exact native owner WebSocket approval, read back,
rolled back and restored. Connector and native refresh credentials were revoked.
Intentional SIGTERM reaped the owned official client and removed private state
and login data. Final separate staging acceptance took6.689s; it is not an extra
independent native-suite total. Final five-second expiry also removed its state.
Initial staging helper cleanup/landing-page assumptions and a harness proposal
that repeated the automation ID were corrected; the latter received the existing
`automation_id_is_target` denial with no mutation. No product defect was found
and no application workaround was introduced.

Separate read-only review corrected interrupted-startup handling and partial
Core cleanup in the staging helper. Stops cancel startup, checked boundaries
prevent readiness after interruption, and a45-second startup observation deadline
is explicit. Forced Core shutdown, actual closed listeners/client and reaped
manager child are verified before cleanup success. Early/partial startup signal
and injected startup deadline acceptance are recorded separately: all4 lifecycle
tests passed in18.003s, including retained private state on uncertain cleanup. Cancellation-
resistant manager ownership means10-second cleanup observation is not a hard
overall process-exit limit; incomplete observation cannot report PASS. No new
watchdog is added. Socket audits of Core/actual official child and fixed local
flags are source/observed isolation, not kernel network confinement.

Cloud Chromium failed sandbox startup (1requested browser test failed,1.677s).
No sandbox disabling/system repair was attempted. Existing immutable candidate
CI38068489555 passed the actual sandboxed owner panel, full native/package tests
and official client. Serving the full native frontend here is not a new browser
interaction result. The existing development CI adds only the same bounded
loopback staging command and4 startup/cleanup regressions; triggers and privileged/VM workflows are unchanged.

### Capability and hosted prerequisites

The cloud proxy returns CONNECT403 for `api.openai.com/v1/tunnels` and all three
requested OpenAI documentation pages, including the narrow approved anonymous
read-only exception check. These are proxy denials, not OpenAI auth responses.
Current official GitHub source was read at
`b91e6c992dfd33e5c5ea94b00449c527c110851e` (permissions/onboarding/architecture/
configuration), alongside the selectedv0.0.16 CLI/release source
`5f99daabd4aa4a77049e6d81d54a0d8c18335397`. Current web-page contents remain
unreadable here; current master is a reference, not an untested upgrade.

Codex's onboarding contract explicitly says snapshots do not guarantee surviving
processes/connections/runtime authentication. No callable hosting/lease/resume
capability establishes availability after this task. Detached processes or a
suspended task are not supported replacements. Real interactive hosting is
**not established in this cloud**. All owned staging processes are stopped
after verification. A new task can reproduce files/startup; it cannot be promised
the same running service, port or authority.

The smallest alternative is a temporary foreground session on an **existing
nonproduction computer with supported Codex shell access**, kept awake only for
the test. The agent can install the isolated tested toolchain, verify the archive,
start/stop Core and its one manager, then remove owned state. It is not a dedicated
test server or permanent always-on dependency. No such host has been identified
or accessed; do not substitute production Ubuntu/home-infra or alter lab
isolation. Linux amd64 is the tested helper/client environment; another OS needs
the matching verified official artifact/toolchain before execution. A local
browser on that computer handles owner approval while iPhone uses ChatGPT. No
public HA API/owner interface or extra tunnel channel is proposed. An all-iPhone
owner-panel workflow remains separate acceptance, not silently proven.

The existing hosted approval row now requires the following **single consolidated
decision**, with separate authorization boundaries still intact:

| Required prerequisite/action | Exact limit and owner involvement |
|---|---|
| Temporary host | Identify and authorize one already available nonproduction computer with agent access, verified outbound OpenAI HTTPS and an uninterrupted test session. Agent handles installation/run/cleanup; no manual server build, paid host, public ingress or persistent service. If none exists, hosting remains the blocker. |
| Platform organization and ChatGPT workspace | Supply non-secret intended organization/workspace IDs and intended account. Codex Cloud membership does not establish either. Verify current eligibility in the actual account; stop if payment/subscription change is needed. |
| One new test tunnel and runtime key | Separately authorize creation of only a new named isolated tunnel, associated with that organization/workspace, selected NoOAuth. Use Platform's account UI: creator Read+Manage; runtime principal and ChatGPT operator Read+Use, preferably per-tunnel. Restricted runtime key gets only Tunnels Read+Use; no admin key in the daemon. Enter it only through the chosen host's supported secure native configuration/secret input, never chat/Git. Current cloud draft has no runtime secret binding; proxy placeholders are not assumed to be raw daemon credentials. |
| ChatGPT and iPhone | Owner attaches only the new test tunnel in ChatGPT's connection settings and performs the actual conversation/iPhone steps. Verify six correct tools, unapproved denial, one native owner-approved repair/readback/rollback and disconnect recovery. With an existing separately permitted not-entitled identity, verify workspace/share denial. No existing connection changes or new account purchase. |
| Cleanup and budget | $0incremental; stop instead of purchasing access. Stop/reap owned Core/client, revoke native connection/key, remove the new ChatGPT test connection and test tunnel, and remove owned runtime state after preserving sanitized results. HAOS/production remain separately NOT AUTHORIZED. |

Prepared configuration is inert: it is not imported or activated. After that
exact authorization, use the retained native wrapper with values from the new
private state; never run a second standalone client alongside its manager:

```json
{
  "enabled": false,
  "authentication_on_platform": "NoOAuth",
  "platform_organization_id": "OWNER_SELECTED_ORGANIZATION",
  "chatgpt_workspace_id": "OWNER_SELECTED_WORKSPACE",
  "wrapper_entry_after_authorization": {
    "tunnel_id": "NEW_TEST_TUNNEL_ID_FROM_PLATFORM",
    "api_key": "ENTER_ONLY_IN_HOST_SECURE_NATIVE_CONFIGURATION",
    "ha_mcp_url": "OWNED_LITERAL_LOOPBACK_ORIGIN/api/hass_codex_admin/mcp",
    "admin_connection_id": "NEW_NATIVE_OWNER_ISSUED_CONNECTION_ID",
    "control_plane_base_url": "https://api.openai.com",
    "control_plane_url_path": "",
    "auto_update_tunnel_client": false
  }
}
```

NoOAuth relies on separately verified Platform/workspace access, not anonymous
administration. The manager resolves the opaque local connector privately and
injects it only for scoped MCP discovery/calls; a broad HA token is never used.
Forwarded caller headers are not human approval. The runtime key goes only to
the control plane; native owner login/approval remains independent. No real
tunnel/key/app association/account change has been performed.

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
