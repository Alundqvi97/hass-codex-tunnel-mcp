# Native administrator release checklist — 2026-10-10

**Release candidate awaiting explicit scope/coordination acceptance and hosted/target acceptance.** The implemented candidate remains optional and disabled without explicit configuration. Full administration is still the Blueprint outcome; the finite supported scope below is not silently substituted for it. Production, Probe A and HAOS/VM execution were neither authorized nor performed.

Starting revision `27a78774c792ab8dfcf8a9abaed57329032d6483` matched PR2's open/draft/unmerged remote head. Reviewed source `a7ad7a6a3362262e0a5f3b8d8a04998106d42acc` and owner amendment `b2dc4eb05f5bda4ec9b32d443a1abba505543a2b` are ancestors. The reviewed source-to-delivery difference was exactly eight added implementation-plan lines. Initial checkout was clean; legitimate history was preserved. Source/test and later documentation SHAs are recorded by the following immutable delivery receipt, avoiding a self-referential hash.

| Finite release item | Implemented/tested result | Remaining gate |
|---|---|---|
| Credential separation and ordinary useful task path | Retained scoped MCP, independent owner decision, final dispatch, native readback and reverse rollback. Durable deny markers defeat failed SQL revocation and late/cancelled issuance; RAM task deny precedes persistence. Boot retires pending authority. | Complete storage failure can prevent durable revocation: keep connection stopped, repair local storage, retire authority independently before reconnecting. Unsupported old auth/DB copies remain a recovery boundary. |
| Helper allocation and edits | HA assigns the final new helper ID; actual response/definition and durable task/index receipt bind same-task follow-ups and rollback. No ID reservation, name-based adoption or unrelated deletion. Interrupted create without a trusted receipt stays uncertain. | Core collection/config APIs lack conditional writes. Proposed explicit `owner_window` policy requires cooperation for only the named objects through the approved expiry (maximum15min); default is `unaccepted`. Owner has not accepted this release policy. |
| Supported credential operations | Native reauth/reconfigure initiation, bound owner-only input/cancel/status, exact entry/source identity, bounded lifecycle and actual unload→loaded observation. Password stays in native owner form, outside MCP/status/logs. | Native menu, standard single/multiple select, password, multiline text, numeric and boolean forms implemented without defaults/secrets. External OAuth/progress/custom/multiple-text steps still require provider frontend coverage; disappeared flows cannot prove success. No universal provider coverage claim. |
| Supported elevated maintenance | Native Supervisor fixed WS API for add-on start/stop/restart/update and Core update, sanitized readback and latest-release/backup contract. Existing Core config check, integration reload, backup/create/restore retained. | Actual Supervisor/HAOS not available. Add-on restart acknowledgment lacks an incarnation proof and stays uncertain; add-on version reservation unsupported (explicit latest contract). Fixed native host reboot/shutdown contracts and actual owned Core restart reconciliation are implemented. Real host/Supervisor acceptance is missing; arbitrary provider repair/physical types remain source coverage gaps. |
| Ordinary connection recovery | Existing single manager/process owner, finite backoff, no crash downloads, generation-safe updater/stop/rollback retained. Actual official v10/v16 clients execute scoped MCP before and after owned crash. | Hosted provider/organization/workspace/mobile acceptance; synthetic control plane does not validate these. |
| Package/install/upgrade/recovery | Deterministic production-only archive, per-file manifest, fresh installed-source execution; real Core0.1→0.2 schema upgrade, unsafe old-schema downgrade refusal, local management and reinstall recovery. Native Core backup/restore and process death retained. | Unsafe0.1 downgrade deliberately unsupported. Real HAOS/Supervisor restore, disk/power loss and target hardware untested. |
| Validation/review | Baseline42 native/489 Phase2L/633 broader+1optional skip reproduced. Earlier installed-archive55 native,489 and633+1optional skip passed; expanded59 native, package and selector-browser results are recorded in the following final receipt. Actual official clientv10/v16 contracts passed. Python/JS/shell/whitespace/isolation pass. Two read-only reviewers' findings corrected. | Actual sandboxed browser runs in existing nonprivileged GitHub CI; see immutable receipt for result. Scanner job114224377837 failed; owner reported HTTP402 quota, detailed logs inaccessible here. No retry/purchase or clean-scan claim. |

### Concrete architecture and dependencies

Keep official OpenAI `tunnel-client` **v0.0.16**, source `5f99daabd4aa4a77049e6d81d54a0d8c18335397`, verified Linux amd64 archive SHA256 `d60cdba019bce451bcc3a15478cc5b9cb11270b049f5b56ea39a80b517f8b117`. This is the maintained upstream release observed today; the previous candidate pin wasv0.0.10. No production installation/version was inspected or altered. Exact-name binary lookup and filtered environment prevent extra channels/Cloudflare activation through inherited settings. Existing automatic-update flags are preserved.

Core **2026.10.0**, Python **3.14.2**, MCP **1.28.1** remain the tested baseline. Native development lock retains all124 previous verified packages and adds only official Core Supervisor dependency `aiohasupervisor==0.6.0` (125 packages). The component accepts2026.10.x for staged compatibility; only2026.10.0 was tested. Private streamable-MCP/request-cache seams remain confined to `connector.py`; the public LLM hook cannot by itself separate connector credentials or register our scoped route. No transport fork, new auth provider, global lock, broker or watchdog was added.

Primary URL shell fetches remain CONNECT403. Official pinned fallback sources were inspected: tunnel v0.0.16 permissions/onboarding/protocol; HA Core commit6a811d3359c7b2076dc9e1cf900843a129c044af; HA developer docs883072b5555988737f681e91a8b2f0d2cf27af70 (`core/llm/index.md`, `auth_api.md`); HA integration docs c86a3009cad7e856b78d8ce3342e47750cf96fb0. OpenAI custom MCP and Secure MCP Tunnel are official client/transport facilities; the HACS wrapper is community code; native MCP is HA's integration; this administrator is custom, not vendor-certified. Assist's own documented API cannot perform administration. Official workspace/org tunnel-use permissions do not establish which human approved a task; NoOAuth does not grant anonymous household access. Hosted eligibility/sharing/operator isolation remains to be tested, with no tier/subscription/mobile compatibility promise.

### Honest conflict, dependency and evidence limits

The task engine serializes its own writes, captures before/after, rechecks exact scope/definition/dependencies at dispatch and preserves independent later edits during rollback. A real test demonstrates that an independent writer in the final-check→send gap can still be overwritten by HA's unconditional API. This is the precise motivation for the proposed short edit window; neither the fixture's acceptance nor a passing race demonstration accepts that risk for the owner. After-dispatch drift stays uncertain and is not overwritten by rollback.

Loaded automation/script definitions, entity registry identity, native group membership and stored dashboards provide practical dependency coverage. Unloaded YAML/custom/dynamic/template references remain explicit uncertainty in destructive effect/rollback consent. Arbitrary behavior is not statically proven. Real Core processes, HTTP/WS/MCP/auth, SQLite and backup restoration are distinguished from synthetic device/Supervisor/control-plane boundaries; no synthetic evidence becomes privileged or hosted PASS.

Implementation changes are in existing auth/store/approval/model/backend/engine/panel/diagnostics/LLM paths; new finite `flows.py` and `supervisor.py` adapters; existing wrapper binary/const/tunnel; native/fault/browser/package/official-client tests; checked-in development package/setup, lock and existing native CI. Durable file inventory/checksums/evidence and archive are committed alongside this source. Historical results below are retained, not counted again as new coverage. See the single approval sheet and install/update/independent recovery path in [RECOVERY_DESIGN.md](RECOVERY_DESIGN.md).

### Final integrated candidate receipt

Immutable source/test/package: [`d0983cbdb422bb4089a846f1aa34d814432aa735`](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/commit/d0983cbdb422bb4089a846f1aa34d814432aa735), normally pushed to open/draft/unmerged PR2. The following documentation commit records this receipt without a self-referential hash. Final production-only archive SHA256: `deb0a0507f8a3105c4c5f14fcb7eabb3952a5dd5d48fabcdff180548df3981d8`; downloaded from GitHub and every production asset compared to this source. Blueprint and both VM workflows remain byte-for-byte unchanged.

Final installed-archive59 native tests passed (134.202s);489 Phase2L (0.704s);633 broader+1optional legacy skip (6.91s). Python/JS/shell/whitespace/isolation and checksum checks passed. Fresh clone/new125-package venv reproduced59/489/633+1; reproduction counts are not added. Actual package install/upgrade/unsafe downgrade refusal/recovery and official v10/v16 contracts passed. Both final native CI runs [38067667282](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38067667282) / [38067672474](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38067672474) succeeded, including sandboxed real owner panel, native menu/selectors/password, full native/package/compilation and actual officialv16 client. D/I/J/K/L/E/F succeeded at this SHA. Scanner38067673769 failed; no clean-scan or quota-purchase claim. Sanitized exact-SHA metadata, substituted boundaries and historical failures are retained in NATIVE_ADMIN_EVIDENCE.json.

Completed corrections include durable denial/issuance recovery, receipt-bound HA-assigned identities/follow-ups, native reauth initialized-form retrieval, queued authorization, standard menu/selector fidelity and accessible labels, fixed Supervisor endpoints/contracts, actual owned Core restart/read-only reconciliation and fixed host boot/shutdown contracts. Shutdown/disconnect alone stays uncertain; consumed mutations never replay. Five varied-schedule iterations had zero failures/duplicate writes (0.844s total; task+rollback129.79–156.67ms). One approved three-operation repair executed in53.81ms and rolled back in83.32ms; neither result is a stability soak or physical guarantee. Two separate read-only review passes found no remaining confirmed defect in the implemented finite scope after fixes; no independent certification claimed.

ENGINEERING remains INCOMPLETE for the full Blueprint scope: external OAuth/progress/custom/multiple-text provider frontend and additional high-impact device adapters remain source coverage gaps. The finite packaged candidate is validated. ACCEPTANCE is PENDING: the real owner has not accepted the proposed maximum15-minute named-object edit window or staging scope; hosted ChatGPT/iPhone, real Supervisor/HAOS and physical acceptance are missing. The observed unconditional-write race remains explicit, not CAS. DEPLOYMENT: NOT AUTHORIZED / NOT PERFORMED. Probe A and HAOS/VM execution: NOT AUTHORIZED / NOT PERFORMED. Use the separate rows in the single runbook sheet for the next policy/scope decision and later external approvals; full administration is not silently replaced with this staging subset.

### Superseded interim blocked receipt — historical evidence

The following receipt described the earlier transient GitHub401/browser failure and is preserved as history. Its access/failure status is superseded by the final receipt.

### Immutable source, CI and blocked final receipt

Source/test/archive revision: [`c38e776e94cdc8efb469ef57ff97832ec1a7ecbe`](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/commit/c38e776e94cdc8efb469ef57ff97832ec1a7ecbe), pushed normally to draft/unmerged PR2. The39-file change inventory is in NATIVE_ADMIN_EVIDENCE.json; protected Blueprint/VM files are unchanged. GitHub download of the committed archive reproduced SHA256 `14fd06bf3d9873839881dae0959555617ac6c7445b643e5dab3f63f2a3e54674`.

Actual source-SHA CI: D [38061621317](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061621317), I [38061621356](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061621356), J [38061621269](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061621269), K [38061621293](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061621293), L [38061621261](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061621261), packaging E [38061619255](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061619255) and F [38061619252](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061619252) **succeeded**. Initial API verified I/J/K/L; public run pages verified D/E/F after access expiry. No privileged workflow was dispatched/retried.

Native CI [38061621359](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/38061621359), job114240873250, **failed at Sandboxed actual owner panel and native login**, public annotation exit code1. The sequential workflow had reached that step after installed native/package validation and compilation; official-client CI afterward was skipped, though actual local v10/v16 contracts passed. Cause remains unknown because detailed logs require authentication. New automatic scanner run38061624025 failed; it is not a clean review. No capacity was purchased or manual scanner retry invoked.

Existing GH_TOKEN became invalid (API HTTP401) after the successful source push and verified archive download. Public status pages remain readable; authenticated logs, further fixes/push and PR-description update are blocked. No credentials were printed, changed or committed, and no workspace security was altered. This final documentation/evidence/checksum receipt is preserved in a normal local commit, **not published while authentication is unavailable**. Refresh the existing repository connection (never paste secrets) to diagnose the browser failure and deliver the receipt. Engineering is INCOMPLETE at that concrete validation boundary; owner scope/coordination and hosted/HAOS/production decisions remain separately listed in the single runbook sheet. No asynchronous completion is promised.

## Previous native candidate and historical results — preserved

# Security implementation plan

## Current native administrator candidate — secure connection and recovery

**CANDIDATE INCOMPLETE.** The source closes the connector's broad-native-bearer bypass and implements bounded recovery in the existing tunnel manager. Useful approved administration remains available. Native configuration conflict/ID reservation limits, remaining adapters and external acceptance prevent a release-ready claim. No exclusive-edit policy, reduced full-administration goal or production risk acceptance is implied. Blueprint section 0 and UX01–12 remain binding.

### Maintained boundary and transport decision

Retain Core **2026.10.0** (`6a811d3359c7b2076dc9e1cf900843a129c044af`), Python **3.14.2**, the existing 124-package hash lock, SQLite v1 and the official OpenAI tunnel client **v0.0.10** (tag commit `ab3b64ba1818d67ae625fb91c9b8ef850759579a`). Do not enable disabled automatic updates or adopt v0.0.15 as part of recovery. Only Core2026.10.0 is tested; other patch releases need staging and other series are rejected. HA2024.6.4 is optional historical wrapper compatibility; `hacs.json` is a minimum, not this administrator's runtime target.

OpenAI custom MCP connections and Secure MCP Tunnel are official client/transport facilities. The HACS tunnel manager is community code. HA native MCP/LLM/auth/backup are Home Assistant interfaces. `hass_codex_admin` is our custom administrator, not vendor-certified. Assist alone does not provide these administrative tools; changing transport does not add them. We retain the official transport and existing wrapper rather than create public HTTPS ingress, an OAuth provider, a broker/watchdog, a transport fork or an always-on computer dependency. Direct HTTPS would still need the same credential separation plus ingress/certificate/discovery maintenance. No connection or provisioning occurred.

Selected source boundary: official tunnel/client workspace access → trusted local header injection → **POST `/api/hass_codex_admin/mcp`** → six existing typed tools → exact owner-approved task → fixed own-loopback HA backend. The connector uses an opaque `hca_` capability, not a HA access token. HA rejects it on native REST, WebSocket, base/alternate MCP, Assist and SSE routes. The custom view accepts no native HA JWT, query routing or caller identity headers. Native owner/backend credentials never leave the backend adapter. The connection identity identifies a delegation, not the authenticated human, OAuth metadata, audience or workspace owner. It never self-approves.

This small credential adapter reuses Core's maintained stateless streamable MCP implementation and supported LLM API registration; it does not copy the MCP protocol. `_async_handle_streamable_message` and aiohttp's request-body cache are **private version-sensitive seams**, covered by connected tests and the supported-version gate. A future public extension API is preferable. The selected hosted connection would use the official tunnel's supported NoOAuth mode with local scoped credential injection; this has **not** been connected to hosted ChatGPT. Native owner OAuth remains independent local login. No broadly privileged native token is tunneled to make OAuth succeed. Native discovery, PKCE, code exchange/replay, wrong-client refresh, refresh and revocation are tested over HTTP. Hosted discovery/consent/redirects, tunnel routing, account eligibility, conversation/iPhone and both approval UIs remain acceptance facts, not subscription or compatibility promises.

All six requested official documentation URLs were attempted: developers.openai.com/api/docs/guides/custom-mcp-server; developers.openai.com/api/docs/guides/secure-mcp-tunnels; developers.openai.com/plugins/deploy/connect-chatgpt; www.home-assistant.io/integrations/mcp_server/; developers.home-assistant.io/docs/core/llm/; developers.home-assistant.io/docs/auth_api/. Normal and approved read-only requests failed at proxy CONNECT403. Current official GitHub tunnel-client README/connectors/permissions and installed pinned Core sources were read instead; this is a documented reference-access blocker, not a claimed successful check of those six pages. No workspace network/authentication/publication settings were changed.

### Authority, lifecycle and ordinary operation

Owner-only native WS connection issue/list/revoke persists capability hashes and a stable connection ID. The raw bearer is returned once and never stored in Git or SQLite. The existing tunnel configuration may reference that stable ID; trusted in-process lookup supplies a volatile current capability only for this exact own-loopback endpoint, without a generic proxy or RPC secret lookup. Native owner session validity is rechecked at requests and every dispatch. Connector expiry, native logout and explicit revocation deny further work. Native WS debug authentication/issuance records are suppressed without logging credentials.

Normal Core boot rotates bearer bytes, preserving an unexpired stable delegation so the existing manager can reconnect without routine copying. Boot retires every saved pending/approved grant. Current native owner validation replaces mandatory manual reenrollment; explicit task approval and elevated effects consent remain necessary. **Supported Core restore retires stable delegations too**: the component depends on native backup setup and observes its retained RestoreBackupEvent after marker consumption, including failed restores. The actual restore test proves the old stable ID cannot acquire a fresh capability. An owner must explicitly issue a new connection after restore. Out-of-band copying an old auth/config/DB cannot be distinguished from an ordinary restart using only restored state; automatic remote reconnection after such a copy is unsupported until authority is retired through independent owner recovery. This is not a non-restored revocation anchor.

The existing manager serializes start/stop/update generations and owns one child/lease. Nonprivileged Linux parent-death notification and a shared inherited ownership lease prevent a second manager from adopting/killing unrelated PIDs. Unexpected child exit relaunches the same installed binary with delays1/2/4/8 seconds, then reports exhausted; a300-second stable interval resets the burst budget. Stop, unload, Core shutdown and failed setup release only owned resources. Repeated cancellation cannot abandon process creation or cleanup, including lock acquisition. TERM and KILL reaping are each bounded; uncertain reaping retains ownership, reports cleanup_incomplete and prevents replacement. This is ordinary child lifetime management, not experimental privileged confinement.

Readiness requires actual `/readyz` and authenticated native MCP tools/list. Stale health files do not count. Retained v0.0.10 poll HTTP metric deltas distinguish permanent401/403 from provider errors without using tool-error counts; optional newer component health is only a fallback. Provider outage/transport disconnect/backend outage are degraded states, not triggers to download or restart HA. Credentials/configuration denial stops recovery. Raw child output is drained without payload logging. Known-good updater rollback and lifecycle epoch checks prevent late downloads/rollback from undoing a user stop. Automatic update enablement is unchanged.

### Writes, dependencies and recovery limits

Preserve the existing task engine, cancellation, consumed intents, exact caller/action/target/arguments/task/policy binding, no self-approval, per-send authorization, independent native readback, prefix rollback and reconciliation. A second snapshot/dependency check occurs after durable intent and backend authentication, immediately before the first mutation. The connected local-edit test preserves an intervening script edit and then performs a fresh approved repair/rollback. This **is not compare-and-swap**. Core's supported CRUD APIs do not provide conditional writes or requested helper-ID reservation; a local edit after the final check can still race. The helper collision test actually creates the unrelated local helper, observes the unexpected remote allocation, retains uncertain status, rejects replay and deletes neither. No hidden exclusive-edit restriction or claim of all-writer atomicity is introduced. Resolving or explicitly accepting that supported-object coordination limit is a source/release blocker.

Dependency discovery covers loaded automation/script definitions, stored dashboards and native declared group membership. New dependencies before inverse deletion block rollback. Unloaded YAML, custom integrations, dynamic templates/references and arbitrary effect analysis remain explicit uncertainty. There is no complete static-analysis promise.

Actual process-death tests distinguish durable SQLite intent/receipts from HA buffered configuration saves. Four boundaries are exercised: before intent, after intent, after native mutation, and after a helper's applied receipt but before HA's delayed save. Reopen reads actual state, preserves uncertainty/drift, never restores consumed authority or retries interrupted writes. The latter demonstrates a SQLite receipt can survive when the helper does not. Supported native Core backup generation/restoration uses four task-owned Core processes and the actual Core startup restore routine; restored configuration and retirement of grants/delegations are verified. This is not HAOS/Supervisor, filesystem power-loss or production restore acceptance.

Connected native covers automation/script CRUD/fault trace/repair, eight helper families, storage dashboard metadata/rollback, synthetic light/switch/cover/media state/services, calculated integration reload, configuration checking and local backup creation. Credential/reauth/integration-reconfigure, arbitrary custom integration repair, Supervisor/add-on/OS maintenance and full physical outcomes remain unsupported adapters/acceptance gates; no manual YAML substitute is counted as implementation.

### Validation, adversarial review and durable delivery

Recovered HEAD7603213; reviewed source14fca17 and owner amendmentb2dc4eb are ancestors. Source14fca17→delivery7603213 differs only by the eight-line implementation-plan receipt. PR2 was open/draft/unmerged and the initial working tree was clean. No descendant or dirty work was discarded, reset or force-pushed. Protected Blueprint and both HAOS workflow bytes remain identical. Historical engineering source and native approval/write workflows are preserved.

Baseline reproduced in this assignment: **30 native /489 Phase2L /626 broader passing**, one optional legacy HA selector skip. **Final fresh-source validation:42 native tests passed (110.188s),489 Phase2L passed (0.706s),633 broader passed (6.74s), one optional legacy HA selector skip and296 subtests.** Compilation, JS/installer syntax and checkout isolation passed. One selected actual browser test failed before panel execution on the supplied sandbox; a user-namespace sandbox attempt also reported no usable sandbox. Fresh-checkout validation, failed browser evidence, dependency/protected-file checksums and source hashes are in [NATIVE_ADMIN_EVIDENCE.json](NATIVE_ADMIN_EVIDENCE.json), a compact committed receipt rather than an inaccessible session archive. Intermediate failures (fixture body assertion, boundary count, listener restart method, changed restored caller scope) were corrected and rerun; they are not independent passing coverage. The final documentation receipt records source SHA separately from delivery SHA.

A separate read-only adversarial source pass found and corrected debug credential leakage, restored-delegation revival on supported restore, repeated-cancellation orphan risk, unbounded KILL reaping, candidate-epoch rollback failure, late updater revival, oversized output pipe failure, missing Core-stop ownership cleanup, failed-setup tail cleanup and nonadmin access to tunnel lifecycle services. Connected tests exercise corrected application boundaries; injected syscall/reaping faults are explicitly synthetic. This self-review is not independent security certification. Remaining native CAS/allocation limitations and externally restored authority are not marked fixed by mocks.

Reproducible setup is checked in at [scripts/development/install.sh](../../scripts/development/install.sh) and [start.md](../../scripts/development/start.md), relocated from the existing unpublished environment logic. It accepts reviewed descendants/dirty work, rejects main or wrong ancestry, never overwrites changes, uses external caches/task state, preserves TLS/hash checks and the authoritative Phase2L upstream pin. Production operation has no dependency on GitHub HEAD. No environment publication occurred.

Before the normal push, inspect existing automatic workflow triggers. This public repository uses existing nonprivileged standard GitHub jobs; no workflow dispatch/retry/VM/probe activation, paid purchase, production change or merge is authorized. The only workflow changes extend the existing bounded native development job's source paths/syntax checks. Actual final-SHA CI status must be read separately from baseline/historical runs; unavailable/pending/failing packaging is not PASS.

### Immutable source receipt for this candidate

Source revision: [`a7ad7a6a3362262e0a5f3b8d8a04998106d42acc`](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/commit/a7ad7a6a3362262e0a5f3b8d8a04998106d42acc), including implementation commit `be98efe` and a normal-history installer EOF/checksum correction. Final native source/test bytes passed the fresh cloned-checkout validation:42 native /489 Phase2L /633 broader, one optional legacy dependency skip. The subsequent EOF-only normalization passed installer syntax, final whitespace and checksum checks; no executable behavior changed. The delivery commit containing this receipt changes **IMPLEMENTATION_PLAN.md only**; derive its immutable SHA from Git history or the final PR report rather than embedding a self-referential commit hash.

Durable sanitized artifacts: [NATIVE_ADMIN_EVIDENCE.json](NATIVE_ADMIN_EVIDENCE.json), [NATIVE_ADMIN_CHECKSUMS.sha256](NATIVE_ADMIN_CHECKSUMS.sha256), capability matrix and operator runbook. Checksum verification passed for every listed source/test/setup/dependency/protected file. The existing 124-package native lock, Blueprint and both HAOS-triggering workflows are unchanged. The final source self-review found no additional confirmed defect beyond the documented native CAS/helper allocation and unsupported restored-state limits; it is not independent certification. Real browser acceptance remains blocked by the supplied sandbox. All six primary documentation hosts remain CONNECT403-blocked; no network/authentication settings were changed.

GitHub CI is to be checked at the delivery SHA after the single normal push, without rerunning jobs, workflow dispatch or privileged/VM activation. Exact observed statuses and run links are recorded in the existing draft PR's description and final report; this receipt does not predeclare CI success. PR2 stays draft/unmerged. Working tree was clean after the source commits; only this receipt is staged for the documentation commit. No real secrets, production, household, real tunnel, paid resource, Probe A or VM operations were introduced.

### Smallest defensible next milestone

Close the supported-object write coordination decision and run the committed owner-panel test on a sandbox-capable browser, while verifying the selected official tunnel NoOAuth/scoped-header deployment against accessible current primary documentation. Do not repeat completed Probe A work. A controlled remote staging proposal then needs independent security review, exact external/internal route reachability and credential custody, hosted ChatGPT/iPhone approval acceptance, approved artifact/backup/recovery and bounded update policy. Native/HAOS/Supervisor, household physical effects and remaining full-administration adapters retain separate gates. Production, Probe A and HAOS/VM execution remain NOT AUTHORIZED / NOT PERFORMED.

## Previous native administrator delivery — preserved receipt

**CANDIDATE INCOMPLETE.** The owner’s practical-product brief supersedes mandatory completion of experimental Probe A S1–S6. This delivery implements a connected administrator, not a read-only replacement, but the missing critical adapters and native authorization limitations below prevent a staging-ready claim. Blueprint section 0 and UX01–12 remain binding; no reduced capability or increased residual risk has been accepted.

### Architecture and maintained target

Use Home Assistant Core **2026.10.0**, official release source `6a811d3359c7b2076dc9e1cf900843a129c044af`, Python **3.14.2**, native `mcp_server`/LLM API extension, MCP **1.28.1**, anyio **4.14.2**, aiohttp-sse **2.2.0** and Core's schema library probatio **0.13.0**. This is one fixed tested target; startup permits the 2026.10 patch series and rejects other series with a useful error. Only 2026.10.0 has been exercised. Any patch/update needs the staged compatibility sequence in [RECOVERY_DESIGN.md](RECOVERY_DESIGN.md). HA2024.6.4 is optional historical compatibility, not the required product runtime; `hacs.json` states the old integration's minimum.

One optional `custom_components/hass_codex_admin` registers supported `homeassistant.helpers.llm.API` tools. HA owns HTTP/MCP, OAuth, normal user/refresh-token identities and lifecycle. The dedicated endpoint is `/api/mcp/hass_codex_admin`. The existing tunnel integration is retained as transport, with static bearer injection rejected for this native endpoint. No new OAuth transport, root helper, watchdog, policy service or upstream fork is deployed. Old ha-mcp8.6 patch candidates and Probe A remain history/test fixtures; no new production module imports them, and there is no fallback to their permissive routes. Their historical failures are preserved below, not converted into PASS.

Native HA OAuth supports discovery, authorization/PKCE, token refresh and revocation. Local tests use synthetic normal native refresh tokens and actual HTTP/MCP authentication; they do not test an actual hosted consent flow. **A native admin bearer also has broader HA API privileges.** The finite tool catalog is not global scope enforcement. A reviewed ingress/identity isolation design that includes OAuth endpoints, followed by wrong-account/alternate-route hosted tests, is mandatory before any remote staging. Client ID metadata is not proof of human presence.

### Connected implementation

Six typed tools: `admin_inspect`, `admin_propose`, `admin_execute`, `admin_status`, `admin_rollback`, `admin_reconcile`. Unknown tools/routes/parameters fail without granting rights or breaking the established session. Reads need no repeated task approval. Writes use one 30–900-second exact plan approval for up to20 operations; before-definitions, targets, complete arguments, indirect effects, rollback scope, caller refresh-token ID and policy hash are bound. Configuration, helper, device and maintenance effects require explicit elevated consent; deletions are destructive. New or indirect scripts/automations are not covered by an ordinary-device allowance.

The separate native owner WebSocket approval channel and local Administrator panel require a live owner normal refresh-token session from an explicit frontend-client allowlist, enrollment, exact task hash and explicit effects confirmation. MCP cannot enroll, approve or invoke arbitrary WebSocket/service/proxy commands. Every actual REST mutation or WebSocket mutation send revalidates caller, grant/hash/expiry/policy and the approving owner session, including dashboard/restore substeps. The actual aiohttp request and LLM user must match the validated native caller. No invented identity claim or secret URL authenticates the user.

A small private stdlib SQLite store persists intent before an external write, operation status, consumption, snapshots and essential audit. Bounded pre-BEGIN contention returns a controlled denial; uncertain transactions/results stay consumed. Writes get one attempt, safe GET gets one bounded reconnect. Readback uses native definitions/HA state, not mutation acknowledgment alone. Canceled background SQL completion cannot overwrite later recovery states. Reconciliation observes configurations without retry or attribution claims. Reverse rollback checks current result before restoring and can restore an applied prefix; inverse deletions check newly introduced references too. All saved pending/approved grants and approver enrollments retire at actual HA boot so restoring a backup cannot revive authority. Results remain history, and replay freshly checks current state for drift.

Fixed native APIs implement automation/script CRUD, eight helper families, storage dashboards including captured metadata, calculated integration reload, exact named basic device control (light brightness/temperature included), Core config validation and local Core backup creation with returned-job/metadata/archive-size correlation. Helper partial edits normalize a full replacement definition into the approved plan; creation collision checks are targeted, and restoration of a renamed helper uses two individually guarded writes under its original ID. Network devices in tests are synthetic native entities; no physical effect is inferred.

### Remaining implementation and API blockers

1. Credential administration, integration reauthentication/reconfiguration, Supervisor add-on restart/update and host/backup restoration need supported elevated outcome/recovery adapters. They are explicitly blocked before mutation, not completed by instructions to paste YAML. Core backup creation is not restore proof.
2. Native configuration APIs have no atomic compare-and-swap, and helper create has no requested-ID reservation. Before/read/send checks and one executor prevent project duplicates but do not eliminate races with independent local administrators. Requested IDs cannot silently alias; unexpected allocation stays uncertain, although it may already have created an unexpected object. This is a release blocker requiring a supported atomic boundary or explicitly reviewed exclusive mutation policy; it has not been accepted.
3. Dependency scanning covers loaded native automation/script definitions and storage dashboards. Unloaded/include/YAML/custom collection dependencies and metadata outside captured definitions are incomplete. Destructive acceptance needs complete supported coverage or an explicit bounded-object policy approved by the owner.
4. Ordinary cover/media commands have outcome rules but lack actual native entity coverage in this delivery; slow/asynchronous effects can remain uncertain. Disjoint device operations work in one task; overlapping device entity scopes are explicitly rejected before any mutation. Global log redaction is not proved. Browser panel rendering, a pre-upgrade installed capability inventory and upgrade/rollback acceptance remain unexecuted.

These are source/coverage limits, distinct from missing production credentials or authorization. Do not call the product complete, silently accept them, or resume obsolete Probe A as their replacement.

### Validation, review and delivery

Connected tests run actual disposable Core/native MCP, native owner WS decisions, fixed HA APIs and real SQLite. Only external protocol/fault boundaries and physical entities are substituted. Services bind loopback; a fixture-only socket guard denies non-loopback DNS/connect/bind/sendto. Synthetic accounts, backups and databases stay in task-owned temporary directories outside Git and are cleaned by fixtures. No production config/token, tunnel, VM, privileged actor or network mutation is used.

Final commands and results are recorded in the source/delivery receipt after validation. The prior **489 Phase2L / 625 broader** baseline is preserved below. Final combined verification after all review corrections: **30 native connected tests, 489 Phase2L and 626 broader passed; one optional legacy HA schema skip; zero failures**. Native suite18–20sec, Phase2L0.67sec and broader5.35sec in the final local run. Python compilation, panel JS/Bash syntax, diff and before/after repository-isolation checks passed. The reusable setup path also repeated successfully with all124 hash-locked modern packages compatible. One measured three-operation native repair used exactly one persisted approval; execution/rollback timings are in the sanitized native log, not a household latency promise. The retained ledger's reported SQLite race was corrected to controlled bounded losing claims, with held-lock recovery and repeated simultaneous races rather than inflated timeouts. The authoritative Phase2L workflow and pinned upstream fixture `fc54437a804858732e4bc927add98e202d879a09` stay intact. The new hash-verified Core fixture lock is development-only; the production component has no separately installed dependencies beyond Core/native MCP manifests.

A separate read-only agent reviewed final authorization, recovery, protocol and compatibility source. Confirmed defects were corrected and connected tests extended: helper reserved selectors/IDs, dashboard metadata, same-object reverse order, final per-send checks, partial-task rollback, redirects/chunked replies, helper replacement/restoration/recreation, plan integrity, delayed completion, inverse-reference checks, disjoint-device task state, drift and boot grant retirement. This is an adversarial source review, not qualified security certification.

Changed components: the new native component and tests/fixture guard/restart runner; hashed development requirements; bounded contents-read-only native Core CI; existing tunnel URL/command guards and tests; retained native ledger race behavior/test; AGENTS.md and the current plan/matrix/threat model/runbook. The Blueprint and original VM/feasibility workflows remain byte-for-byte unchanged. No automatic privileged trigger is added. New native CI uses synthetic loopback data, no secrets and a12-minute budget. Normal Git history delivers to existing draft PR #2, never a competing PR or merge.

Delivery receipts record immutable source SHA separately from documentation SHA and actual D/I/J/K/L, native Core and E/F CI outcomes. Historical E/F registry504 failures and scanner failures are not erased or counted as security review. No paid/manual rerun or quota workaround is authorized. Environment installation/start instructions are tested and saved as a review draft only; publication and fresh-task restoration are separate unverified actions.

### Immutable source and local evidence receipt

Source/test commit: `14fca17f54f364019b6bfa9074d1e016ccb6f92b`, a normal descendant of inspected clean PR #2 HEAD `a5eb4635be6f0ab351be2b1edc4a08224c3735a5` and approved source gate `ad5e0c2ba52901c8384597d3cafd26ce3ffb124d`. This documentation-only receipt changes no source/test/dependency/workflow. Its delivery SHA and actual final-head GitHub runs are recorded in the external sanitized delivery receipt, avoiding a self-hash or repeated CI publication loop. PR #2 stays open/draft/unmerged.

Final local commands: `bash /workspace/.cloud-environment/hass-codex-tunnel-mcp/install.sh --verify`; primary `python3.14 -B -m unittest discover -s tests/staging -p 'test_admin_product.py' -v`; retained `python3 -B -m unittest discover -s tests/offline -p 'test_phase2l_*.py' -v`; bounded offline-network-guarded pytest excluding staging; source `py_compile`/compileall with external bytecode cache; `node --check` and `bash -n`; `git diff --check` and exact protected-file comparison. Final30 native/489 Phase2L/626 broader passed, one optional old-venv HA selector/schema skip. Three-step native script task persisted **one approval**, measured **48.75ms execute /57.36ms reverse rollback** in that local run. No browser/hardware/hosted latency claim. Setup reinstallation/repeat also passed without repository drift.

Transferable evidence includes native/Phase2L logs, broader JUnit result, combined validation log, selected corrected-failure evidence, environment install/start instructions, exact file list, protected hashes and GitHub run metadata. Runtime fixture credentials/config/backups and Git authentication are excluded. The final ChatGPT delivery links the checksum-verified artifact and current runbook. Historical failed VM/probe/scanner/registry outcomes below remain unchanged. New native CI and D/I/J/K/L/E/F must be read at the actual final delivery HEAD; this local receipt does not presume success or trigger manual/paid retries.

### Next milestone and external acceptance

Finish the finite critical adapter/capability gaps above and the exact-route least-privilege architecture before requesting remote staging. No approval is needed merely to continue offline source work; approval is required for a concrete live proposal. That proposal must name exact artifact/configuration, ingress/identity route policy, independent local recovery and verified backup, bounded acceptance checks and rollback triggers. Independent security review, actual hosted OAuth/wrong-account proof, HAOS/Supervisor/add-on acceptance, physical effect tests and separately approved deployment remain gates. Production, HAOS/VM and historical Probe A execution remain NO-GO.

## Historical source/build closeout — 2026-10-10, Europe/Stockholm

**SOURCE_OR_BUILD_INCOMPLETE — EXACT BLOCKERS.** Source/test commit `ce7fd5025c94974bb4c800351759342fff560abe`
continues from inspected owner delivery `b2dc4eb05f5bda4ec9b32d443a1abba505543a2b`,
which changed only the Blueprint after initial `a394c0a...`. Reviewed source stays
`6a5d752...`; approved ancestor `ad5e0c2...` remains. No owner changes were lost.

The reproduced SYS_ADMIN19/21 confusion, inherited socket denial and forbidden
policy-reader path/double decoding are corrected in source. Sealed guardian↔
observer UID-only audit and delayed readiness are connected; signed package/
grant reconstruction, exact FD custody, installed-policy/mount checks, native
role credentials, partial trace source and nested/clone guard contracts are added.
All remain disabled; complete AppArmor/entry/measurement/final evidence/lifetime
wiring is **still missing**, not merely awaiting signatures or live tests.

Final local validation: **489 Phase2L passed; 625 broader passed; one optional
HA schema skip; Python compilation/Bash parse/diff check passed**. Existing C
guard compiled and linked, never loaded/executed. Clang/BPF headers/approved BTF
and AppArmor parser unavailable; no installation or dependency pin changed.
Adversarial self-review and a separate read-only agent pass corrected confirmed
additional defects; neither is security certification.

The finite INT01–03/S1–6 register, exact24 source/test paths, durable sanitized
commands/results/artifact hashes, five-track production matrix, all UX01–12,
owner reliability requirements and unexecuted acceptance/rollback sequence are
in [PROBE_A_CLOSEOUT_2026-10-10.md](phase2l/PROBE_A_CLOSEOUT_2026-10-10.md) and
[PROBE_A_NATIVE_COVERAGE.json](phase2l/PROBE_A_NATIVE_COVERAGE.json).
Source/log artifact SHA256: `5dbbe3c2472b76f812ad41a72f98b146ba30f7392ebfde862d45d0d160dea807`.

No workflow/Blueprint/environment/application/lockfile/production edit;
no private signing material, native execution, VM, live evidence or trusted PASS.
PR #2 remains draft/unmerged. Source CI D/I/J/K/L and E/F SUCCESS; AI scanner FAILURE, not clean independent
coverage. Exact run IDs/merge parents are in the closeout/index. Documentation
receipt and its HEAD/status are reported externally without a self-hash. Final product task grants/caller binding/
final effect authorization and full HAOS/recovery observers remain SOURCE
blockers; a read-only permanent replacement is not accepted.

Delivery-CI correction: docs-only `d22bb09357066c718ad856840c1c78dea5f0d664`
has D/I/J/K/E/F SUCCESS, Phase2L PR SUCCESS but Phase2L push FAILURE
(run38043156777, step4 exit1), and scanner FAILURE. Detailed job logs are blocked
at the storage download host; API metadata works. Cause remains unresolved;
source counts above are local evidence, not inferred CI counts. No test/workflow
change or manual rerun. Exact outcomes remain in the closeout/index, and final
receipt CI is reported externally without an indefinite publication loop.

## Historical implementation records — preserved

Updated 2026-10-10. Repository: Alundqvi97/hass-codex-tunnel-mcp. This work is independent of home-infra-control-plane.

## Historical Probe A remediation and native-source delivery (2026-10-10)

**PARTIAL — EXACT SOURCE OR ENVIRONMENT BLOCKERS.** This assessment supersedes
historical completion/no-confirmed-defect wording below. Source/test revision
`6a5d752412d7452008addcf93d78197322ecd157` continues normally from clean PR #2 delivery
`e483307c3c5ea157068b59c192f6fb0dea27dd1b`, reviewed implementation
`182c8b7c95513b83abc71f2d49ea82adde7ef4fa` and approved ancestor
`ad5e0c2ba52901c8384597d3cafd26ce3ffb124d`. PR #2 remains draft and unmerged.
This documentation receipt is separate; its final GitHub SHA is reported after
commit, with no self-hash and no source/test changes.

INT-01 outer activated-root fail-stop and INT-02 independent cleanup-audit
cutoff authority are corrected through their actual integration paths. INT-03
work/cleanup separation and supervisor failed/cancelled-work retention are
corrected; native all-exit persistence is **partial**, not complete. A separate
adversarial self-review corrected capability/descriptor/claim/signature-purpose
issues; it is not independent certification.

Concrete native source now covers allocation/service composition, protected
asset/source/ELF/alias collection, existing OpenSSL3 signature verification,
durable one-attempt claims and existing-grant validation, seven owned scope
inspection and separate inert provisioning, static policy primitives, bounded
resource/journal/measurement schemas and C hard-deadline source. The exact 20
source/test paths and 22 critical hooks are recorded in
[PROBE_A_NATIVE_COVERAGE.json](phase2l/PROBE_A_NATIVE_COVERAGE.json); actual
topology, manifest workflow and future Linux falsification cases are in
[PROBE_A_NATIVE_PACKAGE.md](phase2l/PROBE_A_NATIVE_PACKAGE.md).

Remaining source defects/implementations are explicit: **S1** post-exec package/
entry loader and exact FD reconstruction/disposal; **S2** guardian-independent
observer UID-audit handoff; **S3** full policy assets/installed inspector, final
caps/groups and supervisor confinement; **S4** kernel trace program/loader/
correlation (clang unavailable, reviewed BTF/ABI/asset missing); **S5** complete
cleanup/emergency/resource collectors and independent final owner/signing
boundary; **S6** mandatory hard-deadline and durable all-exit persistence wiring.
These are source/dependency gaps, not merely missing permission/signatures.

Reproduced baseline **424 Phase 2L / 560 broader passed, one optional HA skip**.
Three baseline integration reproductions failed as expected before correction.
Final local **461 Phase 2L passed; 597 broader passed, one optional HA schema
skip; zero failures**. Python compilation, C syntax only, shell syntax, whitespace
and protected-file checks passed. Logs `/tmp/probe-a-offline.SURlfu`; workflow
reference and pinned upstream `fc54437a804858732e4bc927add98e202d879a09` unchanged.
CI receipts and prior failed L runs are preserved in the new review section;
no CI retry/dispatch or workflow modification occurred. Full native acceptance
was not attempted; synthetic results remain blocked.

GitHub source-revision D/I/J/K/L and packaging E/F: **SUCCESS**. Separate AI
scanning automation: **FAILURE**, with authenticated findings unavailable under
the existing API restriction. This does not provide independent certification.
Exact immutable run links are in the review/JSON register; packaging success
does not authorize HAOS/Supervisor or native OS acceptance.

The next smallest milestone is S1/S2's disabled source-pinned post-exec loader
and independent guardian-observer handoff, with exact offline FD/grant tests.
After source completion: independent review, approved immutable runner/kernel/
confinement policy, external signature trust roots and genuine manifests,
separately authorized provisioning/runtime, actual independent kernel evidence,
and final HAOS/Supervisor acceptance remain required. Do not seek runtime
approval for this incomplete package. No live Probe A, privileged operations,
VM/QEMU, production/tunnel access, packages or environment publication occurred.
All workflows and `PROJECT_DESIGN_BLUEPRINT.md` are unchanged; securely authorized
full Home Assistant administration remains the product requirement.

Probe A execution: UNAUTHORIZED / NOT EXECUTED.
Trusted runtime PASS: UNAVAILABLE.
HAOS/Supervisor acceptance: NO-GO.
Production: NO-GO.

## Historical Probe A OS engineering delivery (2026-10-09)

**COMPLETED — DISABLED OFFLINE ENGINEERING.** Continuation from verified PR #2
HEAD `8ca67a92f224c57c7ea84c2d32a49d4d439d6e32`; approved source gate
`ad5e0c2ba52901c8384597d3cafd26ce3ffb124d` remains an ancestor. PR #2 is draft
and unmerged. The existing 311/447 passing offline baseline was reproduced
before extension; earlier 266-test and phase histories below remain intact.

Source-side A–F interfaces now integrate sealed role entrypoints, actual
kernel-incarnation/deadline/FD handoff, authenticated sequenced readiness,
independent baseline-before-controller release, externally signed dependency
inventory/alias/FD verification, seven distinct inactive containment scopes,
reviewed root/NSS/network confinement contracts and independent evidence
composition. The existing launcher, broker, guardian journals, emergency deny
barrier, irreversible controller drop and no-trusted-PASS gates are preserved.
Default activation remains absent; no CLI, environment opt-in or automatic
privileged workflow was introduced. Every incomplete result remains blocked.

Phase 2L expanded result: **424 passing offline tests**; broader regressions:
**560 passed, one optional schema skipped**. Compilation and whitespace checks
passed. Immutable final source/test commit:
`182c8b7c95513b83abc71f2d49ea82adde7ef4fa`. GitHub D/I/J/K/L and automatic
packaging E/F succeeded on that source; AI scanning automation failed and does
not supply independent review. Exact CI receipts are recorded in the
current `phase2l/PROBE_A_ENGINEERING_REVIEW.md` delivery section. The authoritative
Phase 2L workflow and its pinned upstream commit are unchanged. A separate
adversarial self-review corrected confirmed integration defects; no unresolved
source defect was confirmed, and this is not independent security certification.

**External gates remain:** independent review of the source and trusted native
collectors/factories; approved immutable runner/kernel and reviewed confinement
policy; external signature/verifier trust roots and complete inventory; persistent
one-attempt ledger; separately authorized cgroup provisioning and runtime attempt;
actual independently observed kernel/network/cleanup evidence; final genuine
HAOS/Supervisor acceptance. A read-only root RPC does not prove kernel read-only
privileges. Guardian SIGKILL/runner destruction can leave cleanup uncertain.

**Next smallest milestone:** independent adversarial source/interface review and
a reviewed runner/policy/inventory package. Do not repeat completed remediations.
No live Probe A, VM/QEMU, production/tunnel access or paid retry occurred. All
workflows and full administrator `PROJECT_DESIGN_BLUEPRINT.md` are unchanged.
Securely authorized full Home Assistant administration remains required; a
read-only replacement is not completion. HAOS/Supervisor and production **NO-GO**.

## Phase status

| Phase | Status | Evidence / promotion requirements |
|---|---|---|
| 0 — Audit and baseline | Completed (prior audit) | Source at `def1d7235018745b880b573a944925352dea85a5`, original `mcp_url.py` blob `ad0afdc1d2aaec61390be0a108c8d6a18c853a57`; see SECURITY_AUDIT.md |
| 1 — GitHub and offline validation | **COMPLETED** | Fork/ancestry verified, draft PR opened; baseline 14/14, integration source tests and combined upstream suite passed GitHub CI (see 2026-10-08 receipts below). |
| 2 — Authentication and network security verification | **PARTIALLY COMPLETE / BLOCKED** | Architecture and read-only network inventory documented; isolated representative protocol fixture and synthetic regression tests passed; real HA-MCP POST and approved hosted negative-attachment tests NOT PERFORMED. |
| 3 — Production-ready hardening and rollback | Pending | Independent review, full staging compatibility/upgrade/restart/rollback drill, signed or pinned artifacts, sensitive log audit |
| 4 — Explicitly approved deployment | Pending approval | Backup, restoration copy, change window, authorized exact deployment, automated health gates, rollback rehearsed |
| 5 — Auth0 / Control Plane relationship | Pending | Separate design, no implied shared identity, no deployment coupling |

## Change control and approvals

Authorized: fork development branch, CI, documentation, draft PR, offline tests. **Not authorized:** merge, deploy, Home Assistant restart, router changes, Auth0/OpenAI app changes, credential reads/rotations, OpenClaw invocation.

## Evidence

- Original upstream/fork `main` heads were identical at `def1d72`; GitHub identifies the fork parent and source as `norpol/hass-codex-tunnel-mcp`.
- Original ZIP: `ha_tunnel_hardening_candidate(1).zip`, SHA-256 `b56be95fb58793a91eabc134614767072e42c1b95fc4ea311435b40a82af91e4`.
- 2026-10-08: `git apply --check`, application, exact hardened file comparison, reverse-check/reverse application, baseline restoration all passed offline.
- 2026-10-08: candidate `python -B -m unittest discover -s tests -v` passed 14 tests, including intentional reproduction of vulnerable baseline. Integrated security tests adapted to repository import style: 12 passed locally in isolated environment with the patched module; full repository tests not yet established by this evidence.
- Original tests exercise tunnel-client subprocess logic. GitHub Actions completed a full checkout and test run; see CI receipts below. The HA selector schema test remains skipped due to unavailable `homeassistant` dependency.
- Never store production secrets, URL secret paths or credentials in tickets, CI, or logs.

## Independent security concerns / blockers

1. GET returning 200 or 405 is not proof that backend bearer permits authorized MCP `initialize` / `tools/list`.
2. GET returning 400/405/406 currently stays accepted for compatibility; separate authenticated MCP POST needed.
3. DNS answers may change between URL classification and connection (DNS rebinding); address pinning, network egress rules and IPv6 routing remain unverified.
4. `normalize_mcp_url` accepts query strings; query-based credentials and URL logging are not comprehensively ruled out.
5. `redact_mcp_url` preserves scheme and authority (including host/port); avoid returning exception text that includes sensitive URLs.
6. Default proxy environment and request forwarding deserve separate review; this patch only blocks redirects for its `urllib` GET probe, not tunnel-client network behavior.
7. TCP 9583 direct LAN exposure; zone isolation and any exceptions require read-only inventory and independent negative reachability tests before modification.
8. Hosted OpenAI tunnel attachment authorization, per-user identity, HA least-privilege policy and long-lived credentials are not verified.
9. Check that Home Assistant config/setup errors and child process logs never disclose secrets; test malformed or unreachable endpoints.
10. Do not assume automatic tunnel-client binary updater rollback covers HA integration source rollback.

## Promotion and rollback

- Review threat model and `ROLLBACK.md`; preserve exact current HACS source and rollback artifacts before any install.
- Do not promote until full upstream pytest suite passes on clean checkout, staging backend auth tests and hosted attachment denial are confirmed, and HA restoration access remains independent.
- Explicit deployment approval must identify commit SHA and rollback criteria. Abort on lost MCP connectivity, failed auth requirements, changed exposed admin tools, unexpected network reachability or HA repair errors.
- Phase 2/3 findings must be appended here with dates, evidence, failures and approvals; status is not automatically advanced by CI alone.

## GitHub CI acceptance receipt — 2026-10-08

- Branch CI: [run 37834479131](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37834479131) completed **success** on Ubuntu 24.04 / Python 3.12.
- Exact pytest summary from runner job 113507892161: **43 passed, 1 skipped, 2 subtests passed in 3.98s**. Python syntax compilation and CI guard steps also succeeded.
- The skipped test requires review; it does not change Phase 2 staging/authentication requirements.
- Draft PR [#1](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/pull/1) was opened against fork main; no merge or production change.
- Phase 1 offline GitHub-preparation acceptance satisfied subject to an independent security review of residual findings. Phase 2 remains pending. Re-check CI after any additional commit.

## Phase 2 execution receipt — 2026-10-08

**Current disposition: PARTIALLY COMPLETE / BLOCKED.** The working production Home Assistant connection was not changed. No hosted negative-access tests, production device calls, production port scans, credentials, Auth0 updates, router changes, process restarts, or Control Plane modifications.

### Completed tasks and evidence

- Independently inspected latest draft PR #1, source, docs, workflow and previous CI; corrected stale Phase 1 table status.
- Official OpenAI Secure MCP Tunnel guide documents org/workspace associations and separate Tunnels Read/Use requirements. Whether an unauthorized identity can attach to **this** tunnel was not tested; the label No Auth does not establish either public accessibility or successful denial.
- Read-only HA Core 2026.10.0 / HA-MCP app 8.6.0 / tunnel integration loaded; app policies, redaction and strict best-practice checks on; `enable_security_policy_tool=false`; `read_only_mode=false`; `disabled_tools` empty; token/key configuration presence confirmed but values never collected or written.
- Read-only UniFi survey: Home, IoT, Guest, VPN; 113 policy records; HA-MCP add-on `host_network=true` and 9583/tcp published. No live IPv6 listener or inter-VLAN negative reachability testing.
- Added `AUTHENTICATION_ARCHITECTURE.md`, `NETWORK_EXPOSURE.md`, `PHASE2_TEST_EVIDENCE.md`, `PHASE3_READINESS.md`. Extended audit, threat model, rollback. Do not promote from documentation alone.
- Isolated representative MCP JSON-RPC fixture exercises POST `initialize`, `tools/list`, read-only `tools/call`, and missing/wrong/expired/revoked/scopeless credentials. These are **simulated fixture contracts, not actual HA-MCP/tunnel-client behavior**.
- Source-level fake tunnel-child exit test demonstrates current watcher does not automatically relaunch. The health-URL-file sentinel is not full readiness.
- Identified legacy URL redaction userinfo leakage; development-branch source fix and security regression tests added. **No deployment.**
- Relevant new full-checkout CI [PR run 37835878059](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37835878059) at commit `eacf8a4a21380447f3b3390ca8c04a9d42cb19f0`: **57 passed, 1 skipped, 2 subtests passed in 4.82s**, syntax+guard steps successful. The skipped test was `tests/test_config_flow_schema.py`, because `homeassistant.helpers.selector` cannot be imported (`No module named 'homeassistant'`); that runtime integration compatibility remains unverified. Later documentation commits need their own CI receipts.
- CI had one intermediate FAILED run due to a malformed source line in the initial redaction edit (4 failures, 53 passes on a previous intermediate commit); immediately corrected on the development branch. **Do not claim every intermediate run passed.** Subsequent source+tests CI succeeded (above). GitHub workflow uses pytest `-rs` to reveal skip reasons.

### Risk and decision register

| Risk / uncertainty | Priority | Evidence / decision |
|---|---|---|
| Hosted cross-account/cross-workspace authentication denial, revocation, replay, scope | **HIGH risk, unverified** | Requires authorized disposable hosted tunnel/test identity; cannot infer from docs alone |
| Backend bearer is actually validated by standard-mode HA-MCP on every MCP POST | **HIGH risk, unverified** | Current HA-MCP docs describe the secret path as the credential. Require real staging backend tests; do not overstate bearer strength |
| Policy engine actual rule coverage and alternative invocation routes | **HIGH consequence, not audited** | No read-only policy-rule export exposed; obtain trusted rule inventory before changes |
| Port 9583 Home-LAN direct access, IPv6, other VLANs/WAN paths | **MEDIUM, partial evidence** | Propose host-side isolation after loopback and out-of-band rollback proof; never rely solely on router inter-VLAN rules |
| Child-process crash without integration relaunch | **MEDIUM availability, source/test confirmed** | Design bounded self-healing with independent status and alerting in Phase 3; do not restart production now |
| Child stdout/stderr logged verbatim; secret exposure conditional | **MEDIUM conditional** | Require fake-secret logging/scrubbing verification; do not export production logs |
| Diagnostic URL legacy userinfo echoed | **MEDIUM conditional, fixed in unmerged branch** | New source test + narrow fix. Full CI must be green before merge review |
| DNS rebind, proxy, TLS redirect downgrade and raw binary behavior | **NOT VERIFIED** | Isolated staging with exact v0.0.15 binary required |

### Required separate approvals / next actions

1. **Hosted authorization:** permission to provision a disposable OpenAI test tunnel and distinct test identities, with independently confirmed zero-cost/no-billing effect and permission to run the nine negative attachment cases. Do **not** test unauthorized access against production.
2. **Real HA-MCP staging:** permission to launch a disposable isolated copy of the real HA-MCP service with synthetic tokens, no production HA URL, and a test-only tunnel-client where necessary; if paid resources or external credentials would be needed, stop.
3. **Policy and network:** read-only export of exact effective HA-MCP tool-security rules and network listener/IPv6/NAT inventory from a safe out-of-band interface; production negative network probes require approval and approved devices.
4. **Phase 3 hardening:** plan pinning, backoff/recovery, tested multi-layer redaction and independent local console before any production rollout.

**Security recommendation:** Continue Phase 2 offline planning and retain the PR as draft; do not merge or deploy. Phase 3 production readiness is **NO-GO**. Treat OpenAI association as documented behavior and the HA-MCP secret URL as a credential; neither substitutes for negative authorization evidence. Keep the Home Infra Control Plane separate.


## Phase 2B pinned-source verification — 2026-10-08

**Current phase:** Phase 2 PARTIALLY COMPLETE/BLOCKED. **Phase 3 deployment: NO-GO.** No live test or host/network mutation authorized.

- Source of exact HA-MCP v8.6.0 release tag: annotated `v8.6.0` → commit `fc54437a804858732e4bc927add98e202d879a09`. Running image digest has **not** been compared to the tag.
- **VERIFIED SOURCE:** standard-mode add-on URL secret path is its inbound access credential. `start.py` exports the Supervisor token for outbound Home Assistant API calls; it does not install incoming backend bearer validation. Extra tunnel header is not a verified independent security boundary.
- **VERIFIED SOURCE:** `Policy.rule_effect` defaults to `require_approval`, whose unmatched calls run without approval. A corrupt policy fails closed only when the middleware is registered. If policy middleware import or registration fails, `server.py` logs its absence and continues **without gating**.
- **VERIFIED LIVE:** read-only attempt to inspect effective policy over add-on's `GET /api/policy/config` returned HTTP 403. No policy rules were extracted. Do not claim the live rules are effective based solely on `enable_tool_security_policies=true`.
- Network: v8.6.0 `start.py` binds `MCP_HOST` or default `0.0.0.0`; actual production listener and IPv6/whether loopback-only is possible without breaking Supervisor ingress are not established.
- Four Phase 2B artifacts: `BACKEND_AUTH_VERIFICATION.md`, `TOOL_POLICY_MATRIX.md`, `HOSTED_AUTH_TEST_PLAN.md`, `RECOVERY_DESIGN.md`. Separate recovery source work from narrow auth hardening.
- **Blocked:** actual isolated 8.6.0 server MCP POST test, hosted unauthorized negative test requiring explicit approval and possible billing, effective tool policy read, out-of-band recovery verification, and staged crash/update simulations.
- **Cost:** no resources created or charged. Tunnel/test-account costs have **not been verified**; any future hosted testing requires user-approved budget and exact permissions.
- **Decision:** Do not merge/deploy PR #1. Prioritize out-of-band policy read, isolated true HA-MCP transport behavior, and then approved disposable hosted validation. A synthetic fixture cannot substitute for the real implementation.

Evidence: exact implementation links and risks in `BACKEND_AUTH_VERIFICATION.md`, `TOOL_POLICY_MATRIX.md`, and `PHASE2_TEST_EVIDENCE.md`. No Phase 2B end-to-end tests are claimed passed.


## Phase 2C acceptance — 2026-10-08

**Phase 2C scoped real-implementation staging: COMPLETE.** **Overall Phase 2: PARTIAL/BLOCKED. Phase 3 deployment: NO-GO.** No production, hosted tunnel, credential, router, HA/Supervisor, Auth0, Home Infra Control Plane or OpenClaw mutations.

- Upstream HA-MCP v8.6.0 exact commit `fc54437a804858732e4bc927add98e202d879a09` executed in separate GitHub Actions job using Python 3.13, `uv==0.12.20`, upstream `uv.lock`, `pytest==8.4.2`, in-process Starlette ASGI and only synthetic read-only tools. Runner blocked outbound IPv4/v6 sockets. See `ACTUAL_HA_MCP_STAGING.md`.
- [First complete 38-test real-source staging CI #37838397155](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37838397155) on commit `ef86dfdb6752c5a40cbee88d32e809e5d04093f3`: **38 passed, zero failed, zero skipped**; parallel tunnel job **57 passed, one skipped, two subtests**. Later documentation commits require fresh CI receipts. One previous test harness failure caused by an incorrect import monkeypatch was corrected; no production issue.
- **CONFIRMED STAGING:** Genuine standard-mode FastMCP `initialize`, `tools/list`, synthetic `tools/call` all accept correct secret path with missing, incorrect, arbitrary, malformed and “expired-like” bearer values; wrong path rejects independent of header. Header is not an independently enforced authorization layer.
- **CONFIRMED STAGING:** Pinned middleware/evaluator default missing/empty rules allow unmatched calls. A direct-tool approval rule does not cover generic alternatives. Raw `ha_call_service` and `ha_bulk_control` alternative tool names must be separately covered. Corrupt policy with middleware installed fails closed, while synthetic import/registration failures in server setup are swallowed and leave middleware absent.
- **CONFIRMED SOURCE/OFFLINE:** Pinned add-on startup logs the complete secret path; synthetic secret reproduction through its actual `log_info` sink passed. Do not inspect/export real production logs.
- **VERIFIED LIVE read-only:** Add-on 8.6.0 started, boot auto, watchdog enabled, auto-update true, host network true, TCP/9583 configured; authorized metadata did **not** expose container image digest or runtime bind address. The policy-read HTTP 403 from Phase 2B remains an explicit boundary.
- **Unverified:** Full Supervisor add-on runtime/image digest, actual live effective policy rules, OpenAI hosted cross-account attachment negative tests, actual v0.0.15 binary transport, IPv6/VLAN negative reachability, outage/reboot/rollback, production per-tool behavior.
- **Decision register:** Keep tunnel patch in draft PR #1; no HA-MCP source modification inside tunnel repo. Document upstream fail-closed proposal and startup redaction separately in `POLICY_FAIL_CLOSED_REVIEW.md`/`SECRET_LOGGING_REVIEW.md`. Keep self-healing work separately staged in `RECOVERY_DESIGN.md`.
- **Required approvals:** Any new hosted test identity/tunnel or spending, any production config/network/service change, or a new HA-MCP upstream fork/patch PR. Nothing needed to keep draft PR and current HA system unchanged.

**Minimum safe next step:** Before production install, establish independent local HA/console recovery and a sanitized effective tool-policy read through a supported authenticated admin interface, then plan approved hosted attachment negative tests. The verified bearer non-enforcement and policy initialization fail-open remain high-priority hardening decisions.

### Final Phase 2C CI receipt after action-SHA pinning

- [GitHub Actions run #37838837823](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37838837823), commit `abc06640a6846b00abffdb27bc23177a28b43dc8`: both `pinned-ha-mcp-staging` and `offline-tests` completed **SUCCESS**. Pinned real HA-MCP **38 passed, 0 failed, 0 skipped in 2.72s**; tunnel suite **57 passed, 0 failed, 1 skipped, 2 subtests passed in 5.01s**.
- SHA pins were independently resolved through GitHub metadata: `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (v4.2.2) and `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` (v5.6.0); staging upstream source SHA and runtime dependency lock remain pinned.
- The skipped original config-flow test requires `homeassistant.helpers.selector` not installed in lightweight integration runner. It does not invalidate tested standard-mode FastMCP authentication and policy behavior. Testing the installed Supervisor image remains a separate acceptance criterion.
- This documentation-only commit will itself trigger CI; check its status independently rather than assuming it passed. **No permission to merge or deploy is implied.**

## Phase 2D review work — 2026-10-08

Status: OFFLINE REVIEW IN PROGRESS. Overall Phase 2 remains partial; Phase 3 deployment is NO-GO.

A separate branch, `security/ha-mcp-phase2d-candidates`, preserves the existing tunnel draft PR #1. This branch contains reproducible, SHA-guarded HA-MCP v8.6.0 server and startup-log patch candidates, isolated test cases, and a GitHub Actions workflow. It does not contain a production installation, hosted experiment, or upstream change.

The initial complete isolated candidate CI run, [37840487066](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37840487066), reported 38 baseline tests passed, 19 candidate tests passed and 20 selected upstream tests passed. Both candidate source files were reverted to their verified original Git blob hashes. Additional hardening of the top-level policy initialization error and independent candidate tests require separate final CI verification.

Live read-only metadata confirms policy feature enabled and the HA-MCP add-on running, but does not expose the effective rule list. The prior documented settings API attempt returned 403 and remains respected. The authorized next route for review is the Home Assistant add-on's Open Web UI used by a local administrator; production policy enforcement is not yet verified.

See `docs/security/phase2d/REVIEW.md`, `POLICY_BASELINE.md`, and `ARCHITECTURE_DECISION.md` for implementation, limitations and recommendations. Do not merge, deploy or alter network or credentials without explicit separate approval.


### Phase 2D offline acceptance receipt — 2026-10-08

**Phase 2D offline engineering: COMPLETE within pinned-source scope.** Overall Phase 2 remains PARTIAL/BLOCKED, Phase 3 production remains NO-GO.

Latest independently verified code-and-doc CI: [run #37840801696](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37840801696) at `7422074212f74bd991aefb7c3c6adbe792e5b797`, **SUCCESS**:
- Unmodified pinned HA-MCP real-source baseline: **38 passed**.
- Policy candidate alone: **14 passed, 5 deselected**.
- Logging candidate alone: **5 passed, 14 deselected**.
- Both candidates combined: **19 passed**.
- Selected upstream unit/add-on tests: **20 passed**.
- Policy and logging changes reversed **independently** and together using `git apply -R`; restored exact upstream source Git blobs `bf848d...` and `88e926...`.

Policy candidate now includes sanitized fail-fast at real `_initialize_server` gate boundary; tests demonstrate exception before server run or ASGI mount. Distinguish this from an unperformed full Supervisor boot and an unperformed real MCP admin call on an installed image.

Correct source and test locations: `docs/security/phase2d/patch_candidates.py` and `tests/staging/test_phase2d_candidates.py`. New workflow: `.github/workflows/phase2d-candidates.yml`. Separate draft PR against the security branch; tunnel PR #1 unchanged. Earlier intermediate CI failures were resolved; full logs retained in GitHub.

**Blocked for production:** effective policy rules (authorized API 403), packaged add-on/hosted attachment, host bind/IPv6, secret leakage through unexamined sinks, independent local recovery and deployment approval. No production change occurred.

The CI result above predates this documentation-only receipt and must not be represented as the final HEAD CI until a later workflow run completes.

## Phase 2E execution — 2026-10-08

**Overall:** Phase 2 PARTIAL / Phase 3 production NO-GO. All work on existing fork's stacked draft PR #2; PR #1 unchanged. No production or hosted-resource changes.

### Production policy evidence (VERIFIED LIVE, user screenshots)

- The two PDF captures of the supported HA-MCP 8.6.0 administrator policy UI show 18 distinct configured named-tool rules; all visibly set unconditional approval, zero-minute single-shot retention, and no argument predicates. Names and operation-class gaps: `phase2e/POLICY_INVENTORY.md`.
- Important generic administrative routes `ha_call_service`, `ha_bulk_control`, `ha_manage_addon`, `ha_manage_backup`, `ha_restart` are **not among the pictured rules**. The connected connector lists 79 methods; this is not an independently verified complete deployed catalog.
- Policy `rule_effect` selector and successful startup of middleware **not visible**; approval UI configuration is not runtime enforcement evidence. Earlier supported GET endpoint returned HTTP 403; respected without bypass.
- **Critical migration finding:** the current named approval rules would turn into automatic ALLOW rules if `rule_effect` changed to `allow` while reusing the same entries. Exact pinned evaluator regression verifies this. Requires a new, reviewed positive allow-list and explicit safe migration.
- No screenshots/private HA configuration/secret routes uploaded to GitHub.

### Packaged-staging investigation (VERIFIED PACKAGED where explicitly noted)

- Exact upstream v8.6.0 Dockerfile, pinned base image digests, `uv.lock`, start.py and installed package used in disposable GitHub Actions Docker build; runtime always `--network none` and has no published host port, only dummy Supervisor token and synthetic file fixtures.
- **VERIFIED PACKAGED build** and real installed version = 8.6.0. Container startup and MCP initialize request succeeded in isolated smoke test; first logging-candidate package run then FAILED because collected logs still contained a synthetic secret. This was not detected by earlier source-only tests.
- Source review identified FastMCP startup banner and Uvicorn access logger as additional potential disclosure paths. Logging candidate now disables banner and access logging; latest build+negative-log CI must pass before declaring leak remediated at packaged level.
- Synthetic container fixture initially had a test-volume PermissionError because capabilities were dropped, fixed without weakening production. No Supervisor/HAOS instance or real production administrative tool was used.

### Source quality changes and blocked supported configuration

- Policy candidate now rejects unknown strict flag values, strict-mode failed policy migration and unconditional bare wildcard allow; test explicitly proves mode inversion. Full source tests and clean reverse patch remain required after latest candidate edits.
- Stable Supervisor `config.yaml` has no supported `HA_MCP_REQUIRE_STRICT_POLICY` option; manually injecting env on production is not acceptable. Dedicated `phase2e/STRICT_OPTION_DESIGN.md` specifies durable opt-in, startup export, migration marker, validation and strict persistence across reboot. **Implementation not deployed or verified in Supervisor**.
- Recovery: 39 backups appear in read-only snapshot list, but newest labels are 2026.9.4 vs Core 2026.10.0; a recent compatible recovery point and out-of-band restore have NOT been proved. Add-on boot/watchdog/ingress metadata confirmed read-only, not a restart test.
- Network: host-network TCP/9583 exposure and Supervisor ingress dependencies mean binding solely to loopback may break the UI. See `phase2e/RECOVERY_AND_NETWORK.md`. No scans or firewall changes.

### Approval-dependent gates

1. Screenshot of policy mode and evidence of effective rule handling/approval flow through supported HA administrator UI, without secrets or user-specific PINs.
2. Supported strict add-on option and safe new allow-list migration, packaged Supervisor/HAOS boot/recovery, synthetic log/error capture in complete startup/requests.
3. Independent local recovery and verified current-version backup before any upgrade.
4. Hosted OpenAI unauthorized-attachment testing with separately approved cost/budget and test identities. No hosted resources created.
5. Explicit approval for any change to actual HA, add-on, tunnel, UniFi, Auth0 or Home Infra Control Plane.

### CI integrity

Phase 2D historical final: [run 37840980382](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37840980382) successful. Additional Phase 2E workflow: `.github/workflows/phase2e-packaged.yml`. Earlier packaged negative log test FAILED by detecting synthetic credential; *never claim this gate passed unless a later exact-head run reports success.* Read final run jobs/logs after final commit before assigning any acceptance.


### Phase 2E final offline/package receipt (2026-10-08)

**Phase 2E authorized engineering scope: COMPLETE. Overall Phase 2 PARTIAL/BLOCKED; Phase 3 deployment NO-GO.**

- User-provided official HA-MCP UI screenshots: 18 visible named unconditional approval rules, approval retention 0 min; broad service/bulk/admin methods absent from photographed rule list. Effect mode / actual middleware runtime still not independently shown. See `phase2e/POLICY_INVENTORY.md`.
- Verified pinned Docker build and real installed `/start.py` at 8.6.0 with `--network none`, dummy Supervisor credential, synthetic options/policy and no published ports: [packaged CI #37843820868](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37843820868) SUCCESS. Seven scenario outcomes: 2 healthy (normal valid and same-volume restored), 5 fail-closed (missing, empty, corrupt, disabled-engine and invalid-on-same-volume). All seven passed synthetic-path negative log scans.
- Real source and independent candidate checks: [CI #37843820900](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37843820900) SUCCESS; 38 baseline passed, 18 policy passed, 8 logging passed, 26 combined passed, 20 selected upstream passed; code patches reversed separately and together to exact original Git blobs. These counts are test groups, not 110 unique independent tests.
- Initial packaged logging FAIL found synthetic path leak beyond the first logger filter. Reviewed pinned FastMCP transport logging and revised candidate with banner/access-log suppression plus late-handler-safe record-factory scrubbing. The final packaged log tests passed within collected synthetic-run scope; no Supervisor-wide claim.
- Backups (read-only): 39 recorded, newest labeled HA 2026.9.4 versus running 2026.10.0; no compatible current-version restore established. Add-on auto-start/watchdog and admin UI are observed, but independent local console restore unverified.
- **Strict enablement remains NOT DEPLOYABLE**: stable Supervisor add-on schema lacks the mandatory policy option, no durable marker prevents a corrupt options fallback, and toggling existing approval rules to allow would invert destructive rules. `phase2e/STRICT_OPTION_DESIGN.md` documents a future supported implementation and migration. No production changes.
- Network host binding, direct TCP/9583 isolation, IPv6, actual hosted-identity denial, HAOS packaged boot/recovery, third-party log sinks and policy middleware production initialization remain additional gates.
- Exact source and packaged results, limits and earlier failed tests are in `phase2e/PACKAGED_STAGING.md`. No hosted resources or real credentials accessed.

No phase promotion implies merge or deployment. Keep stacked PR #2 draft, with PR #1 unchanged. After this documentation commit, verify GitHub CI again before claiming latest HEAD passed.


## Phase 2F — Safe policy migration and supported strict-option engineering (2026-10-08)

**Engineering status PARTIAL:** Real pinned-source and packaged tests PASSED, but nested dispatch, approval lifecycle, HAOS/real Supervisor and local recovery gates remain unverified. **Overall Phase 2 PARTIAL/BLOCKED, Phase 3 NO-GO, Phase 4 NOT AUTHORIZED.** No production changes, merge, resource creation, credentials or router changes.

### Live security observation
- New user-provided official policy-mode screenshot confirms **Require approval**. The 18 visible per-tool rules are unconditionally approval-required with 0-minute retention; actual middleware startup success remains unverified.
- In require-approval mode, unmatched tools automatically run. Broad service, bulk, restart, backup and integration operations are not pictured among the approval rules. Do not treat absent screenshot rules as proved unprotected without full policy/runtime inventory.
- The dangerous mode inversion has now been tested against all 18: those same rules in `allow` mode would automatically allow destructive calls. No in-place conversion is acceptable.

### Changes added to PR #2 branch (not upstream or production)
- `docs/security/phase2f/strict_addon_candidate.py`: source-SHA-guarded, separately reviewable extension to the prior Phase 2D candidates, targeting only `homeassistant-addon/config.yaml`, `start.py`, and `src/ha_mcp/server.py`.
- Supported add-on boolean `require_strict_tool_policy` (default false); opt-in exported to runtime, original behavior retained when not enabled. First opt-in creates `/data/strict_policy_required.v1.json` atomically with mode 0600. Subsequent corrupted/missing settings, false option, invalid policy or failed security engine refuse startup.
- Real server per-call provider rechecks strict read-only positive allow-list. Initial auto-allow list only `ha_get_overview`; all existing destructive and generic control routes are approval-required, not HARD DENIED. Future convenience rules need independent argument/schema tests. A trusted administrator capable of deleting both marker and options can defeat the marker; it is **not** TPM-style anti-rollback.
- `tests/staging/test_phase2f_migration.py`: real evaluator and startup preflight; tests 18-rule inversion, unknown tools, broad routes, raw WS evaluator behavior, options/marker damage, restricted service calls and post-startup policy mutation.
- `tests/staging/phase2f_packaged_smoke.py`: network-isolated real upstream Dockerfile, dummy Supervisor token, synthetic read-only requests. Root-owned 0600 marker inspected in a second read-only offline container; synthetic administrator recovery of root-owned policy via another isolated container.
- `.github/workflows/phase2f-strict-addon.yml`: pinned source/dependencies and exact three-file reverse-patch restoration, no production secret or public listening port.

### Verified executable evidence
- [Phase 2F CI #37846398572](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37846398572), code commit `36a011523bc05fe1328a2b5f6fc1e4564865bb91`: **26 prior Phase 2D tests passed, 42 new migration tests passed, 20 selected upstream tests passed, 9 packaged scenarios passed**, synthetic path log scans passed, three exact upstream original Git blobs restored.
- Intermediate candidate failures (test ordering, Phase 2D compatibility sequencing, early ha_mcp import at preflight, fixture root-owned marker/policy access) are documented in `phase2f/STRICT_MODE_TEST_RESULTS.md`; do not claim these runs passed.
- [Safe replacement policy and full 18-rule comparison](phase2f/POLICY_MIGRATION.md), [test receipt](phase2f/STRICT_MODE_TEST_RESULTS.md), [release decision](phase2f/RELEASE_GATE.md).

### Recovery/approval boundaries
- Read-only backup inventory: 39 backups; newest October 8 protected automatic backup includes Home Assistant+database, version field `2026.9.4`, while Core reports `2026.10.0`. Backup metadata alone cannot certify a current-installation restore.
- Actual local console/Supervisor access, full installed-image version provenance, HAOS update rollback, hosted OpenAI unauthorized attachment, direct LAN/IPv6 listener isolation, and production tool policy enforcement remain unverified.
- No additional screenshot is required for the **mode**, which is now established. Do not solicit secrets, PINs or raw policy config. Next best engineering gate is isolated Supervisor/HAOS configuration roundtrip/recovery **with explicit approval and independence from the tunnel**.

**After this documentation update, recheck CI for final HEAD. No merge/deployment authorized.**


## Phase 2G — Supervisor feasibility, real middleware enforcement, convenience, recovery (2026-10-08)

**Phase 2G status: PARTIAL / explicitly blocked at genuine Supervisor staging, full nested backend and restore. Overall Phase 2 PARTIAL/BLOCKED; Phase 3 NO-GO; Phase 4 no authorization.** No production changes or PR merge.

### Completed within authorized review scope

1. Verified final baseline at `befb3c8c97ba3bcfa5d8286826602fa787b5bcfe`: [Phase 2F #37846837038](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37846837038), [Phase 2E #37846837067](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37846837067), and two Phase 2D push/PR tests all SUCCESS. PR #1 draft, unmerged, unchanged; PR #2 draft and stacked against #1 branch.
2. Ran [read-only GitHub hosted VM feasibility #37847835408](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37847835408): ephemeral runner 4 vCPU, 15.6 GiB RAM and 87 GiB observed root free; `/dev/kvm` exists but inaccessible, QEMU/OVMF not preinstalled. Real HAOS VM would require separate authorization for a new VM, runner privilege/package modifications and pinned guest image download. **No guest, Supervisor, host change or external resource created.** See `phase2g/SUPERVISOR_FEASIBILITY.md`.
3. Inspected pinned actual `PolicyMiddleware`, `ApprovalQueue`, `CategorizedSearchTransform`, policy handlers and developer-mode approval guard. Added genuine in-process FastMCP synthetic final dispatch and proxy tests. **Found a real source bug:** after waiting, an approved synthetic action could execute even though policy file had become corrupt. Reproduced with failing regression [#37848286990](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848286990) (11 passed/1 failed by design). Review-only narrow patch `phase2g/middleware_revalidation.py` revalidates current policy immediately before the approved request reaches the terminal tool. [Passing acceptance #37848485823](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848485823): 196 baseline upstream policy tests; 13 new synthetic FastMCP tests; 194 patched applicable upstream tests with two intentional incompatible historical cases deselected; exact original middleware Git blob rollback. **The two excluded historical tests must be rewritten before upstream merge.**
4. Prepared separately scoped, synthetic, conservative everyday-read proposal in `phase2g/CONVENIENCE_POLICY.md` and evaluator tests `tests/staging/test_phase2g_convenience.py`. Auto-allow only status/selected non-sensitive read operations after review, not generic actuator tools. A general `ha_call_service` light-turn-on rule accepts additional uncontrolled `data` keys in the evaluator; no safe generic automatic operation permission claimed. Check the latest Phase 2G CI for actual convenience pass count.
5. Read-only production backup metadata: 39 backup records; latest October 8 protected Core+DB entry labels 2026.9.4 even though Core currently 2026.10.0. Official Supervisor source confirms field is the Core version recorded in the backed-up Home Assistant section, *not backup format*. Add-on/tunnel inclusion cannot be inferred from list; local+Google Drive are locations, not verified separately restorable archives. No backup opened, downloaded or modified. Recovery drill design: `phase2g/RECOVERY_BACKUPS.md`.
6. Created `phase2g/RELEASE_MANIFEST.md` for source/image/tunnel revisions, update hazards, rollout/rollback triggers and missing authorization. Production HA-MCP metadata `auto_update=true` remains unchanged: a future automatic add-on update could overwrite a custom hardened image or ignore mandatory policy marker; needs supported pinning/update procedure during an explicitly approved deployment window.

### Security decision

- Tested candidate default strict list remains exactly `ha_get_overview`; no automatic generic service, bulk, restarts, locks, security camera privacy or add-on/backup changes.
- Genuine hard deny does not exist in the current policy evaluator. Use tool removal, scoped backend identity or separately reviewed server-side final-operation enforcement for irrevocable prohibitions.
- Approval management developer tool requires developer-mode registration and a separate default-off policy-access flag for approve/deny; actual production registration status is not independently known.
- Middleware revalidation happens immediately before tool dispatch but is not an atomic Home Assistant-side authorization across future asynchronous operations.

### Blockers / next gate

**Priority:** explicit approval, if wanted, for a temporary GitHub-runner-only KVM permission change, QEMU/UEFI package/image download and isolated HAOS VM creation. This is the first environment capable of proving Supervisor schema, boot, watchdog, local access and full add-on rollback. No need to use the home-infra server or production HAOS host.

Other blockers: final real backend nested-dispatch/HA tool classification, actual middleware registration, hosted unauthorized attachment with separate cost approval, IPv4/IPv6 network isolation, full current-version backup/restore and independent local HA admin access.

**No software deployment, OpenClaw invocation, production restart/restore, firewall, credential, Auth0 or Control Plane change occurred.**

### Phase 2G updated code acceptance receipt

[GitHub Actions #37849095384](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37849095384) SUCCESS: **196 original upstream policy tests passed**, **39 bounded convenience evaluator tests passed**, **15 real in-process FastMCP synthetic-control/replay/proxy tests passed**, **194 applicable patched upstream tests passed, 2 intentionally deselected**, exact middleware source rollback passed. New cases include nested write/delete proxy and read-proxy refusal. Generic light service `data` field limitation verified at evaluator only.

No full HAOS/Supervisor, actual HA backend, hosted identity denial, live production policy change or backup restore tested. Final-head CI after documentation changes must be checked separately. Production NO-GO.


## Phase 2H — Authorized single HAOS/Supervisor guest and complete approval regression

**2026-10-08 UTC. Status: acceptance experiment RUNNING / final outcome PENDING. Phase 3 NO-GO; production unchanged.**

- Authorization strictly covers **one** disposable standard GitHub-hosted `ubuntu-24.04` VM, QEMU/OVMF package install on that runner only, narrowly temporary KVM access, official SHA-checked HAOS guest, fully synthetic HA identity. No household/server/router, paid runner, independent OpenAI ID or production data.
- Verified repo still public, both PRs draft/unmerged, strict source pinned to `fc54437a804858732e4bc927add98e202d879a09`; official HAOS 18.3 `haos_ova-18.3.qcow2.xz` size 510014132, SHA256 `fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090` via official GitHub release API.
- First [VM preflight #37851700140](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851700140) **FAIL before image download/VM boot**: Ubuntu 24.04 ships 4M OVMF filenames rather than old path. Cleanup record PASS: no guest process and temporary files removed. Corrected matching OVMF_CODE_4M/VARS_4M; second [single-guest run #37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) is **IN PROGRESS** at writing time. No Supervisor outcome may be inferred yet. Workflow triggers only on its exact own file changes; DO NOT run another guest after any actual guest boot without new authorization.
- Test launch has 2 vCPU/4GiB guest, QEMU KVM, user-mode NAT and 127.0.0.1-only host forwards, QEMU-UID host firewall blocks private/loopback/link-local/IPv6 and non-essential ports, but public 80/443 is not a per-domain allow list. Sparse file bound, maximum 43 min job, traps for process, KVM ACL, UID, firewall and private work files. No guest disk/log artifact/cache upload. **Guest boot, cleanup and firewall efficacy are outcomes still to validate**; static policy is not evidence of runtime enforcement.
- [Full approval regression #37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013) **PASS:** original 196 upstream policy tests passed, patched+revised 211 passed without excluded tests; original middleware and test file Git hashes restored exactly after reverse patch. The two old cases were REWRITTEN for the stricter policy-change semantics. Queued approvals bound to original gate policy; stale tokens invalidated when gates change or are unreadable, and a fresh new-policy operation still requires fresh approval.
- Current VM source revision does not test genuine end-to-end HTTP-MCP read, real guest host reboot, corruption repair, installed baseline rollback, or truthful synthetic path redaction unless the run's recorded evidence actually establishes those. Later change to `single_haos_guest.py` uses a generated sentinel, but the running #37851915146 workflow checks out an earlier immutable revision; do not attribute updated tests to it.
- Track all 16 requested acceptance items and VM cleanup in `phase2h/ACCEPTANCE_REPORT.md`. **No production changes**.


### Phase 2H FINAL execution receipt — supersedes preceding RUNNING status

**2026-10-08 22:25 UTC — actual single permitted guest experiment ended BLOCKED, cleanup PASSED, production remains UNCHANGED.** [Official GitHub Actions #37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) exited 3 after the HAOS observer was `NOT_OBSERVED` and Core HTTP readiness `BLOCKED_TIMEOUT` at the bounded 780-second guest boot check. The QEMU guest process had not exited, but no guest OS boot-success or Supervisor API response was proved. HAOS image download/checksum PASS, root-only synthetic local add-on source STAGED on guest disk (NOT INSTALLED by Supervisor), 2vCPU/4GiB test isolation configured. Guest process termination PASS, working-directory removal PASS and zero artifact/cache upload. Full all-16-gate matrix in [Phase 2H acceptance report](phase2h/ACCEPTANCE_REPORT.md). **The single guest authorization has been consumed. Do not retry without a separate exact approval.**

Source security-code regression [#37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013) SUCCESS: **196 original**, **211 revised/patched** no exclusions, exact original test/source reversal PASS. A subsequent *static-only, NO GUEST* harness amendment permits only ESTABLISHED localhost hostforward replies ahead of the QEMU-owner private-destination deny rule and reports fixed Boolean-only serial boot milestones in future. This is a **plausible cause and proposed correction, not a runtime-verified root cause or successful VM acceptance**. [Static CI #37853632264](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37853632264) PASS. Actual Supervisor strict option recognition, installed image, bad-policy refusal, HAOS reboot, watchdog and real restore all **BLOCKED/NOT VERIFIED**; Phase 3 PRODUCTION NO-GO.


## Phase 2I offline follow-up (2026-10-09; not part of original guest result)

Phase 2I adds only synthetic diagnostics, guard and cleanup models in `docs/security/phase2i/offline_harness.py` and `tests/offline/test_phase2i_harness.py`, with a dedicated no-QEMU Python-only workflow. The historical run #37851915146 stays FAILED/BLOCKED. Classifiers do not contact a socket, boot a VM, validate kernel conntrack or prove Supervisor. See `docs/security/phase2i/REVIEW_AND_FUTURE_ACCEPTANCE.md`. No new guest authorization; any later acceptance must pin reviewed commit/hashes and obtain separate explicit approval. Phase 3 production NO-GO.


### Phase 2I subsequent offline runtime-observer addendum (not historical VM evidence)

Review-only commit `6617d6cded7cb6edb712c79af9f95045aab574c2` improved the *future* guest script's fixed-label transport observations (`HTTP_404`, `TCP_REFUSED`, `TCP_TIMEOUT`, absent listener vs no response), explicit QEMU user network `ipv6=off` and defensive no-body/no-exception-text outputs. The pure classifier and mock regression suite passed **13/13** in GitHub Actions [#37913475390](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913475390) and [#37913479830](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913479830); static syntax/isolation [#37913475242](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913475242) SUCCESS. The original failed run has no new findings. No guest/network experiment was started; these are code-only outputs, not runtime proof. The runner shell cleanup, real DNS resolver and supported Supervisor data seeding remain under review. No further VM authorized. Production NO-GO.


## Phase 2I second static hardening follow-up — no guest execution

Future-only `runner_once.sh` now requires a **unique ext4 block device labelled `hassos-data`** before mounting the disposable NBD partition; the old positional `/dev/nbd0p8` mount assumption was removed. It stops before guest creation if the filesystem label or local source staging is not verified. It now attempts partial firewall-chain cleanup after the first chain is created, stops its watchdog in the exit trap and emits separate read-back receipts for IPv4/IPv6 rules, KVM ACL, test UID and mounts. These are **source-level improvements, unexecuted**, not proof of actual privileged rollback. The local-source staging itself remains a supportability hypothesis (legacy `addons/` vs current `apps/`), and guest bootstrap DNS remains unresolved. Existing CI performs bash syntax and synthetic source/cleanup checks only. No VM, sudo, iptables or NBD command was executed by Phase 2I.


### Phase 2I final-acceptance fail-closed correction (2026-10-09; offline only)

Independent source review found a **false-green risk**: the future guest script's `main()` returned exit 0 even when `test_addon()` returned early (store discovery blocked) or raised an exception, while many of the 16 Supervisor acceptance cases were still unimplemented. This was a defect in the *unexecuted test harness*, not a proven production flaw. The review candidate now refuses a false-green result: it requires a confirmed running Supervisor for the preliminary gate, reports `FULL_SUPERVISOR_ACCEPTANCE=BLOCKED_INCOMPLETE_16_CASES` and returns exit **6** after partial add-on testing. This deliberately cannot claim a successful guest acceptance until all mandatory cases receive independently proven PASS results. Pure offline mocks test success-like responses, exceptions and absent source without launching a guest, starting a network service, or using privileged commands.

**Still unverified:** real QEMU owner/conntrack/DNS, actual HAOS boot and installed Supervisor, supported current-apps local store seeding, full strict-policy negative tests, genuine backup restore and watchdog behavior. No additional VM authorization or production change; preserve historical failed run unchanged. Source-gate review only; CI status must be checked on the exact commit.


## Phase 2J final offline acceptance gate (2026-10-09)

The 16-case pure state-machine and adversarial negative tests live in `docs/security/phase2j/acceptance.py` and `tests/offline/test_phase2j_acceptance.py` with a dedicated Python-only CI workflow. No live guest, network or privileged activity is performed. The review identifies unresolved host-side DNS upstream+TCP fallback, unsupported direct Supervisor `/data` provisioning, incomplete live 16-case observers and separate cleanup-readback gaps. This is **NOT READY** for another VM authorization. The historical failed Phase 2H guest is immutable; the future guest launcher intentionally continues to return nonzero for partial acceptance. See `phase2j/FINAL_OFFLINE_READINESS.md`; independent reviewer sign-off remains outstanding. Phase 3 production NO-GO.


## Phase 2K — first-install packaged policy candidate (2026-10-09)

The future-only HAOS harness no longer preloads tool_policy.json into Supervisor's private addons/data directory. It stages only local add-on source beneath apps/local. A reviewed Phase 2K patch adds a Supervisor-schema boolean bootstrap_reviewed_policy option (false by default) and a packaged fixed, minimal positive policy. If expressly enabled with strict policy, the add-on itself creates its *own* persistent /data/tool_policy.json once, exclusively with 0600 permissions; existing/corrupt policies and mandatory markers are never overwritten. The HAOS add-on Settings ingress HTTP 403 boundary is not bypassed. This is an offline developer-side candidate, NOT a verified official HA-MCP import mechanism or installed production security.

Offline CI applies pinned patches and tests failure, interruption, identity, startup, and recovery classifications with synthetic data. Real Supervisor local-store discovery, app image identity, backup restoration, DNS path, all 16 genuine security gates and full privileged cleanup remain NOT TESTED/BLOCKED. See phase2k/INSTALLATION_AND_POLICY_PROVISIONING.md. Verdict: **NOT READY** for another VM, **Phase 3 production NO-GO**, no installation, merger or restart.


## Phase 2L — DNS preflight and real pinned build-context validation (2026-10-09)

The future-only harness now fails BEFORE sudo, firewall, guest download or QEMU when an independent QEMU host-side resolver/network attestation is unavailable. The static preflight distinguishes unsafe DNS and forwarding configurations and refuses all unverified paths; no broad web/DNS/NTP public egress remains in the dormant proposed firewall. Exact staging of the pinned Phase 2K candidate and required Docker COPY helper/template succeeded with 33 Phase 2L offline tests (source CI #37927463857). No Docker image was built, no kernel rules were tested, and Supervisor 16-case acceptance remains BLOCKED. See docs/security/phase2l/DNS_AND_PACKAGING_PREFLIGHT.md. **NOT READY** for another guest, Phase 3 NO-GO.


## Consolidated pre-VM engineering closure — 2026-10-09

Proposed deterministic IPv4/IPv6 owner firewall recipes, exact QEMU localhost forward AST regression, TTL-bound web snapshot review, 16-gate acceptance inventory and 13 independent cleanup readback requirements are now implemented **offline only** under docs/security/phase2l. The future-only runner remains blocked before sudo/network/guest work and has an additional exit-6 guard for unproven cleanup. Pure Phase 2L CI demonstrated 61 tests passing at 7daa6234, including the pinned patched Docker COPY source context; no Docker image or live network enforcement was performed. See docs/security/PRE_VM_CONSOLIDATED_ACCEPTANCE.md. Single immediate blocker is an independently reviewable, separately authorized non-VM libslirp resolver + firewall enforcement probe, not another general research phase. Phase 3 NO-GO, VM and deployment authorization absent.


## Single bounded network probe package — 2026-10-09

The future Probe A package is INERT source-only; no new workflow or privileged action is authorized. Scoped owner-UID iptables/ip6tables argv, deny-first dual-family setup, exact DNS UDP/TCP destination, narrow established-loopback reply and independently required rollback/readbacks live in docs/security/phase2l/probe_contract.py. Old potentially dangerous iptables-restore payload is replaced by non-loadable inert comments; unrelated firewall tables must never be flushed. Ordinary Linux process probe A does NOT prove QEMU/libslirp; QEMU probe B would need separate explicit QEMU approval and guest-originated DNS to prove upstream routing. See docs/security/phase2l/PROBE_APPROVAL_PACKAGE.md. NOT READY for live probe: bounded command executor, DNS client, kernel counters, deadlines and independent cleanup readbacks are not yet implemented; HAOS/Supervisor and production remain NO-GO.


### Final offline transaction rehearsal (2026-10-09)

The inert module docs/security/phase2l/probe_rehearsal.py now drives injected *synthetic callbacks only* through preflight, deny-first dual-stack setup, hook readback before workload, exact effective-order readback, workload-once, stop, both-family teardown, and all mandatory independent cleanup readbacks. It always returns SYNTHETIC or BLOCKED; no subprocess or network is available. Negative tests simulate failure at every setup/teardown step, missing dual-family hook, wrong UID/order, fake provenance, process-stop/cleanup failure, and a deliberately failing first cleanup readback while verifying **all** readbacks are still attempted. Phase 2L CI on source commit e208ba8c9c9030e41e722d7d2bb4e6e9661beca2: 91/91 passed (run #37933409551). This does not close the live command controller/DNS client/counter/readback engineering blocker or authorize Probe A; it provides a safer tested scaffold for that exact correction.


## Probe A recovery and engineering closure (2026-10-09)

The previously committed inert probe_contract/rehearsal/approval package remains intact. New separately committed Phase 2L modules supply a bounded DNS wire verifier, fixed negative socket primitives, strict offline kernel-state/counter parser, dependency-injected 240-second controller with cleanup reserve, exact argv sequencing and an unactivated host process boundary. At source commit 252ced34a63ba07ac450f8edaf7842d956770b82 the existing non-VM Phase 2L workflow passed **128 tests** (run #37937261004). No live network evidence, no VMs or privileged networking. **NOT READY** for one Probe A approval: an actual privilege-dropping runner/loopback peer, independent kernel observer, external cancellation-safe cleanup watchdog, bounded streaming output and independent review remain missing. Do not use the code reference as execution authority. See docs/security/phase2l/PROBE_A_ENGINEERING_REVIEW.md. Probe B QEMU and production stay NO-GO.


### Probe A safety engineering continuation — 2026-10-09

Initial source commit `5c48379109afe5890796fd3ab5051fa10af8e240`: inert streaming subprocess-capture helper and read-only kernel observer with offline-only fault-injection tests. Both remain unactivated. Existing controller and firewall contracts unchanged. This does **not** satisfy live supervised-execution readiness: no off-process cancellation-safe cleanup watchdog, independently proven partial-setup rollback, numeric-UID workload/controlled root loopback, complete resource observers or trusted kernel provenance. Phase 2L offline-only CI passed 137/137 tests at `f2e40e1934a2d3be6549e1d05b3d526766d8e9ee`, run #37940386889. Other workflows are separately tracked; independent security review is not established. **Probe A NOT READY; Phase 2H VM retry and production NO-GO.**


## Administrator experience and security — binding release goals (2026-10-09)

**Authoritative product design:** [PROJECT_DESIGN_BLUEPRINT.md](PROJECT_DESIGN_BLUEPRINT.md). The end goal is **ChatGPT as the user's functioning Home Assistant administrator and troubleshooting/automation/dashboard engineer**, with strong identity, per-operation authorization, server-side enforcement, recovery and proportionate task-scoped approvals — **not merely a read-only overview tool**. The initial `ha_get_overview`-only strict bootstrap policy is a security test baseline, not the final administrator experience.

**Required additional production-release track:** validate UX-01–UX-12 from the blueprint for investigations, trace/log inspection, creation/modification/deletion of automations and scripts, helper and dashboard management, integration troubleshooting, authorized restart/reconfiguration, one bounded approval for multi-step repair when safely implemented, recovery and anti-bypass security. Capture actual working-plugin capabilities, compare staged behavior, preserve end-to-end administrative functionality, and obtain explicit user acceptance of any material reduction. Unimplemented task-scoped approval is **a requirement**, not a current capability.

**No security shortcut:** permanent broad generic-tool/root permissions are prohibited as a convenience workaround. Approval and final action+target checks must be enforced at the actual dispatch boundary across aliases, service calls, proxy tools, scripts and other routes. Protect security-sensitive devices, presence/camera privacy, backups, system settings and credentials with appropriately stronger approval or hard-deny guards.

**Project status remains unchanged:** Probe A source remediation/review, HAOS/Supervisor gates, hosted identity/authentication, independent recovery, qualified security review and explicit production authorization remain prerequisites. Do not interpret this design record as consent to run QEMU, a VM, real firewall/network tests, change live HA, merge PRs or deploy.


## Probe A F1–F6 focused remediation status — 2026-10-09

The frozen security review at `150e5c0` identified F1–F6. Work continued *in draft PR #2*, with no privileged workflow, VM, firewall or production activation. The revised code introduces irreversible controller OS UID/GID/capability drop and an explicitly injected read-only post-observer; resumable journaled ownership-checked cleanup; a dual-stack-verified leading REJECT emergency barrier before removing temporary DNS ACCEPT entries; an unactivated atomic cgroup v2 full-tree containment contract; shared firewall rule normalization; and expanded SHA-256/runtime dependency inventory requirements. Dedicated adversarial offline tests are part of the Phase 2L regression suite. See latest `docs/security/phase2l/PROBE_A_ENGINEERING_REVIEW.md`; prior "missing component" histories describe older commits, not the current source.

**Explicit remaining release blockers, not another implementation phase:** 1) obtain final immutable code SHA with all five nonprivileged engineering CI workflows green; 2) externally design/review and pin the OS-backed read-only observer broker and atomic cgroup-v2 privileged launcher (not bundled or enabled); 3) independently verify complete source, executable and shared dependency manifest with reject-on-drift; 4) independently approve a trusted receipt path that will accept only real per-case kernel counters plus post-guardian cleanup evidence, never injected mocks; 5) obtain a new qualified third-party security review with an attributed finding list for the exact code SHA. **No live Probe A request before all gates.** Probe A cannot prove QEMU/libslirp, HAOS/Supervisor or production safety. Production remains NO-GO.


## Probe A four-finding focused correction — 2026-10-09

**Frozen source-and-test commit:** `536dae328fb5882ccd54e92eb3bc2d6356ace468`. This records four narrow source remediations within existing draft PR #2, **not runtime authorization**: F1 explicit checked Linux bounding/ambient/other capability reduction with post-drop zero-set verification and a libcap runtime dependency; F2 one immutable absolute end/cutoff shared by launcher, guardian and controller; F3 guardian-exclusive cleanup with controller request starvation prevented; F4 owned/unreaped process-group exit handling with no signal to unverified reused IDs plus an explicit disabled-by-default privileged-command cgroup requirement. GitHub Phase 2L CI #37968089534 passed **204 offline tests**, other four engineering workflows green. The current project blueprint remains mandatory for eventual full authorized Home Assistant administration.

**Only next engineering/release gates:** external qualified review of the exact final SHA; actual pinned OS-backed root broker, read-only observer and worker/root-peer plus privileged-command cgroups; complete source/runner/loader/**libcap** and dependency manifest; trusted *real kernel* evidence/cleanup receipt (no mocked PASS); and separate single-run user authorization if every gate passes. No new workflow/VM/probe/production approval; Probe A does not validate QEMU/libslirp, Supervisor, HAOS or household deployments. Production NO-GO.


## Probe A S1–S3 targeted code closure — 2026-10-09

**Immutable code-and-test candidate:** `a3de488ec494bb9e5e378f5fe937d8ebb780f643` in draft PR #2. Source-only S1 fixes root-executed `/usr/bin/pgrep` and `/usr/bin/getent` containment bypass by requiring the injected approved-root command containment path independent of binary directory; permits `getent passwd` only under root-owned local-`files` NSS configuration, now manifest-pinned with `/etc/passwd`. S2 maps normal/cancelled/deadline/unverified/error guardian lifecycle to distinct process exit codes, ensures exceptions cannot yield exit 0, and keeps the separate parent post-audit mandatory. S3 caps snapshots and all non-cleanup IPC to the same absolute work cutoff. Tests: **223/223 Phase 2L offline passed**, Actions #37973014246, four other engineering workflows green. No VM, firewall, network probe, privileged runtime experiment or production mutation.

**Do not equate source closure with release readiness:** A source-independent qualified review, actual OS-backed privileged launcher and read-only observer, worker/root-peer/guardian-command process containment, NSS/name-service network confinement and pinned transitive dependency closure, runner image manifest, genuine kernel readback and trusted independent final PASS composer are still required before requesting any single-use runtime authorization. The future system must continue to meet `PROJECT_DESIGN_BLUEPRINT.md` full, securely authorized Home Assistant administration requirements; reducing the product to read-only is not acceptable. QEMU/libslirp, HAOS/Supervisor and production remain NO-GO.
