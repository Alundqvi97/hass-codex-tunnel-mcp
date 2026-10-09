# Security implementation plan

Updated 2026-10-08. Repository: Alundqvi97/hass-codex-tunnel-mcp. This work is independent of home-infra-control-plane.

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
