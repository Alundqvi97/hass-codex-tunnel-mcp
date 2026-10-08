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
