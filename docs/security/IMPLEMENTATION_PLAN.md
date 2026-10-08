# Security implementation plan

Updated 2026-10-08. Repository: Alundqvi97/hass-codex-tunnel-mcp. This work is independent of home-infra-control-plane.

## Phase status

| Phase | Status | Evidence / promotion requirements |
|---|---|---|
| 0 — Audit and baseline | Completed (prior audit) | Source at `def1d7235018745b880b573a944925352dea85a5`, original `mcp_url.py` blob `ad0afdc1d2aaec61390be0a108c8d6a18c853a57`; see SECURITY_AUDIT.md |
| 1 — GitHub and offline validation | In progress | Fork verified; regression patch and reverse application passed; original isolated suite 14/14 passed; integrated isolated security tests 12/12 passed in local reconstructed source-only environment. Full upstream suite and CI must pass before promotion. |
| 2 — Authentication and network security verification | Pending | Test valid/missing/invalid/expired/revoked backend bearer and real MCP POST; unauthorized hosted tunnel attachment; direct port 9583 access by VLAN |
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
- Original tests exercise tunnel-client subprocess logic and need the full repository checkout. GitHub Actions is the first authoritative full-repository CI execution; record actual run status separately.
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
