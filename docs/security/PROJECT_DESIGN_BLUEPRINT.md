# Project design blueprint — ChatGPT as a secure Home Assistant administrator

**Status:** Authoritative **desired-outcome / release-acceptance design** as of 2026-10-09; **NOT an implemented policy, authorization grant, or production change**.

**Owner intent:** ChatGPT is the user's capable Home Assistant **administrator, automation engineer, dashboard builder and troubleshooter**, not merely a device remote or read-only status bot. Preserve the working tool's breadth and ability to complete tasks end to end, while preventing unauthorized users, sessions, tools, injected instructions and overly broad authorizations from controlling the home.

**Non-negotiable principle:** **Improve security without silently removing the legitimate administrator's capabilities.** A materially reduced admin experience, repeated unnecessary approval prompts, or inability to complete common repairs is a **production release blocker**, even when security tests are green. A deliberate functional restriction requires an explicit, recorded user decision and a viable alternative.

This blueprint is the **product/experience source of truth** for this project. Security reviews, PRs, staging tests and deployment checklists must map their changes to it. It supplements, but does not override, the separate mandatory security/safety gates in `IMPLEMENTATION_PLAN.md`, `THREAT_MODEL.md`, `TOOL_POLICY_MATRIX.md`, `PHASE3_READINESS.md` and the Probe A/HAOS acceptance reports. Never infer authorization for an experiment or live change from this document.

## 1. The job we are trying to preserve

The user's primary interaction with ChatGPT is **administrative work**, not turning lights on and off.

Typical request: *"Investigate why my arrival automation failed. Find the cause, fix it, test it and tell me what changed."*

The target experience is that ChatGPT can independently inspect the relevant system, establish the problem, formulate a bounded change, obtain proportionate approval when a write is needed, **carry out the authorized work itself**, validate the result and explain the outcome. The user should not have to manually assemble YAML, find traces, repeatedly click through tools, or troubleshoot the assistant's own work.

Required functional families:

| Administrator job | Required final capability | Preferred friction |
|---|---|---|
| Investigate automations and scripts | Read definitions, traces, history, trigger/condition/action paths, dependent entities and relevant logs; diagnose end to end | Automatically for authorized, least-scoped, non-sensitive read paths |
| Create automations, scripts and helpers | Build actual configuration through supported HA APIs/tools, check syntax/semantics, apply safely, verify | One scoped approval for a clearly defined change task where a secure task grant is implemented |
| Modify broken automations | Diagnose, identify intended behavior, prepare change, verify result and provide reversible before/after record | Do not demand a new prompt for each internal substep inside the approved scope |
| Delete or replace automations/scripts | Inspect references/dependencies; obtain explicit destructive-operation consent; back up and verify absence | Explicit approval identifying exact objects; no blanket destructive access |
| Design, create and edit dashboards | Inspect existing Lovelace/dashboard structure, build views/cards/resources, apply and verify UI/configuration | Task-scoped approval for writes; do not reduce the plugin to producing text instructions |
| Troubleshoot integrations/devices | Inspect relevant entities, services, diagnostic state, logs, health, updates and configuration; remediate within permission | Reads automatic where safe; scoped approval for restart/reconfigure/install |
| Maintain HA configuration | Support legitimate HA administrative operations, including helpers, integrations, backups, add-ons and recovery when properly authorized | Risk-appropriate approval; stronger guardrails for high-impact operations |
| Manage ordinary devices | Continue to support user-instructed lights, blinds, media and scenes | Avoid unnecessary prompts where a tightly bounded capability has been proven |
| Review a completed task | Explain root cause, exact modifications, outcome, caveats, and how to roll back | Automatic, with no credentials or sensitive data echoed |

**Not acceptable as the permanent experience:** a policy with only `ha_get_overview` permitted automatically and all administrative functionality effectively inaccessible. The one-read initial strict policy is a **safe bootstrap/test baseline**, NOT the target final administrator policy.

## 2. Reference task workflow

1. **Identify user intent and authority** — distinguish a request to inspect, plan, create, edit, delete, repair or perform high-impact administration.
2. **Inspect and diagnose** — use authenticated, reviewed read-only tools automatically within data-minimization bounds; gather relevant logs/traces/state, without exposing tokens or private data unnecessarily.
3. **Plan the change** — state the object(s), before/after intent, affected automations/dependencies, risks, expected side effects, validation and rollback. Avoid speculative writes.
4. **Request proportionate approval, when needed** — a clear **task-scoped grant** covers a bounded, exact set of normalized operations/objects, limited time and operator identity; do not reinterpret a conversation sentence as permanent authorization.
5. **Execute the approved work** — ChatGPT invokes the necessary tools itself; the server checks the final action, arguments, resolved targets, current policy and grant **at dispatch time**, including nested/generic dispatch. If scope expands, stop and ask again.
6. **Independently validate** — re-read configuration, verify traces/status or safe synthetic tests, and distinguish confirmed behavior from untested outcomes. Do not claim real household behavior without evidence.
7. **Report and recover** — summarize changes and verification; restore backed-up state or use independent local recovery if the operation fails. Never fail open to regain convenience.

Example acceptance sequence: "Fix the sunset lights changing manually controlled lights" → inspect relevant automation and recent traces without separate approvals for each safe read → identify exact fix → present one bounded modification for approval → implement → validate configuration and test conditions without unexpectedly altering lights → report result. If a door-lock or camera-privacy rule is implicated, **elevate and request a separate, explicit security-relevant approval**.

**One approval per task is a DESIGN TARGET, not a claim about HA-MCP v8.6.0 today.** A task grant must be implemented and proven server-side, not simulated by blanket approval of generic tools or by accepting any later tool call from the same conversation.

## 3. Security and authorization model — keep administrative power, contain it

**Identity comes first:** A secret MCP path and a static backend token are credentials, **not** proof of which ChatGPT account or person is calling. The intended remote administrator must be authenticated and authorized; prove unauthorized-account, wrong-workspace, expired, revoked and replayed access is denied at the supported hosted/tunnel and backend boundaries. Preserve separate local recovery independent of the remote path. Do not claim cross-account denial is already verified.

**Server-enforced capability boundaries:** Define access using normalized *action + target + input shape + caller/role + approval state*, not only a tool name. Generic service calls, `ha_bulk_control`, nested proxy dispatch, WebSocket commands, scripts, automations and filesystem routes may reach the same sensitive effect. Revalidate the effective authorization at final dispatch after any wait, policy change or expiry. Tool output, HA logs, webpages and integration text are **untrusted data**, never authority to broaden a grant.

**Risk classes for the final administrator UX:**

| Class | Examples | Target rule |
|---|---|---|
| A — Read/diagnose | Relevant entity/configuration state, automation traces, safe logs, dashboard definitions, system overview | Allow authorized and minimized read operations automatically once schema and secret/privacy exposure are verified. Sensitive surveillance/presence/credentials require separate restrictions. |
| B — Reversible administrative writes | Create or edit specified automation/helper/script/dashboard; change an approved benign configuration setting | One narrowly scoped, time-limited approval for the exact change workflow; pre-change snapshot, allowlisted operations, verification and rollback. Future standing grants only after separate security review and explicit user choice. |
| C — Destructive or security-affecting changes | Delete automations/dashboards, wide bulk replacements, occupancy/security automations, door-lock logic, camera privacy, changes to authorization policy | Explicit high-impact approval for named targets and effects; backup/dependency assessment and strong server-side enforcement. No implicit inclusion in a Class B grant. |
| D — Critical administration | Credentials/tokens, add-ons and Supervisor, system/network access, root/sudo, backup deletion/restoration, remote security controls, firmware, unbounded filesystem or service calls | Dedicated elevated approval or unavailable until an independently reviewed guarded path exists. Preserve separate local break-glass management; no permanently broad root-like grant. |
| E — Unknown tools/new routes | Previously unseen tool, alias, parameter, multi-target selection, tool discovery/proxy | No new automatic rights. Discovery can remain useful, but dispatch must be authorized at its final normalized effect. |

Current HA-MCP evaluator semantics must be respected: `require_approval` mode can **allow unmatched tools**, while `allow` mode requires approval for unmatched tools and does **not** implement a hard deny. **Never invert the existing 18 approval rules by simply switching rule_effect.** A true prohibited operation needs a verified server-side DENY/removed tool/least-privilege backend, not the label "approval required". Keep remote policy editing and developer privileges disabled unless a separately reviewed process explicitly requires them.

**Usability with real boundaries:** Broad `ha_call_service`, raw WebSocket, backup/admin or proxy tools must not be permanently auto-allowed to improve convenience. A typed, target-aware admin operation or safely constrained approval grant may offer the same legitimate task completion without granting unrelated capabilities. The assistant may continue the approved workflow, but the server must block any changed target, unexpected side effect or privilege escalation.

**Availability is part of safety:** If the strict policy fails closed, local HA automations should continue independently. Preserve and test local UI/Supervisor access, protected backups, pinned previous versions and a rollback that does not rely on the broken MCP/tunnel. Never weaken a broken policy silently in order to get remote access back.

## 4. Desired outcomes and testable release criteria

These are **requirements, not claims of completed implementation**. Before production change, capture a sanitized baseline of the user's working plugin and test the same workflows against the staged upgrade with synthetic devices and, where permitted, a separately authorized disposable real Supervisor.

| ID | Mandatory acceptance test | Passing outcome |
|---|---|---|
| UX-01 | Investigate a failing automation and trace its dependencies | The assistant can retrieve relevant definitions/traces/logs, explain root cause and avoid privileged write prompts for approved read-only actions |
| UX-02 | Create a complete automation/script/helper | Correct supported tool operations, expected entities/conditions, configured object exists and is independently read back after task approval |
| UX-03 | Repair or modify an existing automation | Preserves unrelated behaviors, applies approved diff, verifies result and provides rollback evidence |
| UX-04 | Delete a named automation | Explicit destructive consent for exact object; checks references, performs deletion, proves result, supports restoration |
| UX-05 | Build/edit a multi-card dashboard | Writes and reads back actual dashboard/views/cards via supported interface, without requiring user to manually paste YAML |
| UX-06 | Diagnose a failing integration/service | Reads relevant state/logs automatically; can complete an authorized bounded restart/reconfigure where supported |
| UX-07 | One bounded approval | Approved multi-step repair completes without unnecessary per-tool approval spam; changed target, unexpected operation, expiry or policy change re-prompts/blocks |
| UX-08 | Unauthorized account and instruction injection | Wrong identity/workspace/revoked credentials and malicious tool-output/log instructions cannot execute, widen or approve administrative operations |
| UX-09 | Alternate privileged routes | Generic/bulk/WS/proxy/script dispatch cannot bypass action/target authorization, including new tools after update |
| UX-10 | Broken policy / MCP / upgrade | Remote unsafe operations stop; independent local administration, preserved HA automations, tested rollback and recovery remain available |
| UX-11 | Capability and latency regression | Compare a captured pre-upgrade admin-task inventory with staging; no unexplained loss of supported admin workflow, new manual steps or repeated approval friction |
| UX-12 | Full administrative closeout | Task reports exact completed/failed steps, evidence quality, affected objects, audit trail, and safe next/recovery action without leaking secrets |

Where a required tool/HA integration does not offer an approved write API, explicitly document the gap and develop a safe path; **do not quietly redefine the required feature as "ChatGPT can provide instructions."** Unknown or unsupported features must be marked BLOCKED, not PASS.

No blanket promise that every task will be silent or that unauthorized access can never occur. Security-changing/destructive tasks must remain intentionally interruptible by the operator.

## 5. Release and operating gates

A production release requires **both** tracks to pass:

**Security/engineering:** genuine HAOS/Supervisor and tool-policy acceptance, hosted access denial, verified identity and final backend enforcement, sensitive path/log redaction, network ingress/IPv6 boundaries, independent qualified review, frozen artifact provenance, backups, rollback and recovery. The current Probe A/Phase 2H work concerns these prerequisites, and offline tests do not substitute for real evidence.

**Administrator experience:** UX-01 through UX-12, mapped to the actual installed HA-MCP tool catalog and the user's existing workflows; a tested operator approval journey; no unexplained capability removal; no hidden broad bypass used to recover ease of use. Demonstrate the full inspect → approve → change → verify loop, not only a read-only status call.

Before cutover:
- Retain the current working Home Assistant and ChatGPT tunnel until the replacement passes both tracks and an exact production change is approved.
- Inventory safe current administrative capabilities and identify deliberate changes, including what is newly approval-gated or unavailable.
- Present a **capability-difference table** to the user and obtain explicit acceptance for every material reduction or high-impact workflow change.
- Keep any new task-scoped capability disabled until its actual server-side enforcement and lifecycle have passed staged negative and recovery tests.
- Record who approved what, for which targets, with expiry and the ability to revoke an unconsumed grant.
- Roll back on unexpected administrative capability loss, approval loops, hosted auth failures, security-policy bypass, loss of independent recovery, or material performance regression. Never automatically loosen security during rollback; operator must choose a protected recovery route.

**Current state (2026-10-09):** PR #1 and PR #2 remain development candidates, not deployed. HAOS/Supervisor 16-case acceptance and Probe A real network evidence remain incomplete, independent review and production deployment approval outstanding. This blueprint adds **product requirements only**. It does not change HA-MCP tools, rule effects, live security settings, any production connector, VM authorization or GitHub workflow.

## 6. Project discipline / non-goals

- Measure progress by closed **security gates AND administrator-task gates**, not by the count of synthetic green tests or additional documents.
- Every security/design change must state its intended effect on legitimate administrator capabilities and how it is tested.
- Keep the Home Infra Control Plane and Auth0 separate; this HA-MCP security work must not block on completing an unrelated infrastructure-management architecture.
- Do not grant ChatGPT broad permanent root rights or promise it can unconditionally operate anything. Human approval is a security control where the stakes warrant it.
- Do not change the homeowner's existing automations, dashboards, household security devices or network to satisfy a simulated acceptance case without a separate explicit approval.
- When a feature is blocked for a legitimate user, prioritize a **narrowly authorized, fully functional replacement**, not a documentation-only workaround.
