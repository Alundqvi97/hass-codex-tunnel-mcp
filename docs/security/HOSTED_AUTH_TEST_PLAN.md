# OpenAI-hosted tunnel attachment authorization: approved test plan

**Status: BLOCKED — no hosted test performed and no resources created.** Maintain separation from existing production tunnel, ChatGPT app, and Home Infra Control Plane.

## Boundary model

A ChatGPT session/workspace and its app association authorize hosted attachment, and a separately scoped OpenAI Platform API key is used by the tunnel runtime to establish the outbound connection. A secret HA-MCP URL path governs backend access. These identities are not interchangeable. OpenAI's [Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) documents Tunnels Read/Use and workspace/organization association, **but only authorized tests could prove cross-identity deny**. Production tunnel ID is never used as a test identifier.

## Necessary disposable resources and test identities

- One **new owned disposable tunnel**, distinct random ID, synthetic read-only MCP backend (single `fixture_status` tool), bounded TTL, and test-only runtime key with minimum Tunnels Read/Use permissions.
- Two independently authenticated **ChatGPT test identities** or separate workspaces/org associations when needed to distinguish same-workspace client sharing from cross-organization access. A second identity in the **same workspace** alone cannot prove cross-workspace isolation.
- A scoped **read-only participant** lacking Tunnels Use and an authorized participant with Use, or one identity whose role may be changed safely in the disposable setup; tests must not change the user's production role.
- Dedicated URL/path/identity material remains out of GitHub; use masked local test evidence only.

## Conditional test sequence and expected outcomes

| Experiment | Expected result | Required setting |
|---|---|---|
| Authorized association + Use | Can discover `fixture_status` only | Test identity A, test org/workspace |
| Unknown tunnel ID | No attachment/tool discovery | A (synthetic invalid test id) |
| Correct test ID, unassociated workspace/org | No attachment/tool discovery | B in a separate workspace/org |
| Correct test ID, missing Use | Denied | B or scoped C |
| Remove test Use permission; new request | Denied | A after approval for test-only permission change |
| Remove Use during existing session | Defined recheck or expiry behavior documented | Separate test session, no production impact |
| Invalid/revoked test runtime key | Cannot establish/reestablish tunnel | Test-only key, disposal endpoint |
| Repeat stale auth/session material | Denied or explicit bounded replay semantics | Test-only session |
| Attempt disallowed `tools/call` | Never execute a write; only synthetically forbidden name | Test service backend |

The minimum number of identities depends on workspace and role capabilities. Two accounts with distinct org/workspace associations may suffice for cross-workspace denial, but testing missing-use scope requires a different role or an **additional** identity if roles cannot change safely.

## Approval, cost, cleanup

**Do not provision without separate explicit user approval.** Need confirmation from Platform billing/settings of whether tunnel resource creation is free; API traffic, model tokens, other resource operations, test identities or subscription plans may incur charges. **Costs are UNKNOWN**, not confirmed zero.

Preflight budget: explicitly set a user-approved maximum; abort test if cannot cap spending. A small fixed request budget should cover 1 authorized initialize/list and 8 negative attachment variants, plus separate post-revocation checks. No hidden retry loops. Cleanup: disconnect test ChatGPT connector, delete disposable tunnel, revoke test keys, remove test association/membership, confirm absence in UI/API, delete ephemeral staging server, retain only non-secret summaries and event/result timestamps.

No existing tunnel connection, production key, Home Assistant device, Auth0 tenant or ChatGPT app is in scope.
