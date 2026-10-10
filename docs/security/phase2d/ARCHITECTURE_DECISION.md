# Phase 2D authentication architecture decision (design only)

## Comparison

| Dimension | A — Existing HA-MCP hardening | B — Dedicated authorization gateway | C — OAuth/OIDC mode |
|---|---|---|---|
| Inbound identity | Shared secret path (not distinct user identity) | Gateway can verify OAuth/JWT and server-side scopes | OAuth per-user HA tokens; OIDC shared HA backend token |
| Security benefit | Fail-closed gate, tool restrictions, host-only ingress, secret-safe logs | Genuine token authentication and individual authorization if implemented and audited | Replaces secret-only MCP client auth, with new auth endpoints |
| ChatGPT tunnel compatibility | Retained, subject to staging | Requires tunnel endpoint reconfiguration; OAuth routing/streaming tests | Requires OAuth discovery/redirect compatibility and TLS |
| HA permissions | Shared existing admin authority | Can mediate scoped operations | OAuth HA token authority per user; OIDC shared server account |
| Complexity | Lowest; no extra service | Highest: gateway lifecycle, credentials, failure modes | Moderate/high: endpoint, client, IdP, callback, DCR |
| Recurring cost | No additional cloud bill assumed | Depends on IdP and hosting; unknown | IdP/proxy costs depend on setup |
| Home Infra Control Plane | Remains separate | Optional future integration, never reuse root privileges | Not required; optional Auth0 for OIDC |
| Recovery | Fail-fast may remove remote MCP; preserve local HA UI/console | Independent proxy recovery/rollback | Restore old modes and app association/credentials |

## Recommendation — A first, with explicit limits

For this single-household administration path, hardening the current HA-MCP standard mode is the smallest practical improvement without introducing another critical service. Make policy middleware mandatory and fail closed; retain a strict allow-list opt-in only with tested and actual effective rules; restrict direct TCP 9583 after out-of-band recovery is proven; suppress startup path disclosure. This does **not** make the connection per-user authenticated.

Choose B later only if the user needs enforceable per-user attribution/scopes that the current secret path cannot provide. C is not a drop-in solution: HA-MCP OAuth remains beta and accepts per-user HA tokens, while OIDC authenticates through an external IdP but uses a shared Home Assistant token. Neither guarantees granular server-side tool authorization by itself.

OpenAI documents organization/workspace and Tunnels Read/Use checks, but this project's hosted unauthorized-attachment negative tests are outstanding. [OpenAI guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) · [HA-MCP 8.6.0 SECURITY.md](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/SECURITY.md) · [OIDC](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/docs/oidc.md) · [OAuth](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/docs/OAUTH.md).

**No production change authorized. Phase 3: NO-GO.**
