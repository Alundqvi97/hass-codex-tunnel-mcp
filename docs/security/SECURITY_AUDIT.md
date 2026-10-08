# Tunnel security audit — 2026-10-08

## Provenance

Fork `Alundqvi97/hass-codex-tunnel-mcp` confirmed by GitHub API as direct fork of `norpol/hass-codex-tunnel-mcp`. Both main branches were at `def1d7235018745b880b573a944925352dea85a5` when this work began. Baseline file Git blob: `ad0afdc1d2aaec61390be0a108c8d6a18c853a57`.

The supplied offline candidate ZIP checksum was SHA-256 `b56be95fb58793a91eabc134614767072e42c1b95fc4ea311435b40a82af91e4`. Local archive integrity passed. The original 14 standard-library tests passed on 2026-10-08, reproducing the vulnerable source behavior intentionally using only synthetic tokens and 127.0.0.1. Applying the reviewed patch and reversing it restored exact source bytes. An adapted repository-style security regression module passed 12 tests in a source-only staging directory; authoritative combined upstream suite and GitHub CI remain to be verified.

## Findings

| ID | Priority | Finding / evidence | Current disposition |
|---|---|---|---|
| HA-01 | High, conditional | Python urllib GET startup probe followed HTTP 302 with bearer header to another local origin (different TCP port) in synthetic regression | Patched to reject probe redirects; *does not prove runtime tunnel-client handling* |
| HA-02 | Medium | Probe accepted 401/403 even when bearer configured | Patched to reject those probe responses; full authenticated MCP POST still unverified |
| HA-03 | Medium | Public cleartext HTTP backend was warned about, not rejected | Patched in URL assessment; DNS TOCTOU/rebinding remains |
| HA-04 | Medium | Direct TCP 9583 reachable from trusted desktop LAN as previously observed | No network change; verify needed access before isolation |
| HA-05 | High consequence | Static bearer, administrative tools, ChatGPT connector No Auth, hosted attachment authorization not independently verified | Requires separate hosted test; not solved by patch |
| HA-06 | Conditional | Unfiltered tunnel child stdout/stderr can contain sensitive output | Logging audit and fake-secret tests pending |

## Residual risks

- Probe success is not proof of backend authorization for MCP POST. 400, 405, 406 remain compatible/inconclusive.
- The patch protects the Python probe, **not** the tunnel-client's transport itself.
- Public HTTPS URL may still be attacker controlled; DNS rebinding, proxy headers, URL userinfo edge cases, query-based secrets and secrets in error chains need targeted analysis.
- `redact_mcp_url` removes path and query but retains the authority; hostname may be sensitive.
- Per-user identity, bearer revocation/expiry, least privilege of HA actions and unsolicited ingress denial require staging verification.
- Patch changes startup accept/reject behavior; no Home Assistant deployment or service restart should happen without separately authorized maintenance and rollback.

## Phase 2 acceptance conditions

Use a disposable staging HA backend and tunnel only. Demonstrate valid authentication, missing/invalid/expired/revoked denial and actual `initialize`/`tools/list` requests; inspect authorization and scope at hosted attachment boundary. Verify egress/DNS/proxy and guest/IoT/WAN reachability separately. Never use real credentials or secret endpoints in recordings, PRs or CI.

See `IMPLEMENTATION_PLAN.md`, `THREAT_MODEL.md`, and `ROLLBACK.md`.


## Phase 2 extension — 2026-10-08

**Evidence hierarchy:** Current GitHub/HA/UniFi read-only results and OpenAI/HA-MCP published documentation are source-backed; they are not negative authorization tests.

| Finding | Classification | Evidence and exact interpretation | Disposition |
|---|---|---|---|
| HA-07: backend bearer may not be enforced in standard-mode HA-MCP | HIGH risk / unverified | Add-on standard mode documents secret URL as credential; production integration includes a separate bearer header. No verified recipient-side 401/403 for real MCP POST. Fixture shows 405 GET can succeed with invalid bearer while POST rejects. | Phase 2 STOP-GATE until actual staging validation. Do not claim token is validated merely because configured. |
| HA-08: crash-only watcher | MEDIUM reliability / source confirmed | `TunnelManager._watch_process` records `exited` but does not create new child; synthetic crash test added. A full HA restart may restore it, but that is not a reliable self-healing strategy. | Phase 3 staged health monitor/backoff/restart policy with independent recovery; no production changes now. |
| HA-09: diagnostic authority userinfo disclosure | MEDIUM conditional / source confirmed | Redactor previously echoed full `parsed.netloc`; newly configured userinfo is rejected, but malformed/legacy URLs could leak into diagnostics. | Narrow development patch strips userinfo, preserves hostname/valid port; tests added. Must pass full CI. |
| HA-10: opaque child logs | MEDIUM conditional / source confirmed | `tunnel.py` sends child stdout/stderr lines verbatim to HA logging. Sensitive values emitted by a binary could remain in logs. | Test with a fake binary; implement bounded central scrub strategy and logging policy before promotion. No production logs exported. |
| HA-11: scope and policy coverage | HIGH impact / not verified | Policy engine on but actual rules not read; `disabled_tools` empty and read-only mode off. Documentation warns alternative tools may exercise the same ability. | Inventory all rules/escape hatches server-side in a safe read-only audit and stage denied calls. |
| HA-12: exposure of port 9583 | MEDIUM / passive confirmed | App host-network true and TCP/9583 published; direct trusted LAN connectivity observed earlier. Full IPv4/IPv6 binds and cross-segment reaches unknown. | Restrict *on host* only after verified loopback path, staged negative tests and OOB rollback. |

### Implementation note
The production-stated tunnel-client version is v0.0.15 but the actual binary's redirect, proxy, credential forwarding and revocation behavior has **not been independently tested**. The Python `mcp_url.py` patch cannot establish those properties. A successful 200/400/405/406 GET probe is evidence of reachability only, not credential validity. The new local JSON-RPC backend test is deliberately a **representative fixture, not real HA-MCP**.

Sources: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels ; https://github.com/homeassistant-ai/ha-mcp/blob/master/SECURITY.md ; https://github.com/homeassistant-ai/ha-mcp/blob/master/homeassistant-addon/DOCS.md ; `AUTHENTICATION_ARCHITECTURE.md`, `NETWORK_EXPOSURE.md`, `PHASE2_TEST_EVIDENCE.md`.
