# Phase 2G — Review-only release compatibility and rollback manifest

**DO NOT INSTALL.** This manifest identifies exact known revisions; it is not a deployment script.

## Version contract and provenance

| Layer | Expected / current | Evidence | Pending |
|---|---|---|---|
| HAOS / Supervisor | Production HAOS (host version not established here) | Existing HA-MCP add-on metadata | Exact HAOS/Supervisor versions, image hashes and guest boot |
| Core | 2026.10.0 reported | Prior/current read-only baseline | Candidate against real Core+Supervisor |
| Community HA-MCP | 8.6.0, pinned source `fc54437a804858732e4bc927add98e202d879a09` | Real pinned unit and Docker package CI | Actual production image digest, upstream signed build, HAOS integration |
| HA-MCP custom component | 2.2.1 reported | Baseline | Coupled update/reload behavior |
| HA tunnel integration | `def1d7235018745b880b573a944925352dea85a5` HACS upstream revision | Baseline | Upgrade/reinstall and client OAuth/probe compatibility |
| OpenAI tunnel-client | v0.0.15 | Prior separate production upgrade verification | Current client release pin/hash and long-term authenticated attach test |
| Phase 2D/2F candidates | Review-only generated patches in draft PR #2 | CI as recorded | Signed upstream integration, Supervisor option persistence, complete rollout |
| Phase 2G middleware revalidation | Review-only `src/ha_mcp/policy/middleware.py` narrow patch | [CI #37848485823](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848485823) | Updated upstream compatibility expectations, real staged execution |
| Home Infra Control Plane/Auth0 | Separate work | Explicit project isolation | Optional future auth; not a prerequisite for this release |

No compatibility conclusion should be inferred merely because version strings exist. Current running tunnel works with unmodified production components; the modified HA-MCP package has not run under a real Supervisor, and hosted attachment limits remain untested.

## Mandatory preflight before promotion

- Confirm proper access to *independent* local HA/Supervisor admin.
- Verify a complete current-installation recoverable backup containing HA Core + database, HA-MCP add-on data and tunnel integration support files; verify protected restore capability without exposing credentials.
- Freeze/pin exact add-on source, OCI digest, HACS integration revision and tunnel binary SHA-256. Preserve original image and configuration for rollback. Record same image provenance after install.
- Disable **automatic HA-MCP add-on updates only in the future approved deployment window**, because production metadata currently reports `auto_update=true`; an automatic upstream upgrade would replace a locally modified add-on image and could remove strict mode or fail to read its marker. Unsupported manual image swaps are not a supported upgrade strategy.
- Ensure HA-MCP settings UI can show supported boolean `require_strict_tool_policy`, and staged restart and host reboot preserve it.
- Replace the old 18-rule `require_approval` configuration with a **new** approved positive allow list, never toggle old rules in-place. Keep old policy in protected admin-only backup. No automatic generic service/bulk/locks/security writes.
- Confirm policy middleware registered, sensitivity classification at FINAL operation, approval expiry/replay and denied routes, credentials not emitted in Python/FastMCP/Uvicorn/Supervisor/proxy logs.
- Verify tunnel backend transport/auth starts and stays compatible, including safe 401/403/redirect probe semantics.
- Confirm LAN TCP/9583 IPv4+IPv6 reachability boundaries; only change firewall/bind after independent staging and an approved timed revert.
- Confirm supportability: safe operator-approved rollback even when remote MCP is completely down.

## Rollback triggers (review-only thresholds)

1. MCP starts serving without strict middleware or with invalid marker/policy.
2. Any synthetic/admin sensitive operation bypasses approval or is executed twice on one token.
3. Secret path or backend bearer leaks into logs, HTTP redirects, URLs or error output.
4. Config option/marker disappears or automatic update silently overwrites secured version.
5. Critical local HA UI/Supervisor access lost, tunnel startup loop or watchdog restart storm.
6. Critical latency/availability regression, inability to restore reviewed policy or pinned image.
7. Cross-workspace unauthorized hosted tunnel attachment succeeds, or same-LAN/IPv6 access violates intended isolation.

On trigger: **stop remote administrative MCP exposure; preserve HA local control** and use independent local admin to restore the last reviewed secure image/policy. Never default to unrestricted policy to regain remote access. A source reverse-patch test is not a production add-on rollback drill.

## Cost and authorization

No new paid service is needed for source and Docker CI. Public standard GitHub-hosted Actions runs are documented as free/unlimited; full nested HAOS staging is experimental, not yet approved, and would require VM creation, guest image download and ephemeral runner host changes. No paid cloud VM, hosting, Auth0 license or secondary OpenAI identity is permitted without a separate estimate and explicit approval.

**Release status: NO-GO.** No actual deployment actions or firewall/credential changes have occurred.


## Phase 2H one-guest staging manifest, pinned and review-only

- GitHub: two unchanged relationship draft PRs (PR #1 tunnel/main, PR #2 upstream HA-MCP review on PR #1 branch); preserve no-merges/no production deployment.
- Source: `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09` + reviewed Phase2D logging/policy, Phase2F strict supported Supervisor option, Phase2H revised middleware; sources applied only in disposable checkout.
- OS asset: official `home-assistant/operating-system` release **18.3** / `haos_ova-18.3.qcow2.xz`; asset SHA256 `fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090`, reported size **510014132 bytes**. Guest Core/Supervisor exact running versions MUST be read from guest and cannot be assumed from production 2026.10.0.
- Host: standard public GitHub runner `ubuntu-24.04`, 2vCPU/4GiB guest, finite job runtime, ephemeral local KVM permission, apt QEMU/OVMF package, official image checksum required before decompression.
- CI full revised middleware [#37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013): **196 baseline and 211 patched tests pass, no deselections, exact rollback**. Genuine [single HAOS VM #37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146): result **PENDING at authoring time**; preserve test-level statuses, do not claim it installed/recovered an add-on.
- No Docker-only assertion substitutes for real Supervisor. No serial logs, disk images, sensitive settings, synthetic secrets or user production data to be uploaded.
- Required production release gates remain current full add-on-inclusive restore, independent admin, actual host reboot, unapproved hosted attachment tests, direct TCP 9583/IPv6 isolation, signed image provenance/update pin, final-action authorization, real deployment compatibility.
- Scope of private responsible disclosure: use upstream SECURITY.md private advisory process with verified minimal synthetic reproduction and no real secret. **Do not submit until explicitly approved.**
