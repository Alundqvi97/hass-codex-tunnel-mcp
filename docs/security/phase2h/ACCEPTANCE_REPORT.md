# Phase 2H — Final executed one-guest HAOS/Supervisor acceptance report

**Date:** 2026-10-08 UTC (2026-10-09 CEST). **Disposition: GENUINE SUPERVISOR ACCEPTANCE BLOCKED; PRODUCTION NO-GO.**

One authorized disposable QEMU HAOS guest attempt was executed. The VM process started and remained running during the bounded wait, but **Home Assistant HTTP never became reachable and no observer response was seen**. Therefore the guest OS boot completion, real Supervisor, reviewed add-on installation and recovery are NOT VERIFIED. A live QEMU process does not prove a healthy HAOS guest. **No further guest run is authorized.**

## 1. Exact source, image and environment

| Evidence | Value / result |
|---|---|
| GitHub repository | Public `Alundqvi97/hass-codex-tunnel-mcp` (standard public Actions runner; no larger/billable runner) |
| Runner job | `ubuntu-24.04` GitHub-hosted; [run 37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146), SHA `be7bfeba6524041c4c6551a77c70fd8532585a34`, **COMPLETED FAILURE**, controlled script exit 3 |
| Source | Genuine `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09` with separate source-checked Phase2D, Phase2F and Phase2H middleware patches **only in disposable checkout** |
| HAOS image | Official release **18.3**, `haos_ova-18.3.qcow2.xz`, **510014132 compressed bytes** |
| Image SHA256 | `fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090`; GitHub release asset provenance metadata verified preflight; downloaded artifact **SHA256 PASS** |
| Guest budget | One QEMU/KVM process, **2 guest vCPU / 4 GiB RAM**, bounded sparse disk, guest user-mode NAT, loopback-only forwarded test ports |
| Guest egress | Runner QEMU-UID iptables configured to reject RFC1918, loopback, link-local, multicast, IPv6 and non-HTTP(S)/DNS/NTP. **Configured, but actual egress enforcement NOT separately probed.** Public 80/443 hosts not domain-pinned |
| Host dependencies | Ubuntu 24.04 apt QEMU, OVFM 4MiB firmware and VARS file, acl, xz, iptables; `websockets==15.0.1` Python helper. Exact distro package versions **not separately recorded** |
| Guest OS/Core/Supervisor running version | **NOT VERIFIED** (booted runtime never answered); source image pin is not proof of boot state |
| Secret data | Only synthetic local ephemeral identity/data. No actual household hostnames, credentials, secrets, guest disk/serial logs or HA backup were exported |

### Execution commands and bounded timeouts

Workflow: [Phase 2H - One Disposable HAOS Supervisor Guest](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146), executed `bash docs/security/phase2h/runner_once.sh`. It pinned official release metadata, installed only Ubuntu repository tools on the disposable runner, gave temporary `/dev/kvm` ACL to a dedicated test UID, staged a local Supervisor add-on source via offline guest disk, verified SHA256 with `sha256sum -c`, and launched `python3 docs/security/phase2h/single_haos_guest.py` under `timeout --signal=TERM --kill-after=20s 2040s`. Python HA readiness bound: **780 seconds**; overall job 43 minutes max. No SSH, Tailscale, network bridge, self-hosted runner, paid cloud VM or external secrets.

First [preflight 37851700140](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851700140) failed **BEFORE** image download and any guest because Ubuntu 24.04 supplies `OVMF_CODE_4M.fd` rather than `OVMF_CODE.fd`. It cleaned up with no guest process. The corrected actual job 37851915146 is the **one guest** allowed by the approval.

## 2. Actual CI lines and sanitized evidence

| Receipt emitted by CI | Observed |
|---|---|
| `PHASE2H_REPOSITORY_PUBLIC` | PASS |
| `PHASE2H_OFFICIAL_IMAGE_DIGEST_METADATA` | PASS |
| `PHASE2H_RESOURCE_GATE` | PASS |
| `PHASE2H_KVM_ACCESS_PERMISSION` | PASS *(device ACL, not definitive KVM guest boot)* |
| `PHASE2H_GUEST_NETWORK` | USER_MODE_NAT_PUBLIC_WEB_DNS_NTP_ONLY *(configured rule set)* |
| `PHASE2H_PRIVATE_AND_IPV6_EGRESS` | BLOCKED *(rule construction; not independent negative network probe)* |
| `PHASE2H_REVIEWED_PATCH_APPLICATION` | PASS |
| `PHASE2H_DOWNLOADED_IMAGE_SHA256` | PASS |
| `PHASE2H_SUPERVISOR_LOCAL_ADDON_SOURCE_SEEDED` | true *(offline disk staging, NOT Supervisor installation)* |
| `PHASE2H_VM_GUEST_LIMIT` | ONE |
| `PHASE2H_HAOS_OBSERVER` | **NOT_OBSERVED** |
| `PHASE2H_HAOS_CORE_HTTP` | **BLOCKED_TIMEOUT** |
| `PHASE2H_SINGLE_VM_RUN_EXIT` | 3 |
| `PHASE2H_GUEST_PROCESS_TERMINATED` | PASS |
| `PHASE2H_GUEST_PROCESS_CLEANUP` | PASS |
| `PHASE2H_TEMPORARY_VM_FILES_REMOVED` | PASS |
| `PHASE2H_PUBLIC_ARTIFACT_OR_CACHE_UPLOAD` | NONE |

QEMU did not exit of its own accord during the 780s wait. The test harness terminated it and reported successful cleanup. **Failure cause is not established:** no sanitized kernel/serial milestones survived the run; host firewall and guest boot/bootstrap configuration remain hypotheses.

## 3. All 16 required acceptance cases

| # | Check | Actual execution outcome |
|---|---|---|
| 1 | HAOS reaches valid boot | **BLOCKED / NOT VERIFIED**: QEMU alive but no observer and no HTTP |
| 2 | Real Supervisor initialized | **BLOCKED**: API never reached |
| 3 | Reviewed HA-MCP add-on accepted/installed by Supervisor | **BLOCKED**: synthetic source staged into image only |
| 4 | Supervisor recognizes `require_strict_tool_policy` | **BLOCKED**: schema never queried |
| 5 | Strict option survives add-on restart | **NOT EXECUTED** |
| 6 | Strict option survives host reboot | **NOT EXECUTED** |
| 7 | Valid positive policy permits harmless synthetic MCP operation | **NOT EXECUTED** in guest |
| 8 | Missing/corrupt policy refuses privileged MCP operation | **NOT EXECUTED** in guest; prior packaged-only evidence exists |
| 9 | Middleware init failure fails closed | **NOT EXECUTED** in guest; prior source/packaged-only evidence exists |
| 10 | Security-option downgrade refused | **NOT EXECUTED** |
| 11 | Approved request revalidated after changing rules | **PASS in-process, guest NOT EXECUTED**; 211 patched tests |
| 12 | Secret path not leaked into actual guest startup/request logs | **NOT VERIFIED**; no real guest add-on request/log test, and the immutable run's previous fixed sentinel was not the actual generated path |
| 13 | Restore valid config and restart healthy add-on | **NOT EXECUTED** |
| 14 | Local HA/Supervisor administration available when MCP fails | **BLOCKED**: no accessible local HA/Supervisor API |
| 15 | Complete original image+configuration rollback | **NOT EXECUTED**; exact *source* rollback separate |
| 16 | Add-on watchdog bounded/no restart storm | **NOT EXECUTED** |

**No Supervisor installation or production recovery was demonstrated.** Docker/package and in-memory source tests are NOT equivalent to guest validation.

## 4. Full approval lifecycle and source rollback

[Independent full regression CI #37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013) **SUCCESS**:
- **196 original upstream source policy tests passed**, unchanged.
- **211 revised/patched tests passed with ZERO deselections**, including the two previously excluded old policy-change cases rewritten to enforce a fresh-approval invariant.
- Genuine FastMCP synthetic direct/write/delete/read proxy and token misuse tests included; exact upstream middleware AND original test source files restored with zero Git diff.
- Corrected code refuses policy corruption/mode/rule changes during a pending approval and prevents stale token reuse. It does NOT establish actual HAOS privileged backend enforcement or a true unconditional hard deny.

## 5. Test-harness security/observability design finding (NOT root-cause proof)

After the run, static analysis identified a possible **self-blocking local health-check rule**: QEMU ran with a per-UID `iptables OUTPUT` chain denying `127.0.0.0/8`. Because all host-forward readiness listeners bound to `127.0.0.1`, replies from QEMU's local server sockets could also be rejected, making a healthy guest invisible. This is a **reasonable hypothesis**, not empirically proven from this run. Guest bootstrap, KVM/UEFI and network failures remain plausible.

The review-only harness was subsequently updated (NOT executed in a second VM):
- Allow ONLY **ESTABLISHED** TCP replies from QEMU to host loopback; NEW guest-to-host localhost connections remain denied.
- Capture fixed Boolean-only guest serial milestones on boot timeout; never publish the raw serial log or secrets.
- [Static-only CI #37853632264](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37853632264) **SUCCESS**: Bash/Python syntax and firewall guard order, not network effectiveness.

The approved single guest experiment is now consumed. **Do not rerun the VM without new specific user approval.**

## 6. Cleanup, charges, limitations and approvals

- **Observed cleanup:** VM process stopped twice-checked by harness; test working directory fully deleted; no artifact/cache upload. The EXIT trap also *attempted* to remove temporary firewall chains, host KVM ACL and test UID; those particular host-state removals did not each have a separate read-back receipt. The hosted runner itself was ephemeral.
- **Cost:** no larger/paid runner, persistent disk, marketplace resource, additional service, identity or billable hosted infrastructure created. Under GitHub's published public standard-runner policy, Actions usage incurs no separate charge. No direct access to account invoice, so no assertion of invoice reconciliation.
- **Production:** zero Home Assistant, Ubuntu home-infra, Windows desktop, UniFi, Tailscale, tunnel/credential, Auth0, Control Plane, OpenClaw or backup changes; PRs remain draft.
- **Unverified release gates:** full 16-test actual Supervisor suite, independent current-version add-on+HACS restore, hosted unauthorized attachment, least-privileged hard deny, installed-image provenance/update pin, IPv4/IPv6 port isolation, tunnel-client crash recovery, secret-path log proof on real guest.
- **Security disclosure:** upstream `SECURITY.md` directs private vulnerability reporting to https://github.com/homeassistant-ai/ha-mcp/security/advisories/new. No report or upstream PR was submitted; separate approval required.

## Final decision

**Phase 2H SOURCE ACCEPTANCE PASS / DISPOSABLE GUEST CLEANUP PASS / GENUINE HAOS-SUPERVISOR ACCEPTANCE BLOCKED. Phase 3: PRODUCTION NO-GO.** The next highest-value action, if explicitly authorized later, is one fresh *offline-observable* isolated guest test of the corrected loopback/firewall behavior and real Supervisor, then completing the outstanding remaining checks. No second guest was started here.


## Phase 2I offline follow-up (2026-10-09; not part of original guest result)

Phase 2I adds only synthetic diagnostics, guard and cleanup models in `docs/security/phase2i/offline_harness.py` and `tests/offline/test_phase2i_harness.py`, with a dedicated no-QEMU Python-only workflow. The historical run #37851915146 stays FAILED/BLOCKED. Classifiers do not contact a socket, boot a VM, validate kernel conntrack or prove Supervisor. See `docs/security/phase2i/REVIEW_AND_FUTURE_ACCEPTANCE.md`. No new guest authorization; any later acceptance must pin reviewed commit/hashes and obtain separate explicit approval. Phase 3 production NO-GO.
