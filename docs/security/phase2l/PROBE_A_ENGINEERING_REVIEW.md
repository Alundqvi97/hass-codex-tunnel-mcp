# Probe A — recovered implementation and adversarial engineering review

**Date:** 2026-10-09. **Decision: NOT READY.** No Probe A runtime authorization is requested, implied or consumed. No VM, QEMU, firewall or Home Assistant was touched. This document supplements the existing PROBE_APPROVAL_PACKAGE.md; it does not supersede Phase 2J's 16 genuine Supervisor acceptance gates.

## Recovery

PR #2 prior code and tests were recovered unchanged from commit d5f040f1746493809d895177e9accf3684850c4d, including probe_contract.py, probe_rehearsal.py and the approval package. Both PRs remain draft/unmerged. Pinned upstream HA-MCP 8.6.0 is fc54437a804858732e4bc927add98e202d879a09. The VM-triggering workflow Git blob is still f6b498b359d2cc9049558589cf8d29d95b417149 (own-file-path trigger only). Historical failed VM #37851915146 is not rerun.

## New reviewed code and source identity

Code commit before documentation: 252ced34a63ba07ac450f8edaf7842d956770b82.

| Path under docs/security/phase2l | Exact Git blob SHA | Implemented behavior |
|---|---|---|
| probe_a_dns.py | e2c2bea8099cd1bfa9e7dbbf7a5514f0e4a437dd | Bounded synthetic .invalid DNS query, strict transaction ID/question/NXDOMAIN and TCP framing verification |
| probe_a_client.py | f0210c59fc84c7104bce381551001f404ae8ec9d | Fixed UDP/TCP DNS socket operations, negative socket cases, safe category-only result; no executable CLI and no root-peer loopback handshake |
| probe_a_kernel.py | 0512870d1198d6be98b0e244df9c887769314580 | Strict synthetic iptables-save comparison, owned-hook precedence, intended rule order, bounded rule counters, pre/post restoration parser |
| probe_a_controller.py | 633932890a5772fed32957f954a15a40e23627b5 | DI bounded transaction, deny-first IPv4/IPv6 setup, per-case counter checks, deadlines, 60-second teardown reserve and mandatory cleanup readbacks, no live PASS |
| probe_a_exec_adapter.py | 888a8bc60a50c15eed010983998d161ead215b7a | Exact-plan argv sequencing and no retry, fixed 8-second per-command budget, bounded/sanitized synthetic backend results |
| probe_a_os_boundary.py | 46cc0a130eb0f5a1611c6621f1d4108e05910a21 | Optional real subprocess boundary (not activated), no shell, fixed command allowlist enforced again at the lowest layer, no automatic main/workflow |

Existing probe_contract.py, probe_rehearsal.py, Phase 2K policy and existing add-on/tunnel candidates were not replaced.

## Offline CI

On code commit 252ced34a63ba07ac450f8edaf7842d956770b82, Phase 2L non-VM GitHub Actions run #37937261004 passed **128 tests, zero failures**, including pinned upstream/patch source staging and Docker **build-context-only** validation. Other engineering CI conclusions on the final documentation commit must be independently checked; AI review failure is NOT independent qualified approval.

Test coverage includes: transaction ID and malformed DNS payloads; UDP/TCP syntax; negative destination set; reject-chain snapshots, owner-hook priority, IPv6 deny, wrong DNS and unknown rules; no proof from mere socket timeout; per-case counter increase; setup/teardown failure injection; every required cleanup readback even after a failure; deadline exhaustion; exact argv, identity/scope validation, no retries, no arbitrary shell or broader firewall flush; bounded output and direct low-level destructive command rejection.

All observations are injected, synthetic, or source-level. No Linux socket, kernel chain, DNS upstream or process owner was actually exercised.

## Adversarial review and residual defects

1. **Real command supervisor absent.** The controller's io callbacks and restricted argv runner have not been bound to one approved, exact runner identity/UID, actual firewall snapshots, account/process readbacks or a callable synthetic client as an end-to-end running test. Allowlist plans and the mock controller are not live enforcement.
2. **Termination safety absent.** The controller has a monotonic budget and passes per-call timeouts, but only an independently supervised watchdog/cleanup actor can protect against SIGKILL, GitHub cancellation, root process failure and partial IPv4/IPv6 installs. Cleanup cannot be assumed from the runner being disposable.
3. **Kernel provenance absent.** The parser validates text shape and counters, but a trusted independent runtime observer must collect real ipv4/ipv6 tables, verify backend/nft family, rule order and counter delta, check exact owner identity and prove unrelated rules unchanged.
4. **Socket harness incomplete.** DNS query and socket primitives exist but no reviewed entry point drops to numeric UID, runs every test exactly once, preserves the 30-second client budget, and supplies the separate root-side loopback ESTABLISHED peer. Failure by timeout is not proof of denial without a dedicated REJECT counter increase.
5. **Low-level output cap is postcollection.** A future supervisor should enforce a bounded streaming stdout reader, not depend solely on limiting collected output after a subprocess completes. Version/runner image and binary hashes require pinning or reject-on-drift.
6. **No host route attestation for QEMU.** Probe A can prove ordinary Linux owner-filter behavior only. A subsequent QEMU/libslirp-specific process or guest-originated DNS investigation needs entirely separate approval.
7. **Review independence outstanding.** These are same-agent adversarial checks, not independent expert or completed AI security review.
8. **No Docker image or real Supervisor proof.** Phase 2H/Phase 2J remain blocked; production NO-GO.

## One bounded immutable *draft scope*, NOT an actionable approval

**Reviewed source code SHA:** 252ced34a63ba07ac450f8edaf7842d956770b82. This is a frozen candidate reference for reviewing differences; an executable approval would need a newer final immutable commit containing the completed supervised runner and watcher, with all offline CI green. Do not treat this code commit alone as runnable.

Candidate future scope: One standard GitHub-hosted ubuntu-24.04 public-repository runner, one attempt, hard 5-minute job limit, at most 30 seconds synthetic traffic and 60 seconds reserved independent cleanup, temporary distinct numeric UID 42000–59999, separate unique owner chains IPv4/IPv6 only. Only reviewed public DNS 9.9.9.9 for positive UDP and TCP 53; alternate 1.1.1.1 TCP/UDP 53 for negative tests; fixed negative destinations 10.255.255.254:443, 169.254.77.77:443, ::1:443, 127.0.0.1:19467, and 1.1.1.1:443. Only p2-probe.invalid. No other external traffic or websites, no household endpoint, token, credentials, production, QEMU, HAOS, Docker, VM, packages, large/paid runner, artifact, packet capture, upload, retry or merge. Expected marginal standard public-runner charge USD 0 subject to actual GitHub billing eligibility; not independently confirmed. No custom IPv4/IPv6 rule should flush other chains.

**The exact request CANNOT be submitted for approval yet.** The future immutable SHA and the supervised execution/watchdog implementation do not exist. A human reviewer should first verify actual command stdout bounds, both-family rollback under every partial failure, denied traffic counters and protected post-cleanup snapshots. If any such check is infeasible, remain NOT READY.

## Smallest next engineering correction

Implement and mock-test one actual, bounded Probe A supervisor/observer that wires the existing exact argv gate + DNS/socket client to a temporary UID, enforces all deadlines externally, independently captures kernel/identity/counter snapshots and owns a cancellation-safe watchdog/cleanup routine. **Do not attach it to any workflow before a new permission boundary is reviewed.** Once that passes an independent review, a single separate runtime authorization can be requested at the final pinned SHA.

Probe B (QEMU/libslirp) is OUT OF SCOPE. Full HAOS/Supervisor and production stay NO-GO.


## 2026-10-09 follow-on: bounded-stream / independent-readback foundations (NOT READY)

Development commit `5c48379109afe5890796fd3ab5051fa10af8e240` adds unactivated `probe_a_stream.py` (bounded, nonblocking streaming stdout with fixed 128 KiB cap, per-process deadline and process-group kill attempt) and `probe_a_observer.py` (fixed read-only command vectors, backend-format check, UID/process and absent-chain preflight, exact counter-target ordering, snapshots and exhaustive named cleanup callbacks). New `test_phase2l_probe_a_supervision.py` injects fake commands, misleading changes and cancellation exceptions without privileged operations. These are components, **not** a supervised Probe A execution path or independent live attestation. GitHub CI outcomes for this new code must be checked separately; no test count is claimed here.

**Blocking engineering still missing:** the fully wired, pinned, hard-disabled single-runner entrypoint; real exact-argv bridge through the host boundary; external watchdog/cleanup actor that survives ordinary controller cancellation; independently observed partial-setup recovery and both-family cleanup under external failure; numeric-UID subprocess workload and root-controlled loopback peer; fixture-free real-kernel provenance; verification of complete cleanup after kernel drift. A same-process process-group kill is not SIGKILL or runner-termination recovery. The observer's independent-resource callback is a protocol, not an implemented listener/files/watcher/resolver observer. No runtime permission, independent reviewer sign-off or execution readiness follows. **Decision: NOT READY; minimum next fix is the supervised, separately owned runner/watchdog and end-to-end injected integration with verified teardown**, then qualified review and new explicit approval. No changes to VM workflow or production.
