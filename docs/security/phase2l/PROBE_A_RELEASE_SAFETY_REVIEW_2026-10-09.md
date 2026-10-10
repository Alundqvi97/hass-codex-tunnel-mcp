# Probe A — frozen offline release-safety review package

**2026-10-09 — NOT READY.** This is an immutable-code-reference **review request**, not an execution approval. Do not execute Probe A, apply firewall rules, boot QEMU/VM/HAOS, modify production, enable a privileged workflow, merge a PR or spend money.

## Exact subject
- Repository: `Alundqvi97/hass-codex-tunnel-mcp`
- **Code and test commit to review:** `150e5c0ce3cfbb20a9c9b07ca0e9a41942470c35`. This commit is immutable; this document commit follows it and does not expand execution authority.
- Original VM workflow blob to preserve: `f6b498b359d2cc9049558589cf8d29d95b417149`; past VM authorization consumed.
- PR #1 remains draft; PR #2 remains draft. No new runtime authorization.
- Latest engineering CI at code/test commit: [Phase 2L run #37948569379](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37948569379), **161 offline tests passed**. Phase 2D/2I/2J/2K workflows on this SHA also succeeded.
- AI security scan previously failed. This document was prepared by the implementing assistant; it is **not qualified independent review**.

## Scope to review
Read the final (newest) section of `PROBE_A_ENGINEERING_REVIEW.md` before its historical lists, then the existing `probe_a_{guardian,runner,recovery,attestation,resources,worker,workload,client_process,stream,os_boundary,observer,controller,kernel}.py`, `probe_contract.py` and `tests/offline/test_phase2l_probe_a_*.py`.

Check disabled entry and separate explicit approval/launcher; fork guardian versus parent; channel JSON limits; cancellation, EOF, SIGTERM, timeout and reserve; least-privilege exact-argv owner-only firewall operations; partial dual-stack setup/teardown; fail-closed drift detection; counter provenance and per-case deltas; numeric UID, capabilities, procfs listener and root-owned loopback peer; bounded streamed output and process-group termination; fresh before/after snapshots and all post-cleanup resources. Verify the 2026-10-09 narrow correction for volatile iptables-save timestamps and per-chain counters: only those volatile fields may be ignored, never a changed rule/policy/chain.

Review adversarially: a worker-supplied success string, mock result, or locally reported kernel text **must never create a trusted PASS**. Explicitly examine guardian SIGKILL, runner destruction and unresponsive privileged subprocess limits; never guarantee recovery beyond the surviving guardian/runner. Check that the runner's injected privileged boundary is not mistaken for a separately approved root launcher.

## Current review gate — FAIL CLOSED
1. No *qualified independent reviewer* has approved the code, IPC, privileged commands, signal handling, observation provenance and cleanup. Request a separate knowledgeable security reviewer who did not implement this work; ask for a written signed/attributed finding naming the exact code SHA, severity-ranked findings and any required fixes.
2. No approved pinned runtime image/binary/source-hash manifest or separately reviewed root guardian launcher/job exists. `ImageVersion` alone is not host attestation. GitHub runner privileges/capabilities, resource quotas and the external five-minute deadline require their own review before installation.
3. No trusted runtime PASS composer exists. Define and independently review a receipt path that accepts *only* independently acquired live kernel evidence (both families, UID/listener and per-case counters) and post-guardian reaped/clean resource readbacks, binds evidence to exact source + image and requires no missing fields. Existing `verdict()` and runner deliberately cannot return PASS; retain that guard until independently approved.
4. No real Probe A kernel behavior has been tested. A separate explicitly authorized one-attempt exercise is needed **after** the previous gates; no such authorization is present. Any host-specific drift must abort, never widen the test.

**Smallest next step:** commission an independent qualified security review of exact code/test SHA `150e5c0ce3cfbb20a9c9b07ca0e9a41942470c35` and this frozen narrow scope. Do not schedule execution. Review findings, required corrections and any future manifest/job/receipt gate must be separately accepted before asking for single-run authorization.

**Probe A scope only:** ordinary Linux host UID networking, not QEMU/libslirp, HAOS/Supervisor, or production. Production **NO-GO**.
