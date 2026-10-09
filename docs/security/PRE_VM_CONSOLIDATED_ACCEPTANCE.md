# Consolidated pre-VM engineering acceptance — 2026-10-09

**Decision: NOT READY — SPECIFIC ENGINEERING BLOCKER.** Phase 2L's offline DNS/classifier, source-staging and Docker input checks are complete; the consolidated policy compiler, cleanup coverage model and adversarial regression tests are committed. The remaining key blocker is a trusted process-specific libslirp upstream resolver observation **and** a reviewed, atomic, verifiable rule-install/readback mechanism. Neither can be honestly claimed from a JSON fixture or an offline-only CI run. No new guest or production authorization exists.

## Baseline and immutable boundaries

Repository Alundqvi97/hass-codex-tunnel-mcp, PR #1 `security/tunnel-auth-hardening` draft, PR #2 `security/ha-mcp-phase2d-candidates` draft. Starting PR #2 HEAD `30057d82f01dfffc32fb523624b254917cfbeeca`. Pinned HA-MCP upstream `fc54437a804858732e4bc927add98e202d879a09`. Historical one authorized VM run #37851915146 failed before HAOS/Supervisor readiness and must never be retried on consumed approval. The workflow capable of booting a guest retains exact Git blob `f6b498b359d2cc9049558589cf8d29d95b417149`; it triggers only on its own filename and has **not** been changed.

**No guest, QEMU, Docker build, privileged networking, active firewall, NBD, host-service or household changes were performed.** Only pure source plus non-VM CI.

## Consolidated engineering changes and evidence

- New `docs/security/phase2l/egress_compiler.py` accepts one schema-validated **PROPOSED_ONLY** network manifest and emits deterministic IPv4/IPv6 `iptables-restore` *text* and an exact QEMU localhost-only user-netdev string. The code never runs or installs either output. Its receipt is explicitly `OFFLINE_PROPOSED_NOT_OBSERVED_NOT_ENFORCED`.
- DNS policy is one expressly declared public IPv4 resolver, **both UDP and TCP 53** to exactly that address. A process-private `/etc/resolv.conf` is the proposed control mechanism; mounting/validating one for the exact QEMU/libslirp process has NOT been implemented or tested. `-netdev user,dns=...` only changes the virtual guest-facing DNS address; it does not pin host upstream DNS. QEMU can reread resolver settings, so resolver drift must abort.
- Bootstrap HTTPS: source-reviewed FQDNs with bounded IPv4 response sets, observation timestamps and TTLs; **no permanent guessed CDN IPs**, no generic `tcp 80/443` allow, no unreviewed redirect, no broad localhost/private access. A changed/expired address set stops for regeneration, fresh evidence and new review. **Any JSON record is still a claim, not a DNS/TLS/SNI or kernel attestation.** The actual first-boot registries/auth/redirects are not exhaustively enumerated.
- Time: no blanket NTP permission. A single reviewed public IPv4 UDP/123 address is required in proposed policy; actual guest time-sync transport and endpoint are NOT VERIFIED.
- IPv6: QEMU `ipv6=off`, plus a separate host owner-chain IPv6 REJECT; unexpected QEMU options/forwarding rejected. IPv4 deny covers reserved, CGNAT, metadata/link-local, loopback, RFC1918, multicast and benchmarking ranges. Four forwards bind explicit 127.0.0.1 TCP addresses in the *source*. Real `ss` bound addresses and kernel owner/conntrack behavior still require a runtime check.
- The future-only runner remains intentionally blocked by `runner_preflight.py` **before sudo, firewall changes, image work or QEMU**. An extra guard prevents any exit 0 if 13 independent cleanup readbacks remain incomplete. No current workflow can create a new VM by modifying the new files.
- New `docs/security/phase2l/runtime_evidence.py` inventories the 16 Phase 2J acceptance cases and all 13 cleanup cases, with distinct readback instructions. It deliberately registers **ZERO live observers**; all provided observations remain synthetic and can never emit genuine runtime PASS or exit zero. Tests verify that even 16 synthetic PASS flags plus 13 synthetic cleanup flags yield exit 6.
- AST regression compares the QEMU launcher's literal `-netdev` source against the compiler output, preventing undetected option or localhost-forwarding drift.
- Phase 2K's fixed read-only positive policy `allow ha_get_overview`, strict-marker refusal, corruption preservation and first-start-only provisioning remain unchanged. Phase 2L tests stage the **actual** pinned and patched source and verify Docker COPY sources and SHA-256 matches of the helper/template. No private Supervisor /addons/data policy file is seeded.

## Real Docker build — not performed

The multistage Dockerfile's actual source paths, pinned base-image digest references, and pinned `pyproject.toml` / `uv.lock` inputs were reviewed and are present in the reproducibly staged context. `uv sync --locked` and the final runtime COPY cannot be fully validated without a real Docker build. The base images/uv dependency artifacts are not established as available in an offline local cache; building could require registry and package-index network, daemon access and external downloads. Under this phase's authorization, do **not** trigger that work and do not call source staging a successful image build. A later separately bounded, nonprivileged, no-network Docker build is acceptable only after verifying all required image layers and dependencies already exist, with no daemon privilege or external resource creation.

## 16 missing real acceptance observers (Phase 2J authoritative)

| Gate | Required independent live evidence; ALL currently NOT TESTED |
|---|---|
| HAOS_BOOT | Actual guest kernel/serial boot and health |
| SUPERVISOR_READY | Authenticated Supervisor health, version, running state |
| CANDIDATE_INSTALLED | Supervisor local-store install + correct source/image digest |
| STRICT_SCHEMA | Effective add-on schema, strict setting and option readback |
| RESTART_PERSISTENCE | Real add-on restart + rule/marker persistence |
| REBOOT_PERSISTENCE | Real HAOS reboot + persistence after reauthentication |
| SAFE_MCP_READ | Authenticated harmless synthetic MCP read, not a mock |
| CORRUPT_POLICY_DENIAL | Real corrupt-policy fault with secure dispatch denied |
| INIT_FAIL_CLOSED | Failed middleware initialization denies access |
| DOWNGRADE_DENIAL | Supervisor options downgrade cannot reopen tool dispatch |
| STALE_APPROVAL_DENIAL | Waiting approval revoked before execution |
| SECRET_LOG_REDACTION | No real synthetic secret-path exposure in sanitized logs |
| CONFIG_RECOVERY | Known-good, add-on-inclusive backup restore and healthy recovery |
| LOCAL_ADMIN_OUTAGE | Supervisor administration works while add-on is broken |
| FULL_ROLLBACK | Original installed image/config restored, verified digest |
| WATCHDOG_BOUNDED | Real bounded watchdog recovery under fault |

The full mandatory runtime gate is **not implemented**, and the current guest exits 6 if it somehow reached partial acceptance. No claimed status string may be mistaken for actual provenance. The separate AI review has failed and is not independent qualified security approval.

## Required independent cleanup readbacks

The 13 gate names are `guest_absent`, `watchdog_absent`, `hostforwards_absent`, `mounts_absent`, `nbd_detached`, `ipv4_rules_absent`, `ipv6_rules_absent`, `user_absent`, `kvm_acl_removed`, `guest_disk_absent`, `firmware_absent`, `serial_absent` and `scratch_absent`.

Required future independent checks: exact QEMU PID/executable owner; watchdog PID and /proc start-time; `ss -ltnp` for all forwarded ports **including wildcard binds**; `findmnt` and mountinfo; `/sys/block/nbd0/pid` plus NBD status; both `iptables-save` and `ip6tables-save` for chain+jump; numeric UID processes and getent account absence; `getfacl` for /dev/kvm; separate file-stat checks for disk, OVMF variable file and serial; and a final scratch-root and nested mounts check. A cleanup attempt, status log line, or disposable runner is not a substitute for each readback. Any missing or unreadable probe mandates nonzero exit. **These are not yet integrated as complete runtime readbacks**, and this source therefore deliberately blocks exit zero even on apparent guest success.

## Adversarial source review

**Strengths:** exact upstream SHA and source-patch anchors, strict positive allow-list, no automatic policy overwrite, only localhost hostfwd configuration, fail-closed network guard and 16-case acceptance state machine, no secret URL printing in synthetic receipts, immutable VM-trigger workflow, no PR merging.

**Residual risks:** (1) claims of a QEMU upstream resolver are not socket attestations, and mounting a process-private resolver requires unapproved namespace/privilege design; (2) QEMU -netdev option matching does not prove effective host socket binds; (3) any host firewall owner-match/NAT/conntrack bypass is only a hypothesis until checked in the kernel; (4) host-to-guest forwarding and redirected registry/CDN destinations still require exact runtime checks; (5) IPv4/IPv6 iptables-restore are two separate transactions and a partial family install can occur; rollback must read back both and fail on incompleteness; (6) frozen TTL snapshots may expire during multi-minute bootstrap; live refresh cannot automatically expand rules; (7) real image provenance, Supervisor installation and strict policy recovery remain unproven; (8) source compiler is NOT wired to live privileged rule installation while the pre-guest guard blocks; (9) incomplete cleanup and independent reviewer sign-off remain release blockers. These findings are pre-release test-harness issues, not proven production vulnerabilities.

## Smallest correction, then an explicit separate approval

**NOT READY — SPECIFIC ENGINEERING BLOCKER:** the planned process-private libslirp resolver and atomic owner-UID firewall workflow have no reviewed real observation and enforcement adapter. Implement a trusted, bounded **non-VM runner-only DNS route/egress probe** that can reproduce the QEMU/libslirp DNS forwarding path under a temporary UID with an exact resolver, then independently inspect the resulting destination sockets, UDP and TCP DNS, localhost binds, IPv6, private access denial, and iptables readbacks. It must abort and fully clean up on any mismatch, without booting HAOS or registering any persistent resource.

Such a probe **requires its own explicit, separate authorization before any QEMU process or privileged network test**. Prepare a purpose-built workflow that cannot invoke the existing guest workflow. A separate later one-time HAOS VM experiment would need additional approval specifying exact commit hashes, SHA-256 image, reviewed network configuration, one ephemeral standard Ubuntu runner, bounded resource/runtime limits, all 16 observers, rollback/cleanup criteria and no retries. This report grants neither approval.

**Cost and scope:** the repository is public; GitHub's documentation says standard GitHub-hosted runners for public repos are normally free, but a larger/paid runner, new artifact storage or hosted services must not be used. No household router, HAOS host, tunnel, VPN, Auth0, production server, secrets or billable infrastructure is involved in either proposed isolated test. Costs were not independently reconciled with the user's billing account.

Authoritative sources: https://www.qemu.org/docs/master/system/qemu-manpage.html ; https://github.com/qemu/qemu/blob/v10.1.0/net/slirp.c ; https://qemu.googlesource.com/libslirp/ ; https://developers.home-assistant.io/docs/apps/configuration/ ; https://docs.github.com/en/billing/concepts/product-billing/github-actions

## Source and CI identifiers

- Start SHA `30057d82f01dfffc32fb523624b254917cfbeeca`; latest pre-report source commit `7daa6234163325b4a89c096fdc7251facb066fc6`.
- Egress compiler Git blob `a4fdbd38653c870d7e9c72f3e02fcd2eaca6b8aa`; 16-gate/cleanup model Git blob `d84ac89cc89c373afa49cb3a007b579adb3cf778`; inactive runner Git blob `382f4e83b560156d0dba9c385cf478bc74968531`; regression test blob `0f2010da389fc2c7ed4a6dc3dda913a09ea49ac7`; VM-triggering workflow Git blob `f6b498b359d2cc9049558589cf8d29d95b417149` unchanged. Git object SHA values are not Docker image digests.
- [Pre-report pure Phase 2L CI #37930309772](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37930309772): **61 passed / 0 failed**; input Docker context staging passed. Prior initial 59-test run failed on two test assertions, and the next 61-test run failed on an incorrectly scoped fixture helper; both were fixed and the later CI passed. Final report commit CI must be checked on its own SHA.
- Overall engineering CI: must be checked at final HEAD. AI scanner failure is not accepted as a qualified independent review.

**Final release gate:** Phase 3 production NO-GO. Neither PR may merge. Any further probe/VM/deploy requires a new explicit approval.


## Single bounded network probe package — 2026-10-09

The future Probe A package is INERT source-only; no new workflow or privileged action is authorized. Scoped owner-UID iptables/ip6tables argv, deny-first dual-family setup, exact DNS UDP/TCP destination, narrow established-loopback reply and independently required rollback/readbacks live in docs/security/phase2l/probe_contract.py. Old potentially dangerous iptables-restore payload is replaced by non-loadable inert comments; unrelated firewall tables must never be flushed. Ordinary Linux process probe A does NOT prove QEMU/libslirp; QEMU probe B would need separate explicit QEMU approval and guest-originated DNS to prove upstream routing. See docs/security/phase2l/PROBE_APPROVAL_PACKAGE.md. NOT READY for live probe: bounded command executor, DNS client, kernel counters, deadlines and independent cleanup readbacks are not yet implemented; HAOS/Supervisor and production remain NO-GO.
