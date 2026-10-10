# Phase 2I — Offline-only preparation for HAOS/Supervisor acceptance

**2026-10-09. Status: OFFLINE MODEL ONLY; VM NOT AUTHORIZED; PRODUCTION NO-GO.**

## Evidence boundary

Historical immutable guest: https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146 (failed HTTP and observer readiness; no known root cause; teardown process and directory receipts passed).
Full source-policy regression: https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013 (196 original + 211 patched/revised, all pass; source rollback pass).
Phase 2H independent static findings are preserved in `docs/security/phase2h/OFFLINE_RECOVERY_REVIEW_2026-10-09.md`.
The Phase 2I classifier remains a pure, inert Python model. A narrow future-only runtime adapter is now included in `phase2h/single_haos_guest.py`: it classifies observed HTTP errors, refusal, timeout and absent localhost listeners using fixed labels and does not emit URL/error strings or HTTP response bodies. It also explicitly sets QEMU `ipv6=off`. **This adapter is unexecuted in any guest**: Phase 2I CI imports and tests the classifier and checks adapter source but never calls the VM launcher's `main()`. No service, firewall or host was changed.

## Confidence-ranked review

| Area | Supported offline | Not proven |
|---|---|---|
| Loopback | Original QEMU-UID OUTPUT would reject 127/8; proposed ESTABLISHED TCP loopback exception precedes rejects; synthetic ordered-rule check passes | Actual QEMU process owner and -o lo, reply conntrack state, SYN-ACK delivery, host listener reachability |
| DNS | QEMU user network gives guest DNS 10.0.2.3 but host-side QEMU resolver destination depends on runner. Loopback/private resolver can be rejected by owner OUTPUT; pure resolver classification tested | Real /etc/resolv.conf and QEMU resolver target during guest boot |
| Gateway | Default QEMU user network 10.0.2.2 host / 10.0.2.3 DNS; synthetic blocks their host-side private targets | Complete guest-to-host isolation, no alternate route via host networking, real egress counter proofs |
| IPv4/IPv6 | Synthetic public 80/443, UDP 53/123 allow; RFC1918, CGNAT, link-local, loopback and IPv6 deny. Proposed QEMU lint insists on `ipv6=off` | Kernel iptables/ip6tables efficacy; allowlisting actual bootstrap registries; IPv6 still enabled in previous QEMU command |
| Readiness | Classifier distinguishes process exit, no listener, TCP refusal/timeout, HTTP 404/other, possible first-boot, Core, and ordered Supervisor/store/install/running milestones. No untrusted body or exception string returned | Adapter exists in future-only launcher but has NOT observed a real QEMU/HTTP socket; `/manifest.json` alone and generic HTTP responses cannot prove Supervisor |
| Disk/store | `hassos-data` must be a unique ext4 NBD filesystem label; no positional p8 trust; reject legacy-only local path until compatibility demonstrated | Image's real filesystem layout; Supervisor revision/migration on guest; local store reload and installed schema |
| Cleanup | 15-item independent synthetic post-condition checklist, including child/watchdog/forwarders, NBD, mounts, ACL, chains, UID, firmware/disk/log/temp | Original job's firewall/ACL read-back, future privileged restoration effectiveness |

The ESTABLISHED exception is TCP-specific. It does not permit localhost UDP DNS for a loopback resolver. Also, QEMU user networking has an internal virtual gateway; host rules see QEMU-owned host sockets, not guest's original 10.0.2.x destination. Never interpret a synthetic verdict as kernel isolation proof.

## Version-specific supportability and discovery

| Version/source | Verified from published source | Remaining assumption |
|---|---|---|
| HAOS 18.3 official partition spec | Data filesystem label `hassos-data`, mounted at `/mnt/data`; Core is not preinstalled and first boot downloads it | Original p8 positional assumption, contents of downloaded 18.3 image, timing and connectivity |
| Supervisor 2026.10.1 bootstrap source | Migrates legacy `addons/{core,data,local,git}` into `apps/` only if target absent | Actual guest Supervisor version, whether both paths exist, and migration success |
| Supervisor 2026.10.1 store code | Reads local apps from `path_apps_local` | Store reload, install and option persistence on true guest are not verified |
| HA-MCP upstream 8.6.0 pin | SHA-guarded source and packaged tests passed | Real Supervisor add-on build, installed image digest, strict option on restart/reboot |

Sources: https://developers.home-assistant.io/docs/operating-system/partition/ ; https://www.qemu.org/docs/master/system/qemu-manpage.html ; https://github.com/home-assistant/supervisor/blob/2026.10.1/supervisor/bootstrap.py ; https://github.com/home-assistant/supervisor/blob/2026.10.1/supervisor/store/data.py .

## Future single experiment — proposal, not approval

Prerequisite: independently review and improve the proposed runtime observer, including any remaining unclassified bootstrap conditions; prove they emit only finite enum values and never bodies, URLs, secrets or raw serial. Resolve QEMU DNS via explicit bounded resolver plan, user-mode forwarding, `ipv6=off` and host egress enforcement. Demonstrate data partition label before any offline seeding. Prefer supported local apps source route and real Supervisor store/install endpoints; no arbitrary private data-state writes. Add cleanup independent read-back even for partially initialized firewall chains.

Freeze **exact PR #2 commit SHA after CI** plus SHA-256 of `runner_once.sh`, `single_haos_guest.py` and the unchanged VM-triggering workflow; obtain a second reviewer signoff. Use official HAOS 18.3 OVA QCOW2 SHA256 `fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090` (510014132 compressed bytes), pinned HA-MCP SHA `fc54437a804858732e4bc927add98e202d879a09`.

One new standard *public repository* GitHub-hosted Ubuntu 24.04 runner only; exactly one QEMU/KVM guest, 2 guest vCPU, 4 GiB RAM, 32 GiB sparse logical disk, 11.5 GiB host sparse-usage stop threshold, 43-minute maximum job / 2040-second harness timeout, 780-second initial readiness bound unless a separately reviewed finite staged-time budget is approved. Temporary runner-only KVM ACL, test user, firewall and NBD mount permissions; zero production credentials. Public standard-hosted runner is documented free under current GitHub policy, but repository billing/invoice is not independently verified. No paid resources.

Allow only essential, recorded public bootstrap web and a reviewed DNS/NTP path. Guest/user-mode network must be unable to reach house/LAN/link-local/loopback or unexpected IPv6 paths. Test sanitized observer, first boot, Core, genuine Supervisor API/running; identify add-on in store, install, strict option persistence after app restart and host reboot, positive read and negative policy/approval, secret log protection, failed-config independent admin recovery, full original image+configuration rollback and watchdog bounded behavior. Record exact 16 acceptance cases from Phase 2H. Abort on unknown DNS target, failed isolation/read-back, unexpected hostforward, secrets in sanitized output, supervisor deadlock, unsupported local-app injection, resource bound or failed cleanup. No automatic retry.

**New authorization required:** user must explicitly approve *that* exact immutable commit, hashes and a single additional disposable HAOS guest with temporary runner privileges and the above budget, isolation and no-retry restriction. Approval cannot be implied by this document or by source CI. Any kernel-only networking exercise is a **different** approval (not covered here).

Phase 2G/2H source checks do not establish genuine Supervisor. Hosted unauthorized attachment, real least-privilege and home backup/recovery, network boundaries and production compatibility remain independent NO-GO gates.

## Phase 2I follow-up harness integration (offline-only)

At code HEAD `6617d6cded7cb6edb712c79af9f95045aab574c2`, the future-only `single_haos_guest.py` imports the pure classifier and emits a finite `PHASE2H_PHASE2I_READINESS_DIAGNOSTIC` timeout receipt in addition to preserving the legacy output categories. It checks localhost LISTEN state (where available), distinguishes HTTP error status, refuses to include exception text, and adds QEMU user-mode `ipv6=off`. This improves the *potential next run's* observability but does not prove packets are actually accepted or blocked. **No QEMU or network runtime test performed.** It intentionally does not change `runner_once.sh` privileged commands, local add-on disk staging or the VM-triggering workflow. Those should be hardened after independent review, before any new VM approval.

New [offline push CI #37913475390](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913475390) and [offline PR CI #37913479830](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913479830): **13 passing tests**, no skips or failures. [Static Phase 2H #37913475242](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37913475242) SUCCESS; no guest. The failed historical VM is unchanged.


## Phase 2I second static hardening follow-up — no guest execution

Future-only `runner_once.sh` now requires a **unique ext4 block device labelled `hassos-data`** before mounting the disposable NBD partition; the old positional `/dev/nbd0p8` mount assumption was removed. It stops before guest creation if the filesystem label or local source staging is not verified. It now attempts partial firewall-chain cleanup after the first chain is created, stops its watchdog in the exit trap and emits separate read-back receipts for IPv4/IPv6 rules, KVM ACL, test UID and mounts. These are **source-level improvements, unexecuted**, not proof of actual privileged rollback. The local-source staging itself remains a supportability hypothesis (legacy `addons/` vs current `apps/`), and guest bootstrap DNS remains unresolved. Existing CI performs bash syntax and synthetic source/cleanup checks only. No VM, sudo, iptables or NBD command was executed by Phase 2I.


### Phase 2I final-acceptance fail-closed correction (2026-10-09; offline only)

Independent source review found a **false-green risk**: the future guest script's `main()` returned exit 0 even when `test_addon()` returned early (store discovery blocked) or raised an exception, while many of the 16 Supervisor acceptance cases were still unimplemented. This was a defect in the *unexecuted test harness*, not a proven production flaw. The review candidate now refuses a false-green result: it requires a confirmed running Supervisor for the preliminary gate, reports `FULL_SUPERVISOR_ACCEPTANCE=BLOCKED_INCOMPLETE_16_CASES` and returns exit **6** after partial add-on testing. This deliberately cannot claim a successful guest acceptance until all mandatory cases receive independently proven PASS results. Pure offline mocks test success-like responses, exceptions and absent source without launching a guest, starting a network service, or using privileged commands.

**Still unverified:** real QEMU owner/conntrack/DNS, actual HAOS boot and installed Supervisor, supported current-apps local store seeding, full strict-policy negative tests, genuine backup restore and watchdog behavior. No additional VM authorization or production change; preserve historical failed run unchanged. Source-gate review only; CI status must be checked on the exact commit.


## Phase 2J final offline acceptance gate (2026-10-09)

The 16-case pure state-machine and adversarial negative tests live in `docs/security/phase2j/acceptance.py` and `tests/offline/test_phase2j_acceptance.py` with a dedicated Python-only CI workflow. No live guest, network or privileged activity is performed. The review identifies unresolved host-side DNS upstream+TCP fallback, unsupported direct Supervisor `/data` provisioning, incomplete live 16-case observers and separate cleanup-readback gaps. This is **NOT READY** for another VM authorization. The historical failed Phase 2H guest is immutable; the future guest launcher intentionally continues to return nonzero for partial acceptance. See `phase2j/FINAL_OFFLINE_READINESS.md`; independent reviewer sign-off remains outstanding. Phase 3 production NO-GO.
