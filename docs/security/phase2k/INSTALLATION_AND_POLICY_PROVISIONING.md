# Phase 2K — Local add-on source installation and policy provisioning

**Recorded 2026-10-09. Verdict: NOT READY for another VM approval.** This is an offline-only implementation candidate. The original single authorized HAOS guest [#37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) remains FAILED to reach HAOS/Supervisor. No authorization to rerun exists.

## 1. Supported contract versus new candidate

Official [Home Assistant app configuration](https://developers.home-assistant.io/docs/apps/configuration/) documents an app's persistent /data volume, its Supervisor-managed /data/options.json, schema validation, and packaging with a Dockerfile. Supervisor 2026.10.1 source confirms discovery under apps/local, local_ slug derivation, store reload/install and apps options/start/status routes. The HAOS 18.3 guest's actual running Supervisor version has **not** been observed.

The pinned HA-MCP 8.6.0 implementation already persists tool_policy.json within its own writable data directory. It already provides a policy editor through the settings UI, but the add-on root settings routes are intentionally limited to HA ingress (direct callers without the required secret receive 403). The new candidate neither changes these routes nor calls an undocumented remote import API.

The old harness wrote tool_policy.json into Supervisor's private host-side addons/data path before the guest booted. That shortcut was **not** a Supervisor-managed install or a supported policy restore, so Phase 2K eliminates it.

## 2. Reproducible new approach

The future-only runner still mounts an offline, checksum-verified disposable HAOS image. It now stages **local add-on SOURCE ONLY** at supervisor/apps/local/ha_mcp_phase2h, rather than directly constructing private add-on data. This bootstrap staging relies on the Supervisor 2026.10.1 local-source folder contract; it is NOT itself installation and is NOT runtime-verified on HAOS 18.3. If the guest version does not match a reviewed source contract, abort rather than guess.

The pinned upstream HA-MCP checkout receives previously reviewed Phase 2D, 2F, and 2G patches, then the anchored Phase 2K source patch. Phase 2K's added app option **bootstrap_reviewed_policy** is boolean and false by default. The patched Dockerfile includes a fixed, synthetic policy template and a small startup helper in the candidate image. The future guest must ask authenticated Supervisor to reload the store, identify the correct local candidate, install the app, confirm image/source identity, verify strict schema, write and read back full options, then start it.

Required options at first start: **enable_tool_security_policies=true**, **require_strict_tool_policy=true**, **enable_security_policy_tool=false**, **bootstrap_reviewed_policy=true**. A POST success alone is not proof: the installed app, effective options and real runtime health must be independently observed.

On first start the candidate helper reads Supervisor's own /data/options.json and may create missing /data/tool_policy.json *inside the app's persistent volume*, not in Supervisor's private host-side operational state. It requires exactly the packaged allow-list containing only ha_get_overview with no predicates, exclusive file creation, mode 0600 and fsync. It never overwrites an existing policy, even if corrupt; if a persistent strict marker exists but the policy is missing, startup must stop. The existing strict marker and runtime policy checks run **after** the new bootstrap and before the MCP listener. No remote AI policy-editor tool is enabled.

This is an **implemented new developer-side mechanism**, not a feature verified in the upstream release or real Supervisor. An interrupted write deliberately leaves a potentially invalid file that causes future fail-closed refusal; it is never silently healed or reset.

## 3. Recovery and rollback

If strict policy becomes corrupt, the bootstrap helper will NOT reset it. Independent local Supervisor administration remains necessary. A supported-direction recovery uses a previous known-good, add-on-inclusive Supervisor backup and its documented restore operation, followed by add-on configuration/digest verification and denied/allowed MCP tests. The HA-MCP authenticated ingress policy editor may be usable while the app is healthy, but it cannot repair a completely failed-to-start app. A recovery test must prove the actual backup contains the app's persistent /data and options and that restoring it works; source rollback and mock file replacement do not count.

The runner's actual teardown must separately read back the absence of QEMU, watchdog, forwarded listeners, mounted filesystems, NBD attachment, temporary guest/firmware/serial files, firewall rules/jumps, temporary user and KVM ACL. Current runner checks only a subset; a cleanup attempt or an ephemeral GitHub runner is NOT independent cleanup proof.

## 4. Version and source evidence

| Item | Verified from official published source | Not verified in guest |
|---|---|---|
| HAOS 18.3 OVA image | Official SHA256 fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090, 510014132 compressed bytes | Boot completion, actual Core/Supervisor version, source discovery |
| Supervisor 2026.10.1 | apps/local and apps/data; local_ slug prefix; V2 store/apps/{slug} install, apps/{slug}/options and start; conditional legacy migration | Whether the HAOS image uses this exact version or supports this staged directory |
| HA-MCP upstream 8.6.0 | Pinned source commit fc54437a804858732e4bc927add98e202d879a09, persistent /data policy and existing UI | Actual candidate image digest, strict options/restart/real backend |
| Phase 2D/2F/2G patches | Prior source/packaged/approval CI successful; strict marker blocks silent downgrade | Guest-side runtime and true failure recovery |
| Phase 2K bootstrap candidate | Anchored patch applies in pinned disposable checkout; synthetic package, options, failure and recovery fixtures pass | App build/install, first boot and supported Supervisor policy backup restore |

Key upstream sources:
- https://developers.home-assistant.io/docs/apps/configuration/
- https://github.com/home-assistant/supervisor/blob/2026.10.1/supervisor/config.py
- https://github.com/home-assistant/supervisor/blob/2026.10.1/supervisor/bootstrap.py
- https://github.com/home-assistant/supervisor/blob/2026.10.1/supervisor/store/data.py
- https://github.com/home-assistant/supervisor/blob/2026.10.1/supervisor/api/__init__.py
- https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/src/ha_mcp/settings_ui/__init__.py

## 5. Synthetic verification

Dedicated **Phase 2K - Packaged Initial Policy Offline** workflow executes strictly non-VM work. It checks out the exact pinned upstream commit, applies Phase 2D/2F/2G and Phase 2K source patches in a disposable checkout, runs standard-library negative tests, checks Python and Bash syntax and Git diff, without Docker, KVM, sudo, QEMU, privileged networking, OS-image mounting, a home system or OpenClaw.

Tests cover: strict option/armed bootstrap and wrong types, pinned template tampering, missing source or settings, symbolic links, pre-existing valid and corrupt policies, mandatory marker, interrupted fsync, mode 0600, synthetic external restoration, rejected unsupported patch anchors, zero private Supervisor data seeding, manifest/source-image identity failure, absent store, rejected install request, install acknowledgment without an installed digest, strict schema/options readback failure, missing policy/unsafe dispatch, startup, recovery, cleanup and incomplete Phase 2J sixteen-case acceptance.

**A fully successful synthetic scenario still returns SYNTHETIC_COMPLETE_NOT_REAL_SUPERVISOR, never actual guest acceptance.** The current future guest launcher continues to return nonzero 6 for incomplete mandatory cases. No test creates a VM. CI run IDs, count and final conclusion must be checked against the final HEAD after this report is committed.

## 6. DNS preflight: BLOCKED, no live networking

QEMU's guest-visible default DNS server 10.0.2.3 is not proof of which host resolver libslirp uses. The user-mode dns= option controls the **guest-visible** address, not necessarily upstream. Runner Linux might have localhost 127.0.0.53 or a private resolver rejected by the QEMU-UID firewall. Current proposed egress permits generic public UDP/53, not TCP/53 fallback. TCP ESTABLISHED loopback health-check exception remains a hypothesis, not observed conntrack behavior.

Before any future guest authorization, design a **pre-guest** bounded runner-only fail-closed resolver/egress check: classify actual runner upstream including stub-versus-real target, verify allowed DNS destinations for UDP and TCP/53 without broad localhost access, constrain public 80/443 for bootstrap where feasible without pinning guessed CDN IPs, confirm QEMU-UID owner/forwarding and IPv6 controls, abort on unknown/private/loopback/IPv6/bypass. A live privileged kernel negative test, if proposed, needs separate permission. No DNS or guest networking preflight was executed in this phase.

QEMU reference: https://www.qemu.org/docs/master/system/qemu-manpage.html

## 7. Exact committed evidence

Starting PR #2: 83be805ecfd95cee818a18f13188c59b0b4a1ef6. Source state prior to final documentation/test tightening: 92ef44287709385e0a87c6e5a2524dd367019a83. Exact final commit and CI results must be verified subsequently.

Immutable **VM-triggering workflow blob f6b498b359d2cc9049558589cf8d29d95b417149**: unchanged. Future runner shell blob aa0c838dd397f5b9db7ce8aadc96f6a3284a9c9c and future guest adapter blob 91c4d1b424f5c9c7ae016ad1acd44da6836f5421: never executed as a guest. Initial Phase2K bootstrap blob 99782515eb4c1426c1f498534bbd6620a43d2b47, fixed policy-template blob 90442aa198c87d6f3930478c89a74d9bb0a96bcb, source-patch blob 3121632c099ac53234269b36ec683dce64d91b06. All Git blob SHA1 identifiers are source identity markers, not runtime image digests.

## 8. Release decision

**NOT READY FOR A NEW VM APPROVAL.** The policy-provisioning blocker now has a safe developer-supported *candidate* and negative tests. However, the DNS/egress preflight, precise real Supervisor version+installed-image proof, complete 16 runtime case observers and independent cleanup/restore drill remain materially incomplete. Production Phase 3 NO-GO; Phase 4 unauthorized; no PR merge.

**Single smallest next engineering action:** implement the bounded **pre-guest DNS/egress preflight model and abort condition** with offline fixtures and review, keeping the VM-triggering workflow unchanged. Do not request another guest yet. Separate qualified security review remains unavailable; this phase is NOT an independent approval.
