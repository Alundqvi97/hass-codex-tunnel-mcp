# Security patch rollback and future deployment gates

**No production deployment authorized.** Current known-good source is `def1d7235018745b880b573a944925352dea85a5`, with `mcp_url.py` blob `ad0afdc1d2aaec61390be0a108c8d6a18c853a57`.

## Offline branch rollback
Reverse only the reviewed source patch in an isolated checkout, or restore `custom_components/hass_codex_tunnel_mcp/mcp_url.py` from the known-good commit; rerun tests and byte-compare to the original blob. Reverting a Git commit on the development branch must not trigger production rollout. Draft PR remains unmerged unless expressly approved.

## Later production-only approval gate

1. Preserve the current HA integration release/commit and HA backup with independent local administrative recovery. Do not put configuration secrets in evidence.
2. Verify backend MCP `initialize` and `tools/list` with valid token; reject missing/invalid token. Prove hosted unauthorized caller denied. Test network paths and baseline tool permissions.
3. Rehearse integration upgrade, HA restart, host reboot, cold-start dependencies, network recovery, rollback and automated health checks in staging.
4. Apply only a specific reviewed/pinned commit after explicit approval and with no unrelated Control Plane change.
5. Abort and restore known-good code via supported integration workflow if HA fails to start, tunnel does not become ready, authorized read-only tool fails, previously blocked access is accepted, or unexpected sensitive logging occurs.
6. After rollback independently verify HA status, HACS version, MCP tools, tunnel health, recovery access and HA repair logs. Network isolation has its own independently tested reversal sequence.

**Security exception:** Do not downgrade solely to hide failed authentication without a separately approved risk acceptance. A rollback of a security fix can re-enable credential leakage, so a secure-disabled remote-admin state is preferable until recovery.


## Phase 2 refinement: availability and rollback dependencies

The integration's child-process watcher sets an exit status when the binary terminates unexpectedly; source inspection does not show an automatic restart. The health-URL-file sentinel does not prove request-level reachability. Phase 3 must add independent health checks and isolated restart/cold-boot/failed-update fault injection **before** a change window.

A future network restriction should be scheduled on the HA host rather than relying solely on inter-VLAN rules, because same-Home subnet peers do not necessarily traverse UniFi's routed firewall. Before changing anything: verify loopback backend routing from the HA Core/tunnel network namespace; establish a separate local console/HA UI path; inventory IPv6, local bind and NAT/UPnP; capture the exact listener configuration; and prepare a one-change reversible policy with a timed automatic revert. Abandon a change if independent recovery cannot be demonstrated.

The development patch also tightens `redact_mcp_url` for legacy authority userinfo; this must be included in the exact future manifest. No production change is authorized merely by adding these instructions.


## Phase 2B additional gates

A HACS-only source rollback does not reconfigure the HA-MCP backend's standard-mode authentication. A stronger ingress credential layer must be independently deployed and tested before any operator assumes an extra bearer provides security. Policy startup must **fail closed** when a configured policy gate cannot load, or a verified out-of-band control must prevent sensitive tools. Any fix requires a separate staged rollback that tests both policy enforcement and administrative recovery; never test it by restarting the existing HA-MCP add-on during Phase 2B.


## Phase 2C evidence-driven rollback boundary

Real pinned-source staging shows an additional tunnel bearer header is not validated in standard HA-MCP mode; rolling back a HACS tunnel source patch cannot fix backend recipient authentication. A later upstream HA-MCP fail-closed change may intentionally prevent startup when the policy guard fails: **ensure independent LAN/console recovery before installing**, and preserve the exact prior add-on image/version, data/config, and tested rollback method. Do not weaken security gates to restore convenience without an explicit exception. Stop and fail closed on policy init errors; don't attempt auto-repair using an admin tool that is protected by the failed gate. Treat the startup-log path as a credential in backups and diagnostic archives.


## Phase 2D isolated candidate reversal

Review-only: run candidate builder against upstream **fc54437a804858732e4bc927add98e202d879a09**, and capture `git diff` from the two modified files. `git apply --check -R` followed by `git apply -R`, `git diff --exit-code` and exact `git hash-object` comparison must restore `server.py` blob `bf848dcec8345eba603295933768fca6724c913b` and `start.py` blob `88e926a59f568dc9a9bf7bcd719b518b42f52baa`. Dedicated CI also reverses candidates separately.

**No production rollback procedure has been exercised.** A policy startup abort may deliberately stop remote MCP while Home Assistant remains operable; rollback MUST use independent local HA/Supervisor/console access, not ChatGPT tunnel tools. Preserve prior HA-MCP add-on image, data and source; ensure the known stored secret path is not rotated or revealed in logs. Stage platform boot and error recovery before approval.


## Phase 2E recovery addition

A Git reverse patch restoring exact `server.py` and `start.py` blobs is **not** a Supervisor-installed rollback. Full packaged image and UI recovery remain separate tests. A fail-closed add-on with bad policy must not be repaired through the unavailable remote MCP path.

Read-only backup metadata: 39 snapshots recorded; most recent snapshot metadata labels HA Core 2026.9.4 while running Core reports 2026.10.0. Verify current-version data/content compatibility and restore access using independent HA/Supervisor administration before any production mutation.

Strict-mode rule-effect conversion of the current 18 configured approval rules is prohibited without a reviewed semantic migration: equivalent rules in allow mode would automatically allow destructive actions. Do not use rollback to re-enable unrestricted admin actions silently.


## Phase 2F supported strict mode and safe policy migration

**Offline rollback verified:** `git apply -R` restored exact pinned original Git blobs of `server.py`, `start.py`, and `config.yaml` after Phase 2D+2F candidate application (CI #37846398572). That is NOT a real Home Assistant add-on uninstall/restore.

**Safe policy migration precondition:** never replace the 18 current `require_approval` rules by toggling `rule_effect` to `allow`. All 18 would become auto-authorized destructive names. Build a new reviewed positive list, preserve the old policy under protected admin-only backup, and test all alternatives before any approved change.

**Local recovery:** The mandatory marker intentionally prevents disabling security via a malformed/missing options file. In packaged synthetic recovery, an independent network-isolated root admin process restored the root-owned policy and restarted a valid container. Production needs supported local HA/Supervisor console/file or restore access, correct add-on image/data backup, plus a rollback drill before deploying; never attempt to repair a failed policy through the unavailable ChatGPT tunnel. Do not weaken marker permissions or expose the stored path in logs.

Backup inventory: 39 existing backups. Most recent dated October 8 includes HA+database but reports `homeassistant_version=2026.9.4` while Core reports `2026.10.0`. Verify metadata/restore compatibility and an independent recovery point before changing any service. No backup was created or restored here.


## Phase 2G additional rollback and isolated recovery receipts

- Narrow `src/ha_mcp/policy/middleware.py` patch is independent of Phase 2D/2F and guarded by upstream SHA `5b431906fe7a37bbc19e466ca92a34b491289298`. Final-approval revalidation ensures a policy that becomes corrupt/invalid during a wait blocks the action (synthetic FastMCP only). [GitHub CI #37848485823](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37848485823) verified `git apply -R`, `git diff --exit-code` and byte-exact original Git blob.
- This is **source rollback**, not a real add-on restore. Original upstream allowed stale previously approved calls on mid-wait policy change. Reverting the patch would re-enable that behavior, so production reversion must disable remote admin MCP until a reviewed remediation/version is available.
- Core+DB in the latest protected backup is established by read-only metadata. Whether Supervisor apps/add-on data and tunnel HACS integration are part of the backup is unknown. A backup can be labelled with earlier Core 2026.9.4 while current Core is 2026.10.0 because metadata records backed-up Core at creation; this is not an archive-format version.
- Exact authorized future local recovery order: independent HA UI/Supervisor admin → verify complete add-on-inclusive backup → preserve pinned original image/settings and reviewed policies → stop unsafe remote administrative MCP exposure on failure → restore the correct add-on image and `/data` policy/marker without falling back to unrestricted remote access → confirm startup and deny/approval behavior → check tunnel HACS/integration client separately → test logs and normal HA state before permitting remote admin. This drill has NOT run on production or HAOS VM.
- HAOS/Supervisor VM is blocked pending explicit approval; disposable QEMU container/VM installation on GitHub runner not attempted. Do not claim normal Docker add-on startup is a Supervisor restore.


## Phase 2H — exact regression rollback and one-guest destruction

Full revised in-process acceptance [#37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013) PASS: 196 original tests, 211 patched/revised tests (no deselections), exact original middleware + original two upstream tests restored after `git apply -R` (no dirty diff). **This is code rollback, not a Home Assistant OS/Supervisor add-on restore.**

First run #37851700140 stopped before any guest was started, cleanup confirms process and temporary files removed. Corrected single guest #37851915146 has finite timeout and an explicit teardown trap. Runtime cleanup verification after actual guest operation is PENDING. Guest QEMU image and private serial log are intentionally not published. If strict MCP fails, local Supervisor must stay usable; no unrestricted re-open of remote administrative MCP is permitted. No production backup contents downloaded or modified; 39 real backup records do not prove full add-on/tunnel restore.


### Phase 2H FINAL disposable VM cleanup and untested add-on restore

Single actual guest [#37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) ended controlled error code 3 on readiness timeout. The workflow emitted **`PHASE2H_GUEST_PROCESS_TERMINATED=PASS`**, **`PHASE2H_GUEST_PROCESS_CLEANUP=PASS`**, **`PHASE2H_TEMPORARY_VM_FILES_REMOVED=PASS`**, **`PHASE2H_PUBLIC_ARTIFACT_OR_CACHE_UPLOAD=NONE`**. The EXIT trap additionally attempts local runner iptables chains, temporary ACL and user cleanup, without distinct post-removal assertions; GitHub's standard runner is ephemeral. No household environment was modified.

**What passed:** strict candidate file source reversal and genuine pinned middleware regression (196 original, 211 patched/revised) with exact original test/source hashes. **What did not:** no Supervisor was reachable; local add-on files were only staged in VM disk and were never installed; no add-on rollback, synthetic backup restoration, HAOS host reboot or local admin during failed MCP state could be performed. Do not infer production restoreability. The post-run loopback-only firewall fix and sanitized serial milestones are unexecuted test-harness revisions, not a validated fix.
