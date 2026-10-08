# Phase 2H — One authorized disposable HAOS/Supervisor acceptance experiment

**Evidence dated 2026-10-08 UTC / 2026-10-09 CEST.** At initial receipt creation, genuine [single VM #37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) was **IN PROGRESS**, **NOT YET VERIFIED**. The report MUST be revised with the complete log/cleanup before final acceptance. Phase 3 production **NO-GO**.

## Authorization and provenance

- Only standard GitHub-hosted `ubuntu-24.04`, existing public repo, one synthetic guest, runner-only packages and KVM ACL, no paid runner/VM, no household, server, router, credentials, backups, OpenClaw or Control Plane.
- Source `homeassistant-ai/ha-mcp@fc54437a804858732e4bc927add98e202d879a09`, reviewed Phase2D+2F+2H isolated source patches.
- HAOS official release 18.3, `haos_ova-18.3.qcow2.xz`, 510014132 compressed bytes, SHA256 `fae6a728768cc10aff60d4820bfcd40d64cd77fab82c8bd92af13b3d9d414090`. Guest actual Supervisor and Core versions remain unknown until guest reports.
- Host guest: 2 vCPU, 4GiB RAM, sparse guest disk upper bound, up to 43 minute standard-hosted job, local-only forwarded API ports and user-mode NAT, temporary QEMU UID firewall blocking private networks/IPv6 and non-HTTP(S)/DNS/NTP egress. Public HTTP(S) hosts are not limited to a domain allow-list. No guest artifact/cache uploaded.
- First [preflight #37851700140](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851700140): **FAILED** before download/guest boot because standard Noble OVMF uses `OVMF_CODE_4M.fd`, `OVMF_VARS_4M.fd`. Cleanup reported guest processes removed, private temporary dir deleted, no artifacts. First attempt did not consume the authorized guest.
- Later corrected [single guest #37851915146](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851915146) is the **only actual guest attempt**; do not rerun after it creates any VM without additional approval.

## Independent approval-security regression

[Full pinned source CI #37851968013](https://github.com/Alundqvi97/hass-codex-tunnel-mcp/actions/runs/37851968013) **PASS**:
- Original upstream unit policy suites: 196 passed.
- Revised two historical assertions for stale authorization plus real FastMCP synthetic acceptance: 211 passed with no excluded tests.
- Exact source+test reverse patch restored original blobs and zero diff.
- Proven: blocked/replayed/denied timed-out approvals, dynamic selector semantics, changed args/policy/corrupt mid-wait and in-process read/write/delete proxies (as bounded by actual tested cases). No real HA household backend calls.

## 16 genuine Supervisor acceptance matrix

The following table is intentionally **unverified until the completed guest log is independently inspected**. PASS must not be borrowed from in-memory tests.

| # | Required gate | Guest evidence at initial creation |
|---|---|---|
| 1 | Genuine HAOS boots | PENDING |
| 2 | Supervisor ready and local API | PENDING |
| 3 | Reviewed add-on installed through Supervisor | PENDING |
| 4 | Supervisor recognizes strict add-on option | PENDING |
| 5 | Strict option persists after add-on restart | NOT VERIFIED |
| 6 | Strict option persists across HAOS host reboot | NOT VERIFIED |
| 7 | Valid positive policy permits harmless synthetic MCP operation | NOT VERIFIED |
| 8 | Missing/corrupt policy denies privileged MCP operation | NOT VERIFIED |
| 9 | Failed mandatory policy middleware initialization refuses startup | NOT VERIFIED |
| 10 | Attempted security downgrade refused at effective runtime | PENDING |
| 11 | Approved requests revalidated after policy changes | PASS in-process only; guest NOT VERIFIED |
| 12 | Secret path absent in synthetic startup/request logs | NOT VERIFIED (running guest version's static sentinel did not correspond to actual generated secret) |
| 13 | Valid config restored and healthy add-on restarted | NOT VERIFIED |
| 14 | Independent HA/Supervisor administration when MCP fails | PENDING |
| 15 | Complete original add-on/config rollback under Supervisor | NOT VERIFIED |
| 16 | Watchdog cannot cause uncontrolled restart loop | NOT VERIFIED |

## Runtime results and cleanup (to update from final run)

- HAOS boot: **PENDING**.
- Supervisor init: **PENDING**.
- Candidate add-on/strict-option recognition: **PENDING**.
- Tested setting/downgrade: **PENDING**.
- Full current guest logs checked for actual secret sentinel: **NOT VERIFIED**. A later committed runner harness generated and checked a real synthetic sentinel, but this was NOT part of in-progress immutable run #37851915146.
- Guest process cleanup; working directory removal; no artifact: **PENDING**. Require observed `PHASE2H_GUEST_PROCESS_CLEANUP` and `PHASE2H_TEMPORARY_VM_FILES_REMOVED` receipts.
- Cost: standard public GitHub-hosted runners require no Actions charges under published billing rules; no paid resource created. Actual user invoice cannot be read.
- Required remaining approvals: no production deployment; any additional VM experiment requires a separate exact approval if this guest has started. Any upstream private disclosure/PR submission also requires explicit approval.

**Release decision:** Phase 2H NOT FULLY VERIFIED; Phase 3 PRODUCTION NO-GO.
