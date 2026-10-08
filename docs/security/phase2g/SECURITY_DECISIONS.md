# Phase 2G — Security decision register (2026-10-08)

This is an evidence-backed review register, not deployment approval. All production Home Assistant, tunnel, router, Auth0, Control Plane and credentials remain unchanged.

| ID | Decision | Evidence | Status |
|---|---|---|---|
| 2G-01 | Preserve Phase 2F positive allow-list and **do not** toggle the 18 existing approval rules in place | Confirmed UI mode require_approval; genuine 8.6.0 evaluator inversion tests | ACCEPTED for staging only |
| 2G-02 | Approval must be revalidated **after** a wait and before final tool dispatch | Reproduced real-middleware bug: original #37848286990 had 11 PASS / 1 FAIL; new narrow candidate #37848485823 13 PASS and upstream 194 PASS / 2 deselected; exact reverse patch PASS | PATCH CANDIDATE / NEEDS UPSTREAM REVIEW |
| 2G-03 | Approval-required is NOT hard-deny; prefer unregistered sensitive tools or a separate operation-aware hard deny | Upstream Policy evaluator has ALLOW or REQUIRE_APPROVAL only | ACCEPTED / HARD DENY NOT IMPLEMENTED |
| 2G-04 | No generic `ha_call_service` or `ha_bulk_control` automatic allow for convenience | Genuine evaluator accepts even an extra `data` field when an allow rule names only service/domain/ID; final backend effect unknown | CONSERVATIVE / PENDING E2E |
| 2G-05 | Allow only reviewable non-sensitive read calls automatically, stage a separately designed typed household control wrapper for benign actions | Source-verified tool signatures, synthetic proposal tests and argument-level constraints | DRAFT, NOT INSTALLED |
| 2G-06 | Do not call a Docker add-on package a Supervisor-managed acceptance | GitHub runner VM preflight #37847835408: KVM present but job lacks access; QEMU/UEFI absent; real nested HAOS requires packages/download/VM permission | BLOCKED / NEW VM APPROVAL NEEDED |
| 2G-07 | Do not rely only on Core+DB backups for restoring add-on security | Live 39 backup metadata, 2026.9.4 Core version in latest backup, no add-on archive inventory/restore receipt | BACKUP COVERAGE PARTIAL |
| 2G-08 | Future hardened add-on deployment must pin and control its update lifecycle | Production metadata `auto_update=true`; upstream images may overwrite a local patch and ignore/remove strict marker | RELEASE BLOCKER / NO PROD CHANGE |
| 2G-09 | Separate OpenAI-hosted attachment tests and Control Plane/Auth0 from this upstream patch review | No hosted negative attach / paid identity created; tunnel unchanged | SEPARATE APPROVAL |
| 2G-10 | Defer live port 9583/IPv6 changes until tunnel ingress and independent local recovery prove supported | `host_network=true`, ingress true, LAN 9583 exposure previously observed, loopback-only bind may break Supervisor | BLOCKED |
| 2G-11 | Keep administrative approval decision tools disabled unless a human explicitly enables developer-mode and policy-override access | Source `tools_dev.py`: developer-mode registration default off, approve/deny requires separate default-off security policy access; production status not fully inventoried | DEFENSE-IN-DEPTH |

## Remaining release confidence boundaries

**PASS**: final prior Phase 2F CI on `befb3c8...`; pinned v8.6.0 source/packaged tests; genuine FastMCP approval & snapshot fake-action cases and narrowly scoped middleware source rollback. New tests are synthetic and do not prove Home Assistant authorization at its final device/REST/WebSocket boundary.

**FAIL (fixed candidate):** old middleware permitted a previously approved, waiting synthetic action after corrupt policy file. New patch blocks this when rechecked at dispatch, but requires upstream tests to be updated intentionally.

**BLOCKED:** genuine VM/Supervisor staging, complete HA backup add-on inventory/restore, independent local access, hosted attachment, native final backend authorization / irreversible DENY, network isolation, update policy.

**NO-GO**: Phase 3 and any deployment or merge. Two draft PRs stay separate. Revisit only with explicit acceptance evidence and deployment authorization.
