# Project guidance

Build the capable Home Assistant administrator described in section 0 and UX01–12 of docs/security/PROJECT_DESIGN_BLUEPRINT.md. Prefer one authenticated request path, native HA lifecycle, a small final-dispatch authorization boundary, and ordinary transactional persistence. Security and practical administration are both release requirements.

Read docs/security/IMPLEMENTATION_PLAN.md for the current architecture and validation, docs/security/THREAT_MODEL.md for boundaries, and docs/security/TOOL_POLICY_MATRIX.md for capability evidence. Historical Probe A completion instructions are superseded by the owner’s practical-product brief of 2026-10-10. Probe A remains disconnected experimental source, not a production dependency or a passing native acceptance result.

Preserve concurrent changes and use normal Git history on existing draft PR #2. Keep the Blueprint intact. Never activate historical Probe A or HAOS/VM workflows, touch production/household networks or credentials, merge/deploy, or incur costs without separate authorization. Development services use synthetic state and loopback only; no elevated processes or host mutations.

Test connected approval → dispatch → readback → recovery, including wrong identities/targets, revocation, expiry, replay, alternate routes, uncertainty and restart. Persist mutation intent before dispatch and never blindly retry uncertain writes. Do not claim hosted identity or current HAOS acceptance from local fixtures. Document unsupported capabilities rather than silently replacing administration with read-only instructions.

Use the existing environment for retained offline tests. Install justified development dependencies only in disposable/project-local environments with TLS/integrity verification. Keep caches, runtime databases and credentials outside tracked source. Run bounded representative tests first, then relevant retained regressions. Record source and delivery revisions separately, preserve failed evidence, and provide transferable sanitized results.
