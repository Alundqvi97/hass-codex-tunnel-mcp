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
