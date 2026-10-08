# Phase 2G — Independent restoration, backup metadata and outage drill

**Production: READ-ONLY assessment. No backup opened, downloaded, created, modified or restored. No service restarted.**

## Verified inventory

A supported read-only `ha_manage_backup(scope="snapshot", action="list", limit=5)` reported **39 stored backup records**. The newest protected automatic record:
- Date: **2026-10-08 15:31:44 +02:00**.
- Embedded `homeassistant_version: 2026.9.4`, whereas running Core is reported as **2026.10.0**.
- Includes Home Assistant Core configuration and database according to tool metadata (`homeassistant_included=true`, `database_included=true`).
- Reports both local Home Assistant and Google Drive backup agent locations.
- Backup is marked **protected**, but encrypted archive/password access and restore integrity were NOT examined.

The `homeassistant_version` field is **not the version of the backup format, Supervisor or operating system**. Supervisor's `Backup.homeassistant_version` returns `_data["homeassistant"]["version"]`; `store_homeassistant` populates that using the Core version seen during the backup. A snapshot from 2026.9.4 is not automatically invalid after an upgrade to 2026.10.0, but the difference proves neither that the most recent current Core state has been backed up nor that restore compatibility is guaranteed. Official source: https://github.com/home-assistant/supervisor/blob/main/supervisor/backups/backup.py

**Scope limitation:** The list response does not expose the underlying `addons[]`, `folders[]`, integration snapshots, secrets, HA-MCP add-on `/data`, tunnel HACS repository files, app version or original image digests. Supervisor stores addon archives **separately** from the Home Assistant Core configuration inside a full backup, when included. Metadata currently proves a Core+DB backup, NOT a complete HA-MCP/tunnel recovery. A Google Drive location and local location for the same backup provide storage redundancy but may share common corruption, encryption-key or credential failure; independent restoreability is NOT verified.

## Recovery layers needed for this connection

1. Home Assistant Core config + database (automation/entities/registry/UI configuration); preserve and verify current-version recovery point.
2. Supervisor add-on package **plus HA-MCP `/data`** (persisted `tool_policy.json`, marker, options and secret path). Rollback must not silently delete mandatory enforcement or reveal its secret.
3. HACS tunnel integration source pinned at the verified revision and HA backend bearer setup; source and credential recovery must be separately validated, without exporting secrets.
4. The OpenAI tunnel-client v0.0.15 binary/runtime and its service/keys (separate Ubuntu server component) are NOT necessarily included in a HAOS snapshot. Keep this independent of the Home Infra Control Plane and Auth0.
5. Local admin/Supervisor access independent of ChatGPT OpenAI tunnel, verified backup encryption unlock/restore procedure and offline recovery notes.

## Future *approved* local recovery drill (none executed)

- Establish direct local HA UI/admin login **without depending on ChatGPT** while keeping the current service running; optionally disable remote tunnel only in an isolated staged environment. Verify Supervisor Apps UI, backups and add-on config.
- Before any deployment, create an explicitly approved protected, full, consistent recovery point containing required add-on data; record backup identifiers/version, app entries and destination metadata without exposing file contents. Confirm Google Drive recovery works with separate credentials.
- Stage the pinned original HA-MCP 8.6.0 package/image and source before introducing Phase 2D/2F/2G changes. Keep the tested original policy and marker in a protected local administrator-only staging backup.
- If mandatory policy causes startup refusal: **do not weaken policy or open generic MCP**. From local Supervisor access, inspect sanitized status, restore the positive policy/valid options with marker intact, and restart only the failed staged add-on. Check logs for no synthetic path disclosure, then negative access checks.
- If the candidate itself prevents recovery: use a local, authorized Supervisor add-on version rollback to the exact original image and restore compatible options/policy. A rollback to old code cannot enforce new marker behavior; block/take offline the remote admin endpoint until a policy consistent with the older version has been explicitly reviewed. Never silently serve in unrestricted mode.
- If tunnel fails: continue HA and local Supervisor operations independently, investigate tunnel-client service and existing recovery scripts; do not route through OpenClaw or assume the Control Plane is available.
- After a failed add-on update: preserve current backup and logs, restore the approved pinned image/config, confirm secret path persistence, run safe read and deny tests and test loopback/ingress before reconnecting ChatGPT.
- After recovery: verify HA Core state, approved door automation behavior **without actually unlocking during initial tests**, add-on policy status, audit log redaction and no unwanted auto-update overwrite.

**Release gate:** No tested real restore, no verified complete add-on-inclusive backup, no independently demonstrated local login while ChatGPT tunnel unavailable. Stage and operator acceptance remain BLOCKED. Do not initiate a backup or production drill without separate approval.
