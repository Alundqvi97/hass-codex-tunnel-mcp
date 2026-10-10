# Phase 2E — Read-only recovery and network assessment

## Production recovery observations (VERIFIED LIVE metadata)

- HA Core reports 2026.10.0; HA-MCP 8.6.0 installed and running; Supervisor add-on `boot=auto`, `watchdog=true`, `ingress=true`, `host_network=true`, `9583/tcp → 9583`, and add-on automatic updates enabled. This shows configuration, not an executed crash/reboot/recovery test.
- Authorized admin UI screenshots demonstrate an accessible HA-MCP settings interface at capture time; they do not independently prove local LAN UI access if OpenAI tunnel fails or that another admin account has recovery rights.
- Read-only `ha_manage_backup(scope="snapshot",action="list",limit=10)` returned **39 total backups**, including recent protected automatic backups on local and Google Drive agents. The newest entries label **HA 2026.9.4**, while live Core is **2026.10.0**. This metadata mismatch must be resolved before relying on them for rollback. No restore was attempted and no backup content was opened.
- No source-verified recovery via local display/keyboard, physical host/SSH, or verified Supervisor independent credentials has been exercised. **OOB recovery: UNVERIFIED**.
- HACS tunnel production revision and exact source/image pins are documented in project baseline; do not assume the Supervisor binary fallback restores all source/configuration layers.

## Network decision (DOCUMENTED ONLY)

In HA-MCP add-on mode, `MCP_HOST` defaults to `0.0.0.0` and `host_network=true`. Direct TCP 9583 from a trusted Home LAN client was previously observed. Same-subnet clients do not necessarily traverse UniFi inter-VLAN firewall rules. The HA Core / tunnel-client to add-on route and Supervisor ingress `172.30.32.2 → 172.30.32.1:9583` must remain reachable.

**Preferred objective:** allow local in-host tunnel and Supervisor ingress only, deny same-LAN/IoT/Guest/VPN/WAN direct clients (IPv4/IPv6), without relying solely on router VLAN firewalls. Control is likely add-on host binding or a *supported* host-level ingress policy; HAOS firewall manipulation is not approved and may be unsupported. Changing `MCP_HOST=127.0.0.1` alone could break Supervisor ingress and is NOT a safe blanket recommendation.

Preflight: identify exact HAOS listener and IPv6 addresses, tunnel target/bind, Supervisor peer, reverse proxy and legitimate LAN clients via passive inventory; test in isolated HAOS/Supervisor image. Only then select a reversible option with independent local console access, a timed revert and negative reachability tests from approved segments.

## Recovery order (NOT EXECUTED)

1. Obtain HA local/Supervisor access independent of ChatGPT tunnel, confirm role, save protected current-version backup and pinned integration/add-on image.
2. If strict policy failure: keep privileged MCP unavailable; inspect repair status through HA UI, restore reviewed policy through an authorized channel; never disable mandatory gating to recover access silently.
3. If logging patch error: restore exact pinned source and path persistence, verify no secret exported in prior logs, stage clean startup.
4. If tunnel-client crashes: use separate bounded recovery design; never invoke OpenClaw or bypass auth.
5. After HA upgrade/add-on update: verify policy init, tool catalog, normal MCP read, denial tests, known-good reversion and local HA accessibility before declaring success.

**Production recovery gate:** BLOCKED; no restart, policy write, update, restore, traffic probe, router or credential changes permitted.
