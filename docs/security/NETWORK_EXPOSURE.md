# Phase 2: network exposure and isolation recommendation

Read-only snapshot 2026-10-08. **Passive configuration evidence is not a reachability test.** No firewall, VLAN, HA or Supervisor changes made.

## Confirmed from live inventory

- HA-MCP app `81f33d0f_ha_mcp`: v8.6.0, running, `host_network=true`, Supervisor network mapping `9583/tcp → 9583`. This does **not** independently establish its exact IPv4/IPv6 bind addresses.
- Home Assistant Core 2026.10.0 and tunnel integration loaded. Tunnel-client and HA-MCP are on the HA host in the known architecture.
- Previous authorized desktop-LAN test reached TCP/9583. That is **one source**, not proof that other segments can or cannot reach it.
- UniFi UDR7: Home VLAN 1, IoT VLAN 20, Guest VLAN 30, VPN VLAN 40. 113 policy records inspected. External-to-Internal block rules and IoT/Guest segregation exist; a kiosk-to-HA exception is present. Exact order, IPv4/IPv6 packet path and exception conditions must be reviewed before enforcement claims.
- Home→Home same-subnet traffic ordinarily bypasses *routed* UniFi inter-VLAN firewall; do not claim a router inter-VLAN rule isolates trusted peers.
- A direct LAN visitor with the secret URL may bypass hosted authorization, as HA-MCP's standard mode treats the secret URL as its credential.

## Exposure matrix

| Path | Passive state | Active verification |
|---|---|---|
| HA host local loopback -> TCP/9583 | Architecture suggests local route; listening interface not established | NOT VERIFIED |
| Trusted desktop/Home -> TCP/9583 | Prior authorized reachable observation | CONFIRMED from one Home client only |
| Other same-Home clients -> TCP/9583 | No host-side deny proven | NOT VERIFIED |
| IoT -> Home TCP/9583 | UniFi segregation with exceptions | NOT VERIFIED (negative reachability) |
| Guest -> Home TCP/9583 | UniFi segregation policy present | NOT VERIFIED |
| VPN -> Home TCP/9583 | VPN policy present; different clients / routes | NOT VERIFIED |
| WAN -> TCP/9583 | External-to-Internal block policy present | NOT VERIFIED (NAT forwards, IPv6 inbound, UPnP and other ingress uninspected) |
| IPv6 and SLAAC addresses -> TCP/9583 | No listener binding or IPv6-specific path evidence | NOT VERIFIED |

## Smallest proposed reversible change (do **not** apply)

**Preferred architecture:** preserve the HA tunnel client’s internal route to the backend using a verified local-only address and secret path. Restrict direct non-loopback TCP/9583 at the **HA endpoint** (bind address / Supervisor app network exposure) if supported by the actual app; otherwise use a host firewall rule that explicitly permits the tunnel's local traffic and blocks inbound TCP/9583 from non-loopback sources, including IPv6.

**Why this sequence:** UniFi inter-VLAN rules cannot isolate untrusted peers on the same Home L2 network. A host-side or loopback listener restriction would reduce direct access from Home clients and from accidental guest/IoT exceptions without changing OpenAI outbound HTTPS.

**Do not set a null Supervisor port mapping blindly:** `host_network=true` may make ordinary container port publishing irrelevant. Validate binding and app behavior first.

Deployment preconditions:
1. From a disposable staging host, prove local IPv4 and IPv6 backend operation and exact required tunnel path without real secrets.
2. Confirm which service/network namespace owns port 9583 and enumerate network listeners with OS-native read-only commands; confirm HA Core can reach loopback.
3. Confirm use of port 9583 by all other legitimate clients, plus TLS/proxy/Ingress requirements.
4. Capture pre/post health, full route table and firewall rule identifiers; verify independent local HA/SSH access and backups.
5. Stage intended restrictive setting/rule with an automatic timed revert; negative tests for Home, IoT, Guest, VPN, WAN and IPv6 from **approved** test clients only.

Rollback blueprint (after separate approval): revert the single exact changed bind/listener config or remove the named host firewall rule via out-of-band local console; reload only the affected service once safe, verify old listener, direct access, tunnel health, authorization-denial tests and HA admin recovery. If a timed revert is used, cancel it only after health gates pass. Never rely on the tunnel itself to roll back its own network disconnection.

**Operational rule:** no production firewall change in this phase. Do not assume anything about port forwards solely from the zone firewall list.
