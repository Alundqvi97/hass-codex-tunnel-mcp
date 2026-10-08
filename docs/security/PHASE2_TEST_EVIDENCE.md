# Phase 2 test and inspection evidence

Date: 2026-10-08. **No production mutation.** All newly introduced tests run with synthetic values on 127.0.0.1. CI results for the final code revision recorded in `IMPLEMENTATION_PLAN.md`.

## Evidence classes

- A = live read-only HA/UniFi inventory.
- B = OpenAI/HA-MCP documentation and fork source analysis; assertions about implementation, *not* hosted denial.
- C = independently executed GitHub CI source-level regression/unit tests.
- D = isolated representative MCP HTTP JSON-RPC fixture; *not* actual HA-MCP service or tunnel-client.
- E = authorized disposable hosted tunnel or actual HA-MCP staging integration: **NOT PERFORMED**.

## Evidence

| ID | Type | Observation | Interpretation |
|---|---|---|---|
| P2-01 | A | HA Core 2026.10.0; HA-MCP 8.6.0 started; tunnel integration loaded; automatic tunnel-client update disabled; two separate configured credentials observed without reading out values | Matches current architecture; healthy/loaded alone is not authorization proof |
| P2-02 | A | HA-MCP host network true; 9583/tcp mapped to host; security policies on; security-policy edit tool off; read-only mode off; redaction on; strict best-practices on | Exposed sensitive capabilities require inspection of *actual* per-tool rules |
| P2-03 | A | UniFi: Home, IoT, Guest, VPN; policies exist, kiosk exception present | Topology inventory only; no forbidden cross-VLAN scans |
| P2-04 | B | OpenAI documents org/workspace tunnel association and Tunnels Read/Use | Hosted attachment denial against another identity **NOT VERIFIED** |
| P2-05 | B | HA-MCP standard-mode secret URL grants shared access; add-on uses Supervisor identity | Backend bearer enforcement for actual POST **NOT VERIFIED**; separate identity not carried downstream |
| P2-06 | C/D | New `tests/test_phase2_protocol_contract.py` provides actual JSON-RPC HTTP `initialize`, `tools/list`, read-only `tools/call` to an isolated representative backend | Verifies test *fixture*, not real HA-MCP; missing/bad/expired/revoked/scope failures are simulated only |
| P2-07 | C/D | GET probe can accept a 405 with invalid bearer while identical fixture rejects POST `initialize` 401 | Concrete protocol/startup-test mismatch; not proof of real backend failure |
| P2-08 | B/C | `tunnel.py` writes bearer only to env vars; child stdout/stderr logged verbatim; watchdog marks healthy when a health file exists | Env reduces argv exposure but raw child output may leak; process liveness ≠ operational readiness |
| P2-09 | C | New fake-child exit test records `exited` without relaunch | Source-level gap: child crash recovery depends on something outside existing watcher; no actual HA reboot or child crash |
| P2-10 | C | Diagnostic redaction from legacy URL userinfo now stripped in development patch; regression covers malformed ports | Scoped change to avoid accidental credential reporting; no production deployment |
| P2-11 | C | One test skipped because `pytest.importorskip("homeassistant.helpers.selector")` cannot import full HA dependencies in lightweight runner | Config password selector integration is untested in CI; does not imply runtime compatibility |

## Test matrix outstanding

- Actual HA-MCP HTTP transport POST authorized/unauthorized, session reuse, token expiry/revocation, scope checks: **BLOCKED — need disposable real backend**.
- Actual proprietary v0.0.15 tunnel-client redirect, header-forwarding, DNS rebinding, TLS downgrade, proxy, IPv4/v6, offline retry, logging and revocation effects: **NOT VERIFIED**.
- Real hosted OpenAI attachment negative matrix and per-identity RBAC: **BLOCKED — approval for disposable hosted resources and test identities**.
- Production LAN/guest/IoT/VPN/WAN/IPv6 reachability: **NOT VERIFIED**, no permission to perform network probes from additional segments.
- Home Assistant reboot, HA-MCP add-on restart, tunnel-client crash in production, network outage / DNS outage / failed update / restore: **NOT TESTED**.
- No externally reachable or production endpoint was accessed by CI.

## Tooling limitations

Current connected GitHub tooling can read/write fork and view Actions; it cannot run OpenAI-hosted adversarial identity tests. HA and UniFi tools allow passive configuration inspection but do not expose a reliable packet-filter simulator or a complete live authorization-policy audit. Do not infer the missing results.


## Phase 2B evidence additions (2026-10-08)

| Item | Classification | Result |
|---|---|---|
| P2B-01 HA-MCP exact tag | VERIFIED SOURCE | `v8.6.0` annotated ref maps to `fc54437a804858732e4bc927add98e202d879a09`; running image digest not attested |
| P2B-02 backend bearer | VERIFIED SOURCE | Add-on standard HTTP ingress path secret, no incoming bearer middleware registered by add-on startup; `SUPERVISOR_TOKEN` exported for outbound HA API |
| P2B-03 policy default | VERIFIED SOURCE | Default require-approval policy allows unmatched tools; initialization can log an error and leave policy middleware unregistered |
| P2B-04 live effective rules | BLOCKED | Read-only ingress GET `/api/policy/config` returned 403; effective rules still unverified |
| P2B-05 exact runtime MCP POST | UNVERIFIED | No isolated real HA-MCP server booted; prior mock POST tests do not apply to actual backend |
| P2B-06 hosted authorization | BLOCKED | No disposable tunnel or additional identity created; billing unknown |
| P2B-07 crash recovery | VERIFIED SOURCE | Existing subprocess watcher records exit without starting replacement; bounded recovery design isolated from PR #1 |

No new Phase 2B code-level tests were run in an environment containing actual HA-MCP 8.6.0 dependencies. GitHub PR CI results apply to tunnel integration's source/tests; they **do not** establish backend authentication. Do not reuse historical mock pass count as if it verified this source.
