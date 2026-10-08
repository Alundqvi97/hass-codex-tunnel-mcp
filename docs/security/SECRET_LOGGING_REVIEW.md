# HA-MCP 8.6.0 secret-path disclosure review

**Severity: HIGH conditional on log reader access** · SOURCE VERIFIED and OFFLINE SYNTHETIC REPRODUCED · Not tested with production logs or actual installed add-on boot.

## Proven source and reproduction

Pinned [`homeassistant-addon/start.py`](https://github.com/homeassistant-ai/ha-mcp/blob/fc54437a804858732e4bc927add98e202d879a09/homeassistant-addon/start.py#L910-L921) logs two fields containing the **full secret MCP URL/path** through its startup logger. A prior invalid custom/stored path may also appear in error log messages. `log_info` writes to stdout with timestamp. The genuine pinned `log_info` function, imported without running `main()`, reproduced emission of a **synthetic** secret path in GitHub Actions staging. Test `test_addon_startup_synthetic_secret_logging_source` passed. It does not prove how Supervisor permissions protect that log.

## Potential exposure surfaces, with evidence classes

| Surface | Evidence | Assessment |
|---|---|---|
| Add-on startup stdout/Supervisor log history | VERIFIED SOURCE for intentional logging | Contains secret path unless separately sanitized before storage |
| HA-MCP `secret_path.txt` and Supervisor add-on options | VERIFIED SOURCE: persisted in add-on data/options | Secret-bearing backup/config data; requires proper access restrictions |
| ChatGPT tunnel integration diagnostics | VERIFIED SOURCE: URL-redaction fix exists in **unmerged** tunnel PR | Unreviewed paths and exception chains still require redaction checks |
| Tunnel-client stdout/stderr in HA logs | VERIFIED SOURCE from `tunnel.py` logger | Binary-dependent contents unverified; caution |
| Browser settings UI and ingress | VERIFIED SOURCE settings routes under secret path and HA ingress | Actual authentication/access policies and visibility to non-admins unverified |
| Reverse proxy / web access logs | UNVERIFIED | URL path might be logged; must not print in PR/CI |
| Support/diagnostic archives | UNVERIFIED | Do not share without deterministic recursive sanitization |
| Backup artifacts | SOURCE-INFERRED; data and config contain secret | Encrypt and restrict; verify exact included content without exposing paths |
| GitHub CI artifacts | VERIFIED OFFLINE synthetic only | CI checks have no production secrets; no real secret disclosed |

## Safe remediation proposal — upstream HA-MCP, not tunnel patch

1. Remove unconditional `log_info` lines that interpolate actual `secret_path` and the full MCP URL. Log only `MCP endpoint configured (secret withheld)` and a clear instruction for retrieving it through **authenticated** HA add-on configuration or a specifically permission-checked settings screen.
2. Avoid including invalid path values in exception messages and error logs; classify errors by static codes and safe field names.
3. Redact process and reverse-proxy logs before storage, not after support bundle export. Defensive recursive scrub should also cover URL-encoded paths, escaped JSON and line wrapping.
4. Preserve a privileged recovery method to reveal/reset the secret without relying on the tunnel. Do not rotate the current path just to reduce log exposure before the migration is prepared.
5. Restrict Supervisor log access and backup export; verify permissions for non-admin HA accounts before claiming this fixed.

**Usability trade-off:** New operators lose the convenience of copying the MCP URL from logs. Provide the same information through a confirmed-admin interface with explicit reveal/copy action and audit trail; never return it to a model tool.

## Regression requirements

Run pinned-startup synthetic logger test, plus upgraded-source test asserting full path absent from normal startup output and error branches, and a bounded test for redaction of common URL encodings. Full Supervisor-packaged boot must be separately staged. This existing reproduction test should be updated to expect the **absence** of the secret only after an upstream patch is approved and implemented.
