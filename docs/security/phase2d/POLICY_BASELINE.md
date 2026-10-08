# Proposed strict policy baseline for this HA installation — NOT APPLIED

## Security semantics

When enabled, `HA_MCP_REQUIRE_STRICT_POLICY=true` requires a nonempty `rule_effect="allow"` file. It is a staged upstream source candidate only; the current Supervisor HA-MCP add-on does **not** expose this new environment setting in its supported configuration UI.

The current policy engine's outcomes are **allow automatically** for matching allow-list rules or **require approval** for other calls. It does **not** offer an unconditional hard-deny action. Any capability that must be impossible to run requires tool removal/disabled registry entry, lower backend credentials, or a distinct server-side hard-deny middleware with a canonical operation classifier.

## Safe starting policy intent, subject to real tool schema and effective-rule audit

| Operation class | Candidate baseline | Alternate routes and constraints |
|---|---|---|
| Read-only inventory / status | Explicit allow by exact verified read-only tool + constrained args | A single tool with action=write must NOT be blanket-allowed |
| Ordinary lights, blinds and media | Explicitly allow selected benign service/domain/operation arguments; otherwise approval | `ha_call_service`, `ha_bulk_control`, tool search proxy and dynamic selectors must be evaluated on final target set |
| Lock and alarm changes, camera privacy/security | Approval required initially; prefer **hard deny** until operation-bound enforcement proven | Dedicated lock tool, `ha_call_service`, raw `ws_command`, `ha_bulk_control`, automations/scripts as alternate execution paths |
| Automations, YAML, files, integrations, HACS, restores | Approval for exact action, no cross-action blanket allowance | Inspect action arguments, custom tool/script calls and nested meta-tool dispatch |
| HA/MCP restart, Supervisor/add-on/OS/network/security-policy changes, backups deletion | Never blanket allow; independent privileged broker/guarded admin workflow | Current engine approval alone is NOT hard denial; disable dangerous tool registration where suitable |
| New tools introduced after update | Not automatically allow | In strict allow mode unmatched tools require approval; additionally review discovery proxies and revalidate catalog after update |

## High-risk routes that defeat superficial name-only rules

- One `Rule(tool_name="lock_tool")` does not constrain a functionally equivalent `ha_call_service`, `ha_bulk_control`, `ha_call_write_tool`, or a script/automation route. The actual Phase 2C middleware test reproduced an equivalent harmless synthetic dispatch via a generic route.
- Outer `PROXY_META_TOOLS` are excluded from direct policy gate. Verify nested forwarded tools are checked with original caller scope and normalized args.
- `ha_call_service` raw `ws_command` has partial special handling when a broad or name-specific rule exists, but never assume the safeguard covers arbitrary aliases or all service operations.
- Unmatched `allow`-mode tool calls need approval rather than hard denial. An approval queue is not a cryptographic authorization boundary against a privileged compromised user.

## Review and staging gates

1. Get a sanitized inventory of effective policy through **Home Assistant → Settings → Apps → Home Assistant MCP Server → Open Web UI → Tool Security Policies**, using an authorized HA administrator. The previous tool-mediated root endpoint returned 403; do not bypass.
2. Compare actual rules against complete **installed** 8.6.0 catalog and alternate dispatch paths; build negative test cases with synthetic devices.
3. Select a conservative initial read catalog and small set of routine changes; sensitive operations remain approval-required until server-side hard-deny and role scopes are evaluated.
4. Validate invalid/empty policy, live reload, expired approval, alternative routes, and startup middleware failures in isolated full app; stage a new tool after update to prove it is not automatically allowed.
5. Confirm manual/local HA access before enabling mandatory fail-fast behavior. Never rely solely on the same tunnel for recovery.

**Policy status in production: UNVERIFIED.** Live metadata establishes `enable_tool_security_policies=true` and `read_only_mode=false`, not the persisted rules or whether middleware successfully registered.
