# One bounded network probe — inert approval package

**2026-10-09. Final decision: NOT READY — SPECIFIC ENGINEERING BLOCKER.** This is source preparation only; it grants no privileged or runtime permission. The one authorized HAOS guest attempt #37851915146 failed previously and may not be rerun. Neither PR may merge.

## A versus B: evidence boundaries

**A — lowest-privilege recommended probe:** One ordinary Linux process under one unused temporary numeric UID on a disposable standard GitHub-hosted Ubuntu 24.04 runner. No QEMU and no HAOS. Owner-filter IPv4/IPv6 OUTPUT rules can be exercised with precisely approved UDP/TCP DNS traffic, alternate DNS, private/link-local, IPv6, unapproved HTTPS, and loopback traffic. Read back both kernel rule families and counters and compare full pre/post filter-table snapshots. This demonstrates host process behavior, NOT QEMU/libslirp behavior. A Linux-host synthetic loopback listener can test ESTABLISHED replies and distinguish refused new connections via counters, but cannot prove real QEMU host-forward binds.

**B — separately approvable, excluded:** Minimal paused QEMU (-S), no boot disk or guest, could potentially instantiate and expose its explicit 127.0.0.1 hostfwd listeners for ss inspection, subject to actual QEMU capability verification. A paused QEMU cannot generate guest-originated DNS. **No DNS forwarding proof follows without guest-generated packets or a separately reviewed libslirp test harness.** QEMU execution is explicitly NOT authorized under A. Never label a QEMU process as a non-QEMU test.

QEMU v10.1 documentation: https://github.com/qemu/qemu/blob/v10.1.0/qemu-options.hx — dns= changes the guest-visible virtual DNS address, not the actual host resolver; restrict=on does not disable explicit forwards.

## Critical firewall correction

Prior Phase 2L generated raw iptables-restore input that would flush unrelated filter-table content if applied normally. Even --noflush may flush a redeclared user chain. That output is now turned into literal INERT comment lines, not loadable rules. This package does NOT use iptables-restore, --noflush, full snapshot restore, nat, or global flush. See https://man7.org/linux/man-pages/man8/iptables-restore.8.html .

Pure module docs/security/phase2l/probe_contract.py generates reviewed, structured *argv arrays* only; it NEVER calls a command. It accepts precisely one 8-hex uppercase scope, a numeric UID 42000–59999, one canonical globally routed IPv4 DNS target, qemu=false and auto_retry=false. A canonical regeneration check rejects any additional, reordered or mutated command. Example offline fixture only: scope A1B2C3D4, UID 45123, DNS 9.9.9.9. These values are not approvals or claims that 9.9.9.9 is reachable.

### Exact proposed command sequence; NOT executed

The two firewall binaries are /usr/sbin/iptables and /usr/sbin/ip6tables. Each uses -w 5 and fixed argv, no shell interpolation. Substitute only the newly reviewed scope and confirmed absent UID; illustrative chains are P2A4_A1B2C3D4 and P2A6_A1B2C3D4.

1. Pre-change snapshots: /usr/sbin/iptables-save -t filter and /usr/sbin/ip6tables-save -t filter. Inspect getent passwd UID, pgrep -u UID, iptables -S dedicated-chain and ip6tables -S dedicated-chain; all identities and chains must be absent. Reject nft/legacy mismatches, unexpected preexisting hooks, any inability to acquire the xtables lock. Keep snapshots memory/private scratch only; never upload.
2. iptables -w 5 -N P2A4_SCOPE; iptables -w 5 -A P2A4_SCOPE -j REJECT.
3. ip6tables -w 5 -N P2A6_SCOPE; ip6tables -w 5 -A P2A6_SCOPE -j REJECT.
4. iptables -w 5 -I OUTPUT 1 -m owner --uid-owner UID -j P2A4_SCOPE; ip6tables -w 5 -I OUTPUT 1 -m owner --uid-owner UID -j P2A6_SCOPE. **No test process adopts this UID until BOTH restrictive chains and hooks have independent readbacks.** This avoids a half-configured IPv4/IPv6 window.
5. Insert before terminal REJECT in P2A4 only: exact DNS destination/32 with UDP dport 53 ACCEPT; same target/32 TCP dport 53 ACCEPT; one loopback TCP ESTABLISHED reply exception with -o lo -d 127.0.0.1/32 and conntrack --ctstate ESTABLISHED. No TCP 80/443 ACCEPT, new-loopback allowance, metadata range, unreviewed web destination or IPv6 ACCEPT.
6. Independently verify expected effective rules/order/UID, all 13 required cleanup-related resource identities where applicable, both IPv4/IPv6 snapshots and exact counters before workload.
7. Future test workload would run with /usr/bin/setpriv --reuid=UID --regid=UID --clear-groups --bounding-set=-all using a fixed standard-library DNS/socket probe and bounded timeout. **This executable controller/client has not been built or approved.** A full test must validate actual DNS responses and counter increments, not infer firewall success from timeouts.
8. Stop and wait for all test processes. Delete only the exact owned IPv6 and IPv4 OUTPUT jumps, then flush and delete only both dedicated chains (-F P2A*_SCOPE, -X P2A*_SCOPE). For any partially failed setup, attempt exact ownership-tested cleanup of both families; never restore a whole-table snapshot. Full filter-table post-cleanup snapshots must equal the originals, including unrelated chains. Independently verify no UID process, listener, account, temporary files, lingering chains, jumps or changed resolver. Unknown cleanup => nonzero exit.

The exact complete command argv vectors, including every rollback action, are in the pure module. Source can be read or run as a Python import without mutation.

## Planned test matrix, only upon separate approval

| Category | Synthetic check | Required proof |
| --- | --- | --- |
| Positive DNS UDP/TCP | One reviewed resolver, name p2-probe.invalid. | Matching transaction ID, response validity and allowance counters |
| Alternate DNS | Separate explicitly approved public resolver, UDP/TCP 53 | Deny counter increase, no successful reply |
| Private/link-local | Non-household documentation and synthetic address ranges, excluding 169.254.169.254 | Deny counter increase; a timeout alone never proves isolation |
| IPv6 | ::1 test socket | IPv6 deny counter increase |
| Loopback NEW | 127.0.0.1 unapproved TCP connection | Deny counter increase |
| Loopback ESTABLISHED | Controlled synthetic local listener and roundtrip | Correct allow counter plus response |
| Unreviewed HTTPS | Explicitly approved nonproduction test target port 443 | Deny counter increase; zero HTTPS allow rules |
| Host-forward address | QEMU source static AST for four 127.0.0.1 binds | SOURCE ONLY; no actual QEMU listener claim |
| Drift | Changes of resolver, UID, rules, counters or redirects | Abort, no automatic widening |
| Partial failure | Every setup/cleanup interruption | Both-family cleanup attempted and independently read back |

No real external destinations other than the expressly approved DNS address are needed for positive traffic in Probe A. Negative public destinations must be specified in the later request; never use household addresses, cloud metadata endpoints or real services as positive application targets.

## Approval envelope and cost

One standard GitHub-hosted ubuntu-24.04 runner in this PUBLIC repository; no larger/paid/self-hosted runner, no artifacts, cache, packet captures, package installation, uploaded logs containing addresses, credentials, secrets, Home Assistant, tunnel, Auth0, UniFi, OpenClaw or home network. Zero retry, one attempt, no QEMU, HAOS or VM boot. Proposed maximum GitHub job duration 5 minutes, test client under 30 seconds, 60 seconds reserved for cleanup; cap to two vCPU, 256 MiB test-client RAM and 32 MiB private scratch. **The exact time/resource enforcement has NOT yet been implemented.**

The only proposed elevated actions are dedicated per-UID IPv4/IPv6 owner filter-chain operations plus independent rule-readbacks; running the client with setpriv also needs controlled root-to-numeric-UID privilege drop. No new system account or /dev/kvm access. Any tool/version/backend mismatch or pre-existing network rule collision aborts.

GitHub documentation says standard hosted Actions in public repositories are free, so estimated marginal GitHub Actions charge is **USD 0** under those terms. Account billing status is not verified; a paid runner, repo made private, artifacts/storage, or hosted infrastructure must not be used. Source: https://docs.github.com/en/billing/concepts/product-billing/github-actions .

Bounded receipts only: PROBE_SCOPE=LINUX_OWNER_ONLY, OWNER_RULES=PASS|FAIL|NOT_TESTED, DNS_UDP=..., DNS_TCP=..., DENY=..., LOOPBACK=..., CLEANUP=..., OVERALL=BLOCKED|PASS. No public raw IP/hostnames, DNS response bodies, exception text, PCAP or secrets. All entries initially NOT_TESTED. Any missing observation/cleanup prevents overall success; fixture flags never produce a live PASS.

## Concrete remaining blocker

The **trusted, bounded command executor, fixed synthetic DNS/socket client, kernel rule/counter observer, signal/watchdog deadline and independent cleanup controller** do not exist yet. This inert package cannot be run to yield true results. Approving it as a live experiment now would effectively approve unaudited manual commands and is NOT justified.

The next implementation change must add that executable controller and test it through injected fake command/syscall adapters, then pin its exact source SHA, ensure no automatically triggered privileged workflow exists, and independently review the exact execution code. Only then can user approval cover a single Probe A attempt.

Proposed future approval wording (NOT an authorization now):

"Approve exactly one ordinary Linux process-owner DNS/firewall Probe A using the immutable reviewed source commit, a standard GitHub-hosted Ubuntu 24.04 runner in this public repository, the explicitly approved DNS/negative targets, one unused numeric UID, scoped chains only, a 5-minute maximum, complete independent rollback/readback, no artifacts/retry, NO QEMU/HAOS/VM, and NO household connections."

This statement must contain the final immutable commit and targets when actually requested. It cannot be inferred from this preparation prompt.

**Release: NOT READY for Probe A execution; full HAOS/Supervisor and production remain NO-GO.**