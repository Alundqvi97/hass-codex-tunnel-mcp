"""Pure Phase 2J acceptance state machine. No I/O, networking, subprocess or secrets.

A claim of runtime origin is *not* an attestation: only independently wired
future guest observers can make it genuine. This component cannot boot a VM.
"""
from dataclasses import dataclass
from typing import NamedTuple

class Gate(NamedTuple):
    name: str
    proof: str
    origin: str
    prerequisites: tuple[str, ...]
    timeout_seconds: int

GATES = (
    Gate("HAOS_BOOT", "HAOS_KERNEL_BOOT", "HAOS", [], 780),
    Gate("SUPERVISOR_READY", "SUPERVISOR_AUTH_STATUS", "SUPERVISOR", ["HAOS_BOOT"], 480),
    Gate("CANDIDATE_INSTALLED", "SUPERVISOR_APP_INSTALLED", "SUPERVISOR", ["SUPERVISOR_READY"], 850),
    Gate("STRICT_SCHEMA", "SUPERVISOR_STRICT_SCHEMA", "SUPERVISOR", ["CANDIDATE_INSTALLED"], 90),
    Gate("RESTART_PERSISTENCE", "APP_RESTART_STRICT_RETENTION", "SUPERVISOR", ["STRICT_SCHEMA"], 180),
    Gate("REBOOT_PERSISTENCE", "HAOS_REBOOT_STRICT_RETENTION", "SUPERVISOR", ["RESTART_PERSISTENCE"], 780),
    Gate("SAFE_MCP_READ", "AUTHENTICATED_MCP_READ", "MCP", ["RESTART_PERSISTENCE"], 120),
    Gate("CORRUPT_POLICY_DENIAL", "CORRUPT_POLICY_WRITE_DENIED", "MCP", ["SAFE_MCP_READ"], 120),
    Gate("INIT_FAIL_CLOSED", "MIDDLEWARE_INIT_DENIED", "MCP", ["CORRUPT_POLICY_DENIAL"], 120),
    Gate("DOWNGRADE_DENIAL", "STRICT_DOWNGRADE_DENIED", "MCP", ["INIT_FAIL_CLOSED"], 120),
    Gate("STALE_APPROVAL_DENIAL", "FINAL_DISPATCH_REVALIDATED", "MCP", ["DOWNGRADE_DENIAL"], 180),
    Gate("SECRET_LOG_REDACTION", "ACTUAL_SECRET_NOT_IN_LOGS", "MCP", ["CANDIDATE_INSTALLED"], 90),
    Gate("CONFIG_RECOVERY", "APP_RECOVERED_AFTER_FAULT", "SUPERVISOR", ["CORRUPT_POLICY_DENIAL","INIT_FAIL_CLOSED","DOWNGRADE_DENIAL"], 240),
    Gate("LOCAL_ADMIN_OUTAGE", "INDEPENDENT_SUPERVISOR_ON_FAULT", "SUPERVISOR", ["CORRUPT_POLICY_DENIAL"], 90),
    Gate("FULL_ROLLBACK", "ORIGINAL_IMAGE_RESTORED", "SUPERVISOR", ["CONFIG_RECOVERY","LOCAL_ADMIN_OUTAGE"], 360),
    Gate("WATCHDOG_BOUNDED", "WATCHDOG_RESTART_BOUND", "SUPERVISOR", ["FULL_ROLLBACK"], 240),
)
GATE_BY_NAME = {g.name: g for g in GATES}
STATES = frozenset(("PASS", "FAIL", "BLOCKED", "NOT_TESTED"))
ORIGINS = frozenset(("HAOS", "SUPERVISOR", "MCP"))
REQUIRED = tuple(g.name for g in GATES)

@dataclass(frozen=True)
class Receipt:
    status: str
    proof: str = ""
    origin: str = ""
    # This field must only be set by a reviewed runtime observer, not a mock.
    runtime_verified: bool = False

class Acceptance:
    """Single attempt, immutable outcomes: no skipping or success overwrites."""
    def __init__(self):
        self.results = {g.name: Receipt("NOT_TESTED") for g in GATES}
        self.cleanup_results = {}
    def record(self, gate_id, status, *, proof="", origin="", runtime_verified=False):
        if gate_id not in GATE_BY_NAME:
            raise ValueError("UNKNOWN_GATE")
        if status not in STATES:
            raise ValueError("UNKNOWN_STATUS")
        if self.results[gate_id].status != "NOT_TESTED":
            raise ValueError("TERMINAL_RECEIPT_CANNOT_BE_OVERWRITTEN")
        if status == "NOT_TESTED":
            raise ValueError("NOT_TESTED_IS_DEFAULT")
        spec = GATE_BY_NAME[gate_id]
        if status == "PASS":
            if proof != spec.proof or origin != spec.origin or not runtime_verified:
                raise ValueError("INVALID_PASS_EVIDENCE")
            if any(self.results[dependency].status != "PASS"
                   for dependency in spec.prerequisites):
                raise ValueError("UNMET_PREREQUISITE")
        elif proof or origin or runtime_verified:
            raise ValueError("FAILURE_MUST_USE_FIXED_STATUS_ONLY")
        self.results[gate_id] = Receipt(status, proof, origin, runtime_verified)
    def record_cleanup(self, key, complete):
        if key not in CLEANUP:
            raise ValueError("UNKNOWN_CLEANUP")
        if key in self.cleanup_results:
            raise ValueError("CLEANUP_ALREADY_RECORDED")
        if type(complete) is not bool:
            raise ValueError("INVALID_CLEANUP_STATUS")
        self.cleanup_results[key] = complete
    def passed(self):
        return all(r.status == "PASS" and r.runtime_verified
                   for r in self.results.values())
    def cleanup_complete(self):
        return all(self.cleanup_results.get(x) is True for x in CLEANUP)
    def verdict(self):
        if any(r.status == "FAIL" for r in self.results.values()):
            return "FAIL"
        if any(r.status in ("BLOCKED", "NOT_TESTED") for r in self.results.values()):
            return "BLOCKED"
        return "PASS" if self.passed() else "BLOCKED"
    def exit_code(self):
        return 0 if self.passed() and self.cleanup_complete() else 6
    def sanitized(self):
        # No proof text, secrets, URLs, response bodies or exception strings.
        return tuple("CASE_%02d=%s" % (i, self.results[g.name].status)
                     for i, g in enumerate(GATES, 1))

CLEANUP = (
    "guest_absent", "watchdog_absent", "hostforwards_absent",
    "mounts_absent", "nbd_detached", "ipv4_rules_absent",
    "ipv6_rules_absent", "user_absent", "kvm_acl_removed",
    "guest_disk_absent", "firmware_absent", "serial_absent",
    "scratch_absent"
)

def check_bootstrap_policy(resolvers, *, udp53_destinations, tcp53_destinations,
                           public_tcp_ports, ipv6_enabled, forwards_local):
    """Inert lint for proposed QEMU-UID egress configuration; not live proof."""
    import ipaddress
    if not resolvers or ipv6_enabled or not forwards_local:
        return "BLOCKED"
    try:
        addresses = [ipaddress.ip_address(a) for a in resolvers]
        udp = {ipaddress.ip_address(a) for a in udp53_destinations}
        tcp = {ipaddress.ip_address(a) for a in tcp53_destinations}
    except ValueError:
        return "BLOCKED"
    if any(a.version != 4 or not a.is_global for a in addresses):
        return "BLOCKED"
    if udp != set(addresses) or tcp != set(addresses):
        return "BLOCKED"
    if set(public_tcp_ports) != {80, 443}:
        return "BLOCKED"
    return "OFFLINE_CONSISTENT_NOT_NETWORK_VERIFIED"

def validate_local_app_fixture(root, *, slug, expected_files):
    """Only inspect a synthetic temporary directory supplied by tests."""
    from pathlib import Path
    import re
    base = Path(root) / "supervisor" / "apps" / "local" / slug
    if not re.fullmatch(r"[a-z0-9_]+", slug):
        return "BLOCKED"
    if not base.is_dir() or base.is_symlink():
        return "BLOCKED"
    if not all((base / f).is_file() and not (base / f).is_symlink()
               for f in expected_files if "/" not in f and ".." not in f):
        return "BLOCKED"
    if any("/" in f or ".." in f for f in expected_files):
        return "BLOCKED"
    return "SOURCE_LAYOUT_ONLY_NOT_INSTALLED"
