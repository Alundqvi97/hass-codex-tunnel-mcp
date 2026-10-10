"""Pure required-cleanup proof and runtime observer coverage inventory.

This is not a guest observer. Only direct, independent read-back from a
separately approved runtime test can populate evidence in future.
"""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("prevm_acceptance", ROOT/"phase2j/acceptance.py")
mod=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=mod
SPEC.loader.exec_module(mod)

REQUIRED=tuple(mod.CLEANUP)
GATES=tuple(g.name for g in mod.GATES)
# No genuine live observers are registered as of this source commit.
RUNTIME_OBSERVERS: dict[str,str]={}

def status_for_gate(gate: str, *, instrumented: bool, live_verified: bool) -> str:
    if gate not in GATES:
        return "BLOCKED_UNKNOWN_GATE"
    if instrumented is not True or live_verified is not True:
        return "NOT_TESTED_RUNTIME_PROOF_MISSING"
    # Caller flags cannot prove real runtime provenance.
    return "BLOCKED_EXTERNAL_ATTESTATION_REQUIRED"

def review_cleanup(evidence: object) -> str:
    if not isinstance(evidence,dict) or set(evidence)!=set(REQUIRED):
        return "BLOCKED_CLEANUP_INCOMPLETE"
    if any(type(evidence[name]) is not bool or evidence[name] is not True for name in REQUIRED):
        return "BLOCKED_CLEANUP_FAILED_OR_UNKNOWN"
    return "SYNTHETIC_CLEANUP_COMPLETE_NOT_RUNTIME_VERIFIED"

def future_readback_requirements():
    return {
        "guest_absent":"pgrep owner by UID and exact executable + process wait result",
        "watchdog_absent":"watchdog PID wait and independent /proc PID start-time",
        "hostforwards_absent":"ss -ltnp bound ports and listener owner, including 0.0.0.0/::",
        "mounts_absent":"findmnt target + /proc/self/mountinfo",
        "nbd_detached":"qemu-nbd connection state + /sys/block/nbd0/pid",
        "ipv4_rules_absent":"iptables-save chain+OUTPUT jump absent",
        "ipv6_rules_absent":"ip6tables-save chain+OUTPUT jump absent",
        "user_absent":"getent passwd + pgrep numeric UID",
        "kvm_acl_removed":"getfacl /dev/kvm exact ACL entry absent",
        "guest_disk_absent":"stat verified temp file path absent",
        "firmware_absent":"stat verified temporary NVRAM file absent",
        "serial_absent":"stat verified serial output file absent",
        "scratch_absent":"stat verified temporary root absent and no mounts below",
    }

def release_exit_code(gate_receipts: object, cleanup_receipts: object) -> int:
    # Synthetic flags or text claims are never a real runtime PASS.
    return 6
