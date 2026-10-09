"""Inert, scoped, review-only Linux owner firewall probe command plan.

This is NOT an executor: no subprocess, shell, socket, firewall, or QEMU.
Never use iptables-restore: default table flush and even --noflush with
redeclaration of an existing custom chain can change unrelated state.
"""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress
import re

# Shared inert case contract. Privileged modules must not import controller
# code, even to obtain a constant; controller execution happens only after drop.
CASES = (
    ("approved-udp", "ipv4", 2), ("approved-tcp", "ipv4", 1),
    ("alternate-udp", "ipv4", 3), ("alternate-tcp", "ipv4", 3),
    ("private", "ipv4", 3), ("link-local", "ipv4", 3),
    ("ipv6-loopback", "ipv6", 0), ("loopback-new", "ipv4", 3),
    ("public-web", "ipv4", 3), ("loopback-established", "ipv4", 0),
)

class Refused(ValueError):
    pass

def _ip(value):
    if not isinstance(value,str): raise Refused("DNS_ADDRESS_INVALID")
    try: x=ipaddress.ip_address(value)
    except ValueError: raise Refused("DNS_ADDRESS_INVALID")
    if x.version!=4 or not x.is_global or x.is_private or str(x)!=value:
        raise Refused("DNS_NOT_PUBLIC_IPV4")
    return value

@dataclass(frozen=True)
class Command:
    family: str
    argv: tuple[str,...]
    phase: str

@dataclass(frozen=True)
class Plan:
    status: str
    uid: int
    scope: str
    chain4: str
    chain6: str
    dns: str
    inspect: tuple[Command,...]
    setup: tuple[Command,...]
    teardown: tuple[Command,...]
    # No approvals, destinations, or secrets can escape in receipt.
    def receipt(self):
        return "PROBE=OFFLINE_PLAN_ONLY"

# Every phase is displayed for review, not executed. Live probe must check
# observed outcomes and independent snapshots, not replay these blindly.
def compile_plan(*, scope, uid, dns, qemu=False, auto_retry=False):
    if not isinstance(scope,str) or not re.fullmatch(r"[A-F0-9]{8}",scope):
        raise Refused("SCOPE_INVALID")
    if type(uid) is not int or not 42000<=uid<=59999:
        raise Refused("UID_INVALID")
    if qemu is not False or auto_retry is not False:
        raise Refused("RUNTIME_SCOPE_WIDENING")
    dns=_ip(dns)
    c4,c6="P2A4_"+scope,"P2A6_"+scope
    ip4="/usr/sbin/iptables"
    ip6="/usr/sbin/ip6tables"
    def op(fam,phase,*args):
        binary=ip4 if fam=="ipv4" else ip6
        return Command(fam,(binary,"-w","5",*args),phase)
    inspect=(
        Command("ipv4",("/usr/sbin/iptables-save","-t","filter"),"snapshot"),
        Command("ipv6",("/usr/sbin/ip6tables-save","-t","filter"),"snapshot"),
        Command("identity",("/usr/bin/getent","passwd",str(uid)),"ensure-absent"),
        Command("identity",("/usr/bin/pgrep","-u",str(uid)),"ensure-no-process"),
        op("ipv4","ensure-chain-absent","-S",c4),
        op("ipv6","ensure-chain-absent","-S",c6),
    )
    # Both restrictive hooks must be installed AND independently read back
    # before any workload is permitted to adopt this numeric UID.
    setup=(
        op("ipv4","create","-N",c4),
        op("ipv4","restrict","-A",c4,"-j","REJECT"),
        op("ipv6","create","-N",c6),
        op("ipv6","restrict","-A",c6,"-j","REJECT"),
        op("ipv4","hook","-I","OUTPUT","1","-m","owner","--uid-owner",str(uid),"-j",c4),
        op("ipv6","hook","-I","OUTPUT","1","-m","owner","--uid-owner",str(uid),"-j",c6),
        op("ipv4","allow-dns-udp","-I",c4,"1","-d",dns+"/32","-p","udp","--dport","53","-j","ACCEPT"),
        op("ipv4","allow-dns-tcp","-I",c4,"1","-d",dns+"/32","-p","tcp","--dport","53","-j","ACCEPT"),
        op("ipv4","allow-loopback-reply","-I",c4,"1","-o","lo","-d","127.0.0.1/32","-p","tcp","-m","conntrack","--ctstate","ESTABLISHED","-j","ACCEPT"),
    )
    # Cleanup is attempted for BOTH families even if setup failed during
    # the earliest command. An executor must check presence before delete;
    # deleting an unrelated/mismatched rule is forbidden.
    teardown=(
        op("ipv6","unhook","-D","OUTPUT","-m","owner","--uid-owner",str(uid),"-j",c6),
        op("ipv4","unhook","-D","OUTPUT","-m","owner","--uid-owner",str(uid),"-j",c4),
        op("ipv6","own-chain-only","-F",c6),
        op("ipv4","own-chain-only","-F",c4),
        op("ipv6","own-chain-only","-X",c6),
        op("ipv4","own-chain-only","-X",c4),
    )
    return Plan("OFFLINE_NOT_EXECUTED",uid,scope,c4,c6,dns,inspect,setup,teardown)

def emergency_barrier_command(plan):
    """Exact deny-first owned chain rule, ONLY after both UID hooks read back."""
    if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise Refused("INVALID_EMERGENCY_BARRIER_PLAN")
    return Command("ipv4",("/usr/sbin/iptables","-w","5","-I",
                          plan.chain4,"1","-j","REJECT"),"emergency-barrier")

def emergency_deny_commands(plan):
    """Fixed, owned-only ACCEPT deletion; never remove hooks or terminal REJECT.

    Reverse setup order ensures each readback remains a recognized partial
    prefix. This is NOT an automatically executable operation.
    """
    if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise Refused("INVALID_EMERGENCY_PLAN")
    result=[]
    for orig in reversed(plan.setup[-3:]):
        a=orig.argv
        if orig.family!="ipv4" or a[3:6]!=("-I",plan.chain4,"1") or a[-1]!="ACCEPT":
            raise Refused("EMERGENCY_NOT_EXACT_OWNED_ALLOW")
        result.append(Command("ipv4",a[:3]+("-D",plan.chain4)+a[6:],"emergency-deny"))
    return tuple(result)

def validate_plan(plan):
    if not isinstance(plan,Plan) or plan.status!="OFFLINE_NOT_EXECUTED": return "BLOCKED"
    seen=set()
    for command in (*plan.setup,*plan.teardown):
        a=command.argv
        if command.family not in ("ipv4","ipv6") or a[:3] not in (
            ("/usr/sbin/iptables","-w","5"),("/usr/sbin/ip6tables","-w","5")
        ): return "BLOCKED"
        if any(x in a for x in ("iptables-restore","--noflush","-P","INPUT","FORWARD","-t","nat","PREROUTING")):
            return "BLOCKED"
        if "-F" in a or "-X" in a:
            if a[-1] not in (plan.chain4,plan.chain6): return "BLOCKED"
        if "OUTPUT" in a and ("--uid-owner" not in a or str(plan.uid) not in a):
            return "BLOCKED"
        if command.phase in ("hook","create"):
            seen.add((command.family,command.phase))
    if seen!={("ipv4","hook"),("ipv6","hook"),("ipv4","create"),("ipv6","create")}:
        return "BLOCKED"
    if any(a.argv.count("ACCEPT") for a in plan.setup if a.family=="ipv6"): return "BLOCKED"
    # Exact regeneration is an allowlist for every argv, phase, order and
    # teardown/readback command: no injected extra ACCEPT or wider owner hook.
    try:
        canonical=compile_plan(scope=plan.scope,uid=plan.uid,dns=plan.dns)
    except Refused:
        return "BLOCKED"
    if plan!=canonical:
        return "BLOCKED"
    return "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED"

CLEANUP_READBACKS=(
    "numeric_uid_process_absent","numeric_uid_account_absent",
    "ipv4_chain_absent","ipv6_chain_absent","ipv4_output_hook_absent",
    "ipv6_output_hook_absent","preexisting_ipv4_filter_identical",
    "preexisting_ipv6_filter_identical","test_listeners_absent",
    "temporary_files_absent","watchdog_absent","resolver_unchanged",
)

def verdict(observations, *, provenance):
    # In-memory mock/synthetic evidence can NEVER become live proof.
    if not isinstance(observations,dict) or set(observations)!=set(CLEANUP_READBACKS):
        return "BLOCKED_CLEANUP_INCOMPLETE"
    if any(type(observations[x]) is not bool or observations[x] is not True for x in CLEANUP_READBACKS):
        return "BLOCKED_CLEANUP_UNVERIFIED"
    if provenance!="REAL_INDEPENDENT_HOST_READBACK":
        return "SYNTHETIC_COMPLETE_NOT_ENFORCEMENT_PROOF"
    # Live attestation is intentionally not implemented in this package.
    return "BLOCKED_NO_TRUSTED_OBSERVER"
