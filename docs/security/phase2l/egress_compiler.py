"""Offline-only, deterministic owner-egress compiler for future one-guest review.

An output is a PROPOSED policy, never an observed QEMU route, an installed
iptables rule, or authorization to run any command. No subprocess or network.
"""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from typing import Mapping

HOSTPORTS=((18123,8123),(18124,80),(14357,4357),(19583,9583))
CHAIN4="PHASE2H_GUEST"
CHAIN6="PHASE2H_GUEST6"
DENY_CIDRS=(
    "0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
    "169.254.0.0/16","172.16.0.0/12","192.168.0.0/16",
    "198.18.0.0/15","224.0.0.0/4","240.0.0.0/4",
)
PROPOSED="OFFLINE_PROPOSED_NOT_OBSERVED_NOT_ENFORCED"

class PolicyBlocked(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code=code

def deny(code: str):
    raise PolicyBlocked(code)

def ip4(value) -> str:
    if not isinstance(value,str):
        deny("INVALID_ADDRESS")
    try:
        address=ipaddress.ip_address(value)
    except ValueError:
        deny("INVALID_ADDRESS")
    if address.version!=4 or not address.is_global or str(address)!=value:
        deny("NON_PUBLIC_IPV4")
    return value

def host(value) -> str:
    if not isinstance(value,str) or len(value)>253 or not re.fullmatch(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?",value
    ):
        deny("INVALID_HOST")
    return value

def fields(value, expected: tuple[str,...], label: str):
    if not isinstance(value,dict) or set(value)!=set(expected):
        deny(label)

@dataclass(frozen=True)
class Compiled:
    status: str
    qemu_netdev: str
    resolver: str
    expiry_epoch: int
    ipv4_restore: str
    ipv6_restore: str
    cleanup: tuple[str,...]
    # No raw commands, IP addresses or hostnames in the bounded public receipt.
    def receipt(self):
        return "PREVM_NETWORK="+self.status

def compile_proposal(plan: Mapping, *, now_epoch: int) -> Compiled:
    """Compile an explicitly reviewed, unexpired *proposal* for offline QA.

    Caller MUST NOT treat this output as trustable observed route evidence.
    Rule payload must never be directly applied without independent approval,
    effective-route evidence, atomic install/readback and full rollback.
    """
    if type(now_epoch) is not int or now_epoch<1:
        deny("INVALID_CLOCK")
    fields(plan,("schema","origin","dns","web","ntp","redirects","ipv6","hostforwards","owner_uid","cleanup"),"INVALID_PLAN")
    if plan["schema"]!=1 or plan["origin"]!="PROPOSED_ONLY" or type(plan["owner_uid"]) is not int or not 100<=plan["owner_uid"]<=65534:
        deny("INVALID_IDENTITY")
    dns=plan["dns"]
    fields(dns,("public_ipv4","tcp","udp","resolver_control"),"INVALID_DNS")
    resolver=ip4(dns["public_ipv4"])
    if dns["tcp"] is not True or dns["udp"] is not True:
        deny("DNS_TRANSPORT_INCOMPLETE")
    # A process-private, reviewed resolv.conf is a future proposal, not
    # a supported QEMU -netdev option or something this function provisions.
    if dns["resolver_control"]!="PROCESS_PRIVATE_RESOLV_CONF_PROPOSED":
        deny("RESOLVER_ROUTE_NOT_CONTROLLED")
    if plan["ipv6"]!={"guest":"off","host":"deny"}:
        deny("IPV6_GUARD_MISSING")
    if type(plan["hostforwards"]) is not list or plan["hostforwards"] != [[h,g] for h,g in HOSTPORTS]:
        deny("UNEXPECTED_FORWARD")
    required_cleanup=(
        "qemu_absent","watchdog_absent","hostforwards_absent",
        "mounts_absent","nbd_detached","ipv4_rules_absent",
        "ipv6_rules_absent","user_absent","kvm_acl_removed",
        "guest_disk_absent","firmware_absent","serial_absent",
        "scratch_absent",
    )
    if plan["cleanup"]!=list(required_cleanup):
        deny("CLEANUP_CONTRACT_INCOMPLETE")
    ntp=plan["ntp"]
    fields(ntp,("mode","public_ipv4"),"INVALID_NTP")
    if ntp["mode"]!="REVIEWED_NTP_DESTINATION":
        deny("NTP_SOURCE_UNVERIFIED")
    ntp_addr=ip4(ntp["public_ipv4"])
    web=plan["web"]
    if type(web) is not list or not 1<=len(web)<=16:
        deny("WEB_BOUND_INVALID")
    whitelist={}
    expiry=now_epoch+3600
    for record in web:
        fields(record,("hostname","addresses","observed_epoch","ttl_seconds","https_only"),"WEB_BINDING_INVALID")
        hostname=host(record["hostname"])
        if hostname in whitelist or record["https_only"] is not True:
            deny("UNREVIEWED_WEB_HOST_OR_HTTP")
        stamp=record["observed_epoch"]
        ttl=record["ttl_seconds"]
        if type(stamp) is not int or type(ttl) is not int or ttl<1 or ttl>3600 or stamp>now_epoch or stamp+ttl<=now_epoch:
            deny("DNS_BINDING_EXPIRED_OR_UNOBSERVED")
        ips=record["addresses"]
        if not isinstance(ips,list) or not 1<=len(ips)<=12 or len(set(map(str,ips)))!=len(ips):
            deny("INVALID_WEB_ADDRESS_SET")
        whitelist[hostname]=tuple(sorted(ip4(x) for x in ips))
        expiry=min(expiry,stamp+ttl)
    redirects=plan["redirects"]
    if not isinstance(redirects,list) or len(redirects)>32:
        deny("REDIRECT_SET_INVALID")
    for item in redirects:
        if not isinstance(item,list) or len(item)!=2 or any(not isinstance(x,str) or x not in whitelist for x in item):
            deny("UNREVIEWED_REDIRECT")
    forwards=",".join(f"hostfwd=tcp:127.0.0.1:{h}-:{g}" for h,g in HOSTPORTS)
    netdev="user,id=net0,ipv6=off,"+forwards
    out=[
        "*filter",f":{CHAIN4} - [0:0]",
        f"-I OUTPUT 1 -m owner --uid-owner {plan['owner_uid']} -j {CHAIN4}",
        f"-A {CHAIN4} -o lo -d 127.0.0.1/32 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT",
    ]
    out.extend(f"-A {CHAIN4} -d {net} -j REJECT" for net in DENY_CIDRS)
    for protocol in ("udp","tcp"):
        out.append(f"-A {CHAIN4} -d {resolver}/32 -p {protocol} --dport 53 -j ACCEPT")
    out.append(f"-A {CHAIN4} -d {ntp_addr}/32 -p udp --dport 123 -j ACCEPT")
    for dest in sorted({x for addresses in whitelist.values() for x in addresses}):
        out.append(f"-A {CHAIN4} -d {dest}/32 -p tcp --dport 443 -j ACCEPT")
    out.extend((f"-A {CHAIN4} -j REJECT","COMMIT"))
    v6=[
        "*filter",f":{CHAIN6} - [0:0]",
        f"-I OUTPUT 1 -m owner --uid-owner {plan['owner_uid']} -j {CHAIN6}",
        f"-A {CHAIN6} -j REJECT","COMMIT",
    ]
    return Compiled(PROPOSED,netdev,resolver,expiry,"\n".join(out)+"\n","\n".join(v6)+"\n",required_cleanup)

def handle_answer_change(compiled: Compiled, *, current_epoch: int, new_addresses_equal: bool) -> str:
    """Any stale/change requires stop + full revalidation, never auto-expand."""
    if type(current_epoch) is not int or current_epoch>=compiled.expiry_epoch or new_addresses_equal is not True:
        return "BLOCKED_STOP_AND_REVIEW_REPLACEMENT"
    return "OFFLINE_UNEXPIRED_SNAPSHOT_NOT_OBSERVED"
