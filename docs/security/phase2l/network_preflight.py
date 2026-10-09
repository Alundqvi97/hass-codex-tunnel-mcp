"""Phase 2L pure network design preflight — no live sockets or firewall changes.

Use this model for synthetic/CI validation. It distinguishes a syntactically
consistent proposed egress policy from an attested libslirp route or actual
kernel enforcement; neither is established by these fixtures.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

MAX_INPUT = 8192
EXPECTED_FORWARD_PORTS = {18123: 8123, 18124: 80, 14357: 4357, 19583: 9583}
EXPECTED_WEB_PORTS = (80, 443)
BLOCKED = "BLOCKED"
CONSISTENT = "OFFLINE_CONSISTENT_NOT_RUNTIME_VERIFIED"

@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str
    # Only fixed labels; do not log resolver addresses, packet captures or URLs.
    def receipt(self) -> str:
        return "PHASE2L_" + self.status + "_" + self.reason

def reject(reason: str) -> Verdict:
    return Verdict(BLOCKED, reason)

def public_ip(text: object) -> bool:
    if not isinstance(text, str):
        return False
    try:
        ip = ipaddress.ip_address(text)
        return ip.version == 4 and ip.is_global and str(ip) == text
    except ValueError:
        return False

def parse_resolv_conf(raw: str) -> tuple[str, ...]:
    if not isinstance(raw, str) or len(raw) > MAX_INPUT or "\x00" in raw:
        raise ValueError("INVALID_RESOLV_CONF")
    result = []
    for line in raw.splitlines():
        fields = line.split("#", 1)[0].strip().split()
        if not fields:
            continue
        if fields[0] != "nameserver":
            continue
        if len(fields) != 2:
            raise ValueError("MALFORMED_RESOLVER")
        try:
            parsed = ipaddress.ip_address(fields[1])
        except ValueError as exc:
            raise ValueError("MALFORMED_RESOLVER") from exc
        result.append(str(parsed))
    if not result:
        raise ValueError("MISSING_RESOLVER")
    if len(result) != 1:
        raise ValueError("MULTIPLE_RESOLVERS")
    return tuple(result)

def validate_qemu_netdev(text: str) -> Verdict:
    if not isinstance(text, str) or len(text) > 1800:
        return reject("UNSUPPORTED_QEMU_NETDEV")
    entries=text.split(",")
    if entries[:2] != ["user", "id=net0"]:
        return reject("UNSUPPORTED_QEMU_NETDEV")
    if entries.count("ipv6=off") != 1 or "ipv6=on" in entries:
        return reject("GUEST_IPV6_NOT_DISABLED")
    forwards={}
    for entry in entries[2:]:
        if entry == "ipv6=off":
            continue
        match=re.fullmatch(r"hostfwd=tcp:127\.0\.0\.1:(\d+)-:(\d+)",entry)
        if match is None:
            return reject("QEMU_NETDEV_UNEXPECTED_OPTION")
        host,guest=(int(x) for x in match.groups())
        if host in forwards:
            return reject("DUPLICATE_FORWARD")
        forwards[host]=guest
    if forwards != EXPECTED_FORWARD_PORTS:
        return reject("UNEXPECTED_FORWARD")
    return Verdict(CONSISTENT,"LOCAL_ONLY_FORWARD_CONFIGURATION")

def resolver_kind(address: str) -> str:
    try:
        ip=ipaddress.ip_address(address)
    except ValueError:
        return "MALFORMED_RESOLVER"
    if ip.version == 6:
        return "IPV6_RESOLVER"
    if ip.is_loopback:
        return "LOCAL_STUB" if str(ip) == "127.0.0.53" else "LOOPBACK_RESOLVER"
    if ip.is_private or ip.is_link_local or ip.is_reserved or not ip.is_global:
        return "PRIVATE_OR_RESERVED_RESOLVER"
    return "PUBLIC_IPV4"

def inspect_network(resolv_conf: str, manifest: object, qemu_netdev: str) -> Verdict:
    """Manifest is a reviewed *proposal*. Never proves effective route/kernel."""
    try:
        resolvers=parse_resolv_conf(resolv_conf)
    except ValueError as exc:
        reason=str(exc)
        return reject(reason if reason in ("INVALID_RESOLV_CONF","MALFORMED_RESOLVER","MISSING_RESOLVER","MULTIPLE_RESOLVERS") else "INVALID_RESOLV_CONF")
    kind=resolver_kind(resolvers[0])
    if kind != "PUBLIC_IPV4":
        return reject(kind)
    qemu=validate_qemu_netdev(qemu_netdev)
    if qemu.status != CONSISTENT:
        return qemu
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version","approved_dns_ipv4","effective_upstream_ipv4",
        "qemu_route_evidence","dns_udp_53","dns_tcp_53",
        "host_ipv6_reject","private_ipv4_reject","egress_default_reject",
        "approved_web_ipv4","web_tcp_ports","reviewed_bootstrap_hosts",
        "cleanup_evidence",
    }:
        return reject("MANIFEST_MISSING_OR_INVALID")
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        return reject("MANIFEST_MISSING_OR_INVALID")
    declared=manifest["approved_dns_ipv4"]
    observed=manifest["effective_upstream_ipv4"]
    if not public_ip(declared) or declared != resolvers[0]:
        return reject("DNS_TARGET_NOT_APPROVED")
    if observed is None:
        return reject("QEMU_UPSTREAM_UNKNOWN")
    if not public_ip(observed) or observed != declared:
        return reject("QEMU_UPSTREAM_MISMATCH")
    # This is a *label for externally provided evidence*, not an attestation.
    # Before any VM authorization a different, reviewed runner-only
    # observation mechanism must establish this value; fixtures cannot.
    if manifest["qemu_route_evidence"] != "CONTROLLED_RESOLVER_PATH_REVIEWED":
        return reject("QEMU_ROUTE_UNVERIFIED")
    for key,code in (
        ("dns_udp_53","DNS_UDP_NOT_RESTRICTED"),
        ("dns_tcp_53","DNS_TCP_NOT_RESTRICTED"),
        ("host_ipv6_reject","HOST_IPV6_NOT_REJECTED"),
        ("private_ipv4_reject","PRIVATE_IPV4_NOT_REJECTED"),
        ("egress_default_reject","EGRESS_NOT_DEFAULT_DENY"),
        ("cleanup_evidence","CLEANUP_EVIDENCE_MISSING"),
    ):
        if manifest[key] is not True:
            return reject(code)
    web=manifest["approved_web_ipv4"]
    hosts=manifest["reviewed_bootstrap_hosts"]
    if not isinstance(web,list) or not web or len(web)>32 or len(set(map(str,web)))!=len(web) or not all(public_ip(ip) for ip in web):
        return reject("UNAPPROVED_WEB_DESTINATION")
    if not isinstance(hosts,list) or not hosts or len(hosts)>16 or not all(isinstance(h,str) and re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?",h) for h in hosts):
        return reject("BOOTSTRAP_HOSTS_NOT_REVIEWED")
    if type(manifest["web_tcp_ports"]) is not list or sorted(manifest["web_tcp_ports"]) != [80,443]:
        return reject("UNAPPROVED_WEB_PORT")
    return Verdict(CONSISTENT,"CONFIGURATION_ONLY")

def load_manifest(raw: str) -> object:
    if not isinstance(raw,str) or len(raw)>MAX_INPUT:
        raise ValueError("MANIFEST_OVERSIZED")
    try:
        return json.loads(raw)
    except (ValueError,TypeError) as exc:
        raise ValueError("MALFORMED_MANIFEST") from exc

def before_guest_authorization(verdict: Verdict) -> Verdict:
    """An offline assessment is not permission to launch a guest.

    Actual QEMU resolver path and firewall enforcement were not tested, so
    this remains blocked even for a fully consistent synthetic manifest.
    """
    if verdict.status != CONSISTENT:
        return verdict
    return reject("ACTUAL_ROUTE_AND_KERNEL_NOT_VERIFIED")
