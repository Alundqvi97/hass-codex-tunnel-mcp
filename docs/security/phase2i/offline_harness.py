"""Phase 2I: pure, inert models for *future* disposable HAOS acceptance.

Never launches QEMU, reads live network state, runs a shell or uses credentials.
Synthetic classifications do not demonstrate Linux kernel/conntrack behavior.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Mapping

PRIVATE_AND_RESERVED = tuple(ipaddress.ip_network(x) for x in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
    '224.0.0.0/4', '240.0.0.0/4',
))
FORWARDS = {18123: 8123, 18124: 80, 14357: 4357, 19583: 9583}
ALLOWED_PROBE_CODES = frozenset({
    'QEMU_EXIT', 'GUEST_STARTUP_NOT_OBSERVABLE', 'HOST_FORWARD_ABSENT',
    'TCP_REFUSED', 'TCP_TIMEOUT', 'NETWORK_ERROR', 'HTTP_404',
    'HTTP_VALID_OTHER', 'HTTP_FIRST_BOOT_POSSIBLE', 'HA_CORE_MANIFEST',
    'HA_API_RESPONDING', 'SUPERVISOR_API_REACHABLE', 'SUPERVISOR_RUNNING',
    'ADDON_IN_STORE', 'ADDON_INSTALLED', 'ADDON_RUNNING',
    'DNS_LOOPBACK_RISK', 'DNS_PRIVATE_RISK', 'DNS_PUBLIC_POSSIBLE',
    'DNS_UNKNOWN', 'SERIAL_KERNEL_OBSERVED', 'SERIAL_NOT_OBSERVED',
})
CLEANUP_ITEMS = (
    'guest_pid_absent', 'watchdog_pid_absent', 'hostforward_listeners_absent',
    'mounts_absent', 'nbd_detached', 'ipv4_jump_absent', 'ipv4_chain_absent',
    'ipv6_jump_absent', 'ipv6_chain_absent', 'kvm_acl_removed',
    'temporary_uid_removed', 'firmware_removed', 'guest_disk_removed',
    'private_serial_removed', 'scratch_directory_removed',
)


def classify_synthetic_packet(*, destination: str, protocol: str,
                              port: int, interface: str = 'eth0',
                              conntrack: str = 'NEW') -> str:
    """Return expected ORDERED rule outcome, not a live kernel verdict.

    The per-QEMU-UID OUTPUT jump is assumed to have already matched.
    The ESTABLISHED loopback exception is intentionally TCP-only and narrow.
    """
    try:
        ip = ipaddress.ip_address(destination)
    except ValueError:
        return 'REJECT_INVALID_ADDRESS'
    if ip.version == 6:
        return 'REJECT_IPV6'
    if (interface == 'lo' and ip == ipaddress.IPv4Address('127.0.0.1')
            and protocol == 'tcp' and conntrack == 'ESTABLISHED'):
        return 'ALLOW_ESTABLISHED_LOOPBACK_REPLY'
    if any(ip in network for network in PRIVATE_AND_RESERVED):
        return 'REJECT_RESERVED'
    if protocol == 'tcp' and port in (80, 443):
        return 'ALLOW_PUBLIC_WEB'
    if protocol == 'udp' and port in (53, 123):
        return 'ALLOW_PUBLIC_DNS_OR_NTP'
    return 'REJECT_OTHER'


def parse_resolvers(resolv_conf: str) -> tuple[str, ...]:
    """Extract literal numeric resolvers; do not resolve hostnames."""
    result = []
    for raw in resolv_conf.splitlines():
        tokens = raw.partition('#')[0].split()
        if len(tokens) >= 2 and tokens[0] == 'nameserver':
            try:
                result.append(str(ipaddress.ip_address(tokens[1])))
            except ValueError:
                result.append('INVALID')
    return tuple(result)


def resolver_assessment(resolvers: tuple[str, ...]) -> str:
    """The runner resolver is not necessarily QEMU's actual upstream DNS."""
    if not resolvers or 'INVALID' in resolvers:
        return 'DNS_UNKNOWN'
    try:
        addresses = [ipaddress.ip_address(r) for r in resolvers]
    except ValueError:
        return 'DNS_UNKNOWN'
    if any(ip.is_loopback for ip in addresses):
        return 'DNS_LOOPBACK_RISK'
    if any(ip.version == 6 or any(ip in n for n in PRIVATE_AND_RESERVED)
           for ip in addresses):
        return 'DNS_PRIVATE_RISK'
    return 'DNS_PUBLIC_POSSIBLE'


def validate_qemu_user_netdev(netdev: str, *, require_ipv6_off: bool = True) -> tuple[str, ...]:
    """Conservative configuration lint; never evaluates or launches QEMU."""
    defects = []
    entries = netdev.split(',')
    if not entries or entries[0] != 'user' or 'id=net0' not in entries:
        defects.append('NOT_EXPECTED_USER_NETDEV')
    if require_ipv6_off and 'ipv6=off' not in entries:
        defects.append('GUEST_IPV6_NOT_EXPLICITLY_OFF')
    forwards = {}
    for item in entries:
        if not item.startswith('hostfwd='):
            continue
        match = re.fullmatch(r'hostfwd=tcp:127\.0\.0\.1:(\d+)-:(\d+)', item)
        if not match:
            defects.append('UNSAFE_HOST_FORWARD')
            continue
        host, guest = map(int, match.groups())
        if host in forwards:
            defects.append('DUPLICATE_HOST_FORWARD')
        forwards[host] = guest
    if forwards != FORWARDS:
        defects.append('UNEXPECTED_HOST_FORWARD_SET')
    return tuple(dict.fromkeys(defects))


def loopback_listener_ports(proc_net_tcp: str) -> frozenset[int]:
    """Parse synthetic /proc/net/tcp; LISTEN + 127.0.0.1 only."""
    ports = set()
    for row in proc_net_tcp.splitlines()[1:]:
        tokens = row.split()
        if len(tokens) < 4 or tokens[3] != '0A':
            continue
        try:
            addr, port = tokens[1].split(':')
            if addr == '0100007F':
                ports.add(int(port, 16))
        except (ValueError, IndexError):
            continue
    return frozenset(ports)


def classify_probe(*, running: bool = True, listener: bool = True,
                   error: str | None = None, status: int | None = None,
                   path: str = '/manifest.json', serial_observed: bool = True) -> str:
    """Fixed categories only. Never include exception strings or HTTP bodies."""
    if not running:
        return 'QEMU_EXIT'
    if not listener:
        return 'HOST_FORWARD_ABSENT'
    if error == 'refused':
        return 'TCP_REFUSED'
    if error == 'timeout':
        return 'TCP_TIMEOUT'
    if error is not None:
        return 'NETWORK_ERROR'
    if status is None:
        return 'GUEST_STARTUP_NOT_OBSERVABLE' if not serial_observed else 'NETWORK_ERROR'
    if status == 404:
        return 'HTTP_404'
    if status == 200 and path == '/manifest.json':
        return 'HA_CORE_MANIFEST'
    if status in (200, 401) and path == '/api/':
        return 'HA_API_RESPONDING'
    if path in ('/', '/api/onboarding') and status in (200, 202):
        return 'HTTP_FIRST_BOOT_POSSIBLE'
    return 'HTTP_VALID_OTHER'


def sanitized_code(candidate: str) -> str:
    """Only allow authored diagnostic labels; no raw untrusted strings."""
    return candidate if candidate in ALLOWED_PROBE_CODES else 'NETWORK_ERROR'


def choose_data_partition(records: list[Mapping[str, str]]) -> str:
    """Fail closed unless exactly one correctly labelled ext4 NBD data partition."""
    labeled = [r for r in records if r.get('LABEL') == 'hassos-data']
    if len(labeled) != 1:
        raise ValueError('HASSOS_DATA_LABEL_MISSING_OR_AMBIGUOUS')
    record = labeled[0]
    device = record.get('PATH', '')
    if (record.get('TYPE') != 'ext4'
            or re.fullmatch(r'/dev/nbd\d+p\d+', device) is None):
        raise ValueError('HASSOS_DATA_PARTITION_UNSUPPORTED')
    return device


def supervisor_local_store(root: Path) -> Path:
    """Require a current-layout local store; do not change private state."""
    new = root / 'supervisor' / 'apps' / 'local'
    if not new.is_dir():
        raise ValueError('SUPERVISOR_CURRENT_LOCAL_STORE_NOT_VERIFIED')
    return new


def cleanup_receipt(observed: Mapping[str, bool]) -> tuple[str, ...]:
    """Every independent restoration check must be true (never print secrets)."""
    return tuple(item for item in CLEANUP_ITEMS if observed.get(item) is not True)


def future_guest_authorized() -> bool:
    """The Phase 2I offline model cannot authorize or create any guest."""
    return False


def runtime_milestones(evidence: Mapping[str, bool]) -> tuple[str, ...]:
    """Only report success stages if each earlier independently proven stage exists."""
    stages = (
        ('supervisor_api_reachable', 'SUPERVISOR_API_REACHABLE'),
        ('supervisor_running', 'SUPERVISOR_RUNNING'),
        ('addon_in_store', 'ADDON_IN_STORE'),
        ('addon_installed', 'ADDON_INSTALLED'),
        ('addon_running', 'ADDON_RUNNING'),
    )
    outcome = []
    for key, label in stages:
        if evidence.get(key) is not True:
            break
        outcome.append(label)
    return tuple(outcome)


def cleanup_intentions() -> tuple[str, ...]:
    """Neutral restoration checklist, not executable cleanup commands."""
    return CLEANUP_ITEMS
