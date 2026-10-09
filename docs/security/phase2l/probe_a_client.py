"""Fixed synthetic DNS/socket workload functions for Probe A.

No automatic main, no packet capture, no secrets and no home endpoints.
Socket operations occur ONLY if a separately approved caller explicitly
calls a function. All targets are passed through fixed-case allowlist.
"""
from __future__ import annotations
import socket
import struct
from probe_a_dns import query, verify_response, verify_tcp_frame, targets, InvalidPacket

TIMEOUT=1.5
MAX_REPLY=4096
CASE_NAMES=("approved-udp","approved-tcp","alternate-udp","alternate-tcp",
            "private","link-local","ipv6-loopback","loopback-new",
            "public-web","loopback-established")

def _recv_exact(sock, size):
    if type(size) is not int or not 0<=size<=MAX_REPLY:
        raise InvalidPacket("BOUNDED_SIZE")
    buf=bytearray()
    while len(buf)<size:
        chunk=sock.recv(size-len(buf))
        if not chunk:
            raise InvalidPacket("TRUNCATED_TCP")
        buf.extend(chunk)
    return bytes(buf)

def dns_udp(ip: str,txid: int,*,factory=socket.socket):
    with factory(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.connect((ip,53))
        s.sendall(query(txid))
        payload=s.recv(MAX_REPLY)
        return verify_response(payload,txid)

def dns_tcp(ip: str,txid: int,*,factory=socket.socket):
    with factory(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        s.connect((ip,53))
        wire=query(txid)
        s.sendall(struct.pack("!H",len(wire))+wire)
        hdr=_recv_exact(s,2)
        length=struct.unpack("!H",hdr)[0]
        body=_recv_exact(s,length)
        return verify_tcp_frame(hdr+body,txid)

def negative_socket(ip: str,port: int,*,v6=False,factory=socket.socket):
    """A failed socket is NOT standalone firewall-denial proof.

    Caller must verify matching terminal REJECT rule counter increments.
    """
    with factory(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.connect((ip,port))
        except OSError:
            return "SOCKET_FAILED_REQUIRES_KERNEL_COUNTER"
        return "BLOCKED_UNEXPECTED_CONNECTION"

def perform(case: str, *, approved_dns: str, alternate_dns: str, txid: int, factory=socket.socket):
    mapping={name:(addr,port) for name,addr,port in targets(approved_dns,alternate_dns)}
    if case not in CASE_NAMES:
        return "BLOCKED_UNREVIEWED_CASE"
    if case=="loopback-established":
        return "BLOCKED_SEPARATE_ROOT_PEER_REQUIRED"
    addr,port=mapping[case]
    if case=="approved-udp":
        return dns_udp(addr,txid,factory=factory)
    if case=="approved-tcp":
        return dns_tcp(addr,txid,factory=factory)
    if case=="alternate-udp":
        # Alternate UDP query could still receive a response if firewall
        # is broken. Do not accept an ordinary DNS packet as a success.
        with factory(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            try:
                s.connect((addr,port))
                s.sendall(query(txid))
                s.recv(MAX_REPLY)
            except OSError:
                return "SOCKET_FAILED_REQUIRES_KERNEL_COUNTER"
            return "BLOCKED_UNEXPECTED_DNS_REPLY"
    if case=="alternate-tcp":
        return negative_socket(addr,port,factory=factory)
    return negative_socket(addr,port,v6=(case=="ipv6-loopback"),factory=factory)

def admissible_result(case, result):
    if case in ("approved-udp","approved-tcp"):
        return result==("DNS_UDP_MATCHED_NXDOMAIN" if case=="approved-udp" else "DNS_TCP_MATCHED_NXDOMAIN")
    if case=="loopback-established":
        return result=="ROOT_PEER_ROUNDTRIP_COMPLETE"
    return result=="SOCKET_FAILED_REQUIRES_KERNEL_COUNTER"
