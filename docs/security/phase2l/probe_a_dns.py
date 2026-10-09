"""Fixed, synthetic DNS/socket workload protocol for Probe A.

No network calls at import time. The CLI entry point deliberately does not
launch network traffic; a future approved, pinned runner must provide its own
explicit execution entrypoint and sandbox/UID restrictions.
"""
from __future__ import annotations
import ipaddress
import struct
from dataclasses import dataclass

NAME="p2-probe.invalid"
TYPES={"A":1}
MAX_PACKET=4096

class InvalidPacket(ValueError):
    pass

def query(transaction_id: int) -> bytes:
    if type(transaction_id) is not int or not 0<=transaction_id<=65535:
        raise InvalidPacket("BAD_ID")
    labels=NAME.encode("ascii").split(b".")
    question=b"".join(bytes((len(s),))+s for s in labels)+b"\x00"
    return struct.pack("!HHHHHH",transaction_id,0x0100,1,0,0,0)+question+struct.pack("!HH",1,1)

def verify_response(payload: bytes, transaction_id: int, *, tcp: bool=False) -> str:
    """Require a matched NXDOMAIN, not merely a returned UDP/TCP packet.

    TCP caller has already consumed and checked its two-octet framing.
    DNS compression in the question is deliberately rejected for simplicity.
    """
    expected=query(transaction_id)
    if not isinstance(payload,bytes) or len(payload)<len(expected) or len(payload)>MAX_PACKET:
        raise InvalidPacket("BAD_RESPONSE_LENGTH")
    tx,flags,questions,answers,authority,additional=struct.unpack("!HHHHHH",payload[:12])
    if tx!=transaction_id or questions!=1 or answers>32 or authority>32 or additional>32:
        raise InvalidPacket("BAD_RESPONSE_HEADER")
    if flags&0x8000==0 or flags&0x7800!=0 or flags&0x0200 or flags&0x000F!=3:
        raise InvalidPacket("NOT_COMPLETE_NXDOMAIN")
    if payload[12:len(expected)]!=expected[12:]:
        raise InvalidPacket("QUESTION_MISMATCH")
    return "DNS_TCP_MATCHED_NXDOMAIN" if tcp else "DNS_UDP_MATCHED_NXDOMAIN"

def verify_tcp_frame(frame: bytes, transaction_id: int) -> str:
    if not isinstance(frame,bytes) or len(frame)<2:
        raise InvalidPacket("TCP_FRAME_SHORT")
    size=struct.unpack("!H",frame[:2])[0]
    if size!=len(frame)-2 or size>MAX_PACKET:
        raise InvalidPacket("TCP_FRAME_LENGTH")
    return verify_response(frame[2:],transaction_id,tcp=True)

def targets(approved_dns: str, alternate_dns: str) -> tuple[tuple[str,str,int],...]:
    """Fixed test vector; the API accepts only reviewed public IPv4 literals.

    These are proposed destinations, not authority to send. Documentation
    addresses are negative only. No metadata endpoint or household address.
    """
    def public(value):
        try: addr=ipaddress.ip_address(value)
        except (ValueError,TypeError): raise InvalidPacket("DESTINATION_INVALID")
        if addr.version!=4 or not addr.is_global or addr.is_private or addr.is_reserved:
            raise InvalidPacket("DESTINATION_NOT_PUBLIC")
        return str(addr)
    a,b=public(approved_dns),public(alternate_dns)
    if a==b: raise InvalidPacket("ALTERNATE_DNS_DUPLICATE")
    return (
        ("approved-udp",a,53),("approved-tcp",a,53),
        ("alternate-udp",b,53),("alternate-tcp",b,53),
        ("private","10.255.255.254",443),
        ("link-local","169.254.77.77",443),
        ("ipv6-loopback","::1",443),
        ("loopback-new","127.0.0.1",19467),
        ("public-web",b,443),
    )

@dataclass(frozen=True)
class WorkResult:
    # Bounded categorical results only; never addresses or response bodies.
    labels: tuple[str,...]
    def receipt(self):
        return "CLIENT=SYNTHETIC_OR_UNVERIFIED"

def inspect_result(received, *, expected):
    """Validate an injected client's result shape; no live provenance."""
    if not isinstance(received,dict) or set(received)!=set(expected):
        return "BLOCKED_MISSING_CASES"
    if any(type(received[k]) is not bool or received[k] is not True for k in expected):
        return "BLOCKED_CLIENT_CASE"
    return "SYNTHETIC_CLIENT_COMPLETE_NOT_KERNEL_VERIFIED"
