"""Fixed Probe A UID worker and root peer; NEVER imported by offline CI to run.

Network functions execute only through the deliberately explicit main mode.
The only destinations are constants or the reviewed single public DNS target.
No shell, DNS system resolver, arbitrary FQDN, logs or credentials.
"""
from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_a_client import perform, admissible_result, CASE_NAMES
from probe_a_dns import targets

UID_MIN, UID_MAX = 42000, 59999
FIXED_ALT = "1.1.1.1"
FIXED_DNS = "9.9.9.9"
FIXED_TXID = 6699
PEER_PORT = 19468
HELLO = b"P2AHELLO"
REPLY = b"P2AACK!!"


def serve_established(*, socket_factory=socket.socket):
    with socket_factory(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(1.5)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        listener.bind(("127.0.0.1", PEER_PORT))
        listener.listen(1)
        # Parent's streaming reader launches the independently attested
        # root-side peer ONLY after this readiness line is received.
        print("READY", flush=True)
        connection, address = listener.accept()
        with connection:
            connection.settimeout(1.5)
            if address[0] != "127.0.0.1" or connection.recv(16) != HELLO:
                return "BLOCKED_PEER_MISMATCH"
            connection.sendall(REPLY)
            return "ROOT_PEER_ROUNDTRIP_COMPLETE"


def root_peer(*, socket_factory=socket.socket, euid=os.geteuid):
    if euid() != 0:
        return "BLOCKED_ROOT_PEER_NOT_PRIVILEGED"
    with socket_factory(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.5)
        sock.connect(("127.0.0.1", PEER_PORT))
        sock.sendall(HELLO)
        return "ROOT_PEER_ACK_MATCHED" if sock.recv(16) == REPLY else "BLOCKED_ROOT_PEER_RESPONSE"


def run_worker(case, uid, dns, *, euid=os.geteuid, groups=os.getgroups,
               socket_factory=socket.socket):
    if (type(uid) is not int or not UID_MIN <= uid <= UID_MAX or
            euid() != uid or groups() or dns != FIXED_DNS or case not in CASE_NAMES):
        return "BLOCKED_UID_OR_SCOPE"
    # Reject any alteration of the fixed target inventory.
    if len(targets(dns, FIXED_ALT)) != 9:
        return "BLOCKED_TARGET_VECTOR"
    if case == "loopback-established":
        return serve_established(socket_factory=socket_factory)
    return perform(case, approved_dns=dns, alternate_dns=FIXED_ALT,
                   txid=FIXED_TXID, factory=socket_factory)


def main(argv=None):
    """Explicit internal command only; no imports execute it."""
    values = sys.argv[1:] if argv is None else argv
    try:
        if (len(values) == 4 and values[0] == "--p2a-internal" and
                values[1] in CASE_NAMES and values[2] == FIXED_DNS and
                values[3].isdigit()):
            case, uid = values[1], int(values[3])
            answer = run_worker(case, uid, values[2])
            ok = admissible_result(case, answer)
        elif values == ["--p2a-root-peer"]:
            answer = root_peer()
            ok = answer == "ROOT_PEER_ACK_MATCHED"
        else:
            answer, ok = "BLOCKED_ARGUMENTS", False
    except BaseException:
        answer, ok = "BLOCKED_CLIENT_FAILURE", False
    if len(answer) > 80 or "\n" in answer:
        answer, ok = "BLOCKED_BAD_RESULT", False
    print(answer, flush=True)
    return 0 if ok else 7


if __name__ == "__main__":
    raise SystemExit(main())
