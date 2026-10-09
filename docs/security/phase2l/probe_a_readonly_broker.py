"""Independent, default-disabled read-only RPC actor for Probe A.

Private inherited AF_UNIX streams only; no listening socket, pathname RPC,
shell, sudo, firewall-write request, peer-selected path or execution on import.
The broker may need root/CAP_NET_ADMIN for filter reads; Linux has no
read-only CAP_NET_ADMIN. Its exact API is read-only, not a claim that an
unreviewed root process is kernel-confined. Runtime confinement is UNVERIFIED.
"""
from __future__ import annotations

import json
import math
import os
import time

from probe_contract import validate_plan, CLEANUP_READBACKS
from probe_a_exec_adapter import Reply, checked_reply
from probe_a_ipc import BoundedSocketIPC, MAX_REQUEST, MAX_FRAME
from probe_a_linux_identity import CredentialSocket, ProcessBinding, ProcessIdentity
from probe_a_linux_launcher import NativeBoundedCapture, command_catalog
from probe_a_os_boundary import require_local_passwd_nss


class BrokerDenied(RuntimeError):
    pass


def catalog(plan):
    if validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise BrokerDenied("INVALID_OBSERVER_PLAN")
    commands = command_catalog(plan, "read-command")
    return {"read:" + str(i): argv for i, argv in enumerate(sorted(commands))}


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BrokerDenied("DUPLICATE_MESSAGE_KEY")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(BrokerDenied("NONFINITE_MESSAGE")))
    except (ValueError, UnicodeError):
        raise BrokerDenied("INVALID_JSON_MESSAGE") from None


class ReadOnlyBroker:
    """One bound peer/session, fixed catalog, shared absolute lifetime deadline.

    command/read_resource are trusted bootstrap bindings, never supplied by
    the untrusted request. handle() is pure protocol wiring for offline DI;
    serve() additionally enforces actual identity and explicit runtime review.
    """
    def __init__(self, plan, *, command, read_resource, observer_identity,
                 inventory_id, end, clock=time.monotonic, expected_peer=None):
        self.commands = catalog(plan)
        if (not callable(command) or not callable(read_resource)
                or type(inventory_id) is not str or len(inventory_id) != 64
                or any(c not in "0123456789abcdef" for c in inventory_id)
                or type(end) not in (int, float) or not math.isfinite(end)):
            raise BrokerDenied("MISSING_TRUSTED_OBSERVER_BINDINGS")
        self.command, self.read_resource = command, read_resource
        if not isinstance(observer_identity, ProcessIdentity):
            raise BrokerDenied("OBSERVER_KERNEL_IDENTITY_REQUIRED")
        self.identity, self.inventory_id = observer_identity, inventory_id
        self.expected_peer = expected_peer
        self.end, self.clock, self.sequence = end, clock, 0

    def handle(self, raw):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST or self.clock() >= self.end:
            raise BrokerDenied("REQUEST_BOUNDS_OR_DEADLINE")
        request = unique_json(raw)
        if (type(request) is not dict or set(request) != {"v", "seq", "op"}
                or type(request["v"]) is not int or request["v"] != 1
                or type(request["seq"]) is not int or request["seq"] != self.sequence + 1
                or request["seq"] > 4096 or type(request["op"]) is not str):
            raise BrokerDenied("UNEXPECTED_COMMAND_IDENTITY_OR_REPLAY")
        op = request["op"]
        deadline = min(self.end, self.clock() + 8)
        self.sequence = request["seq"]  # consumed before an uncertain observation
        if op in self.commands:
            reply = checked_reply(self.command(self.commands[op], deadline))
        elif op.startswith("resource:") and op[9:] in CLEANUP_READBACKS:
            # Fixed key only, no PID, path, argv or resource supplied by the caller.
            value = self.read_resource(op[9:], deadline)
            if type(value) is not bool:
                raise BrokerDenied("RESOURCE_READBACK_NOT_CATEGORICAL")
            reply = Reply(0, json.dumps({"observed": value}, separators=(",", ":")))
        else:
            raise BrokerDenied("WRITE_OR_UNKNOWN_RESOURCE_DENIED")
        if self.clock() >= deadline:
            raise BrokerDenied("OBSERVATION_COMPLETED_AFTER_DEADLINE")
        response = {"v": 1, "seq": self.sequence, "op": op,
                    "observer": [self.identity.pid, self.identity.starttime],
                    "inventory": self.inventory_id, "code": reply.code,
                    "stdout": reply.stdout, "evidence": "UNVERIFIED_NOT_PROBE_PASS"}
        encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode()
        if len(encoded) > MAX_FRAME:
            raise BrokerDenied("UNBOUNDED_RESPONSE")
        return encoded

    def serve(self, stream, peer, *, activated=False, verify_review=None):
        if (activated is not True or os.geteuid() != 0 or not callable(verify_review)
                or verify_review() is not True or not isinstance(self.command, NativeReadCommands)):
            raise BrokerDenied("BROKER_DISABLED_OR_UNREVIEWED")
        if (not isinstance(peer, ProcessBinding) or peer.identity != self.expected_peer
                or peer.verify() is not True):
            raise BrokerDenied("BOOTSTRAP_BOUND_CALLER_REQUIRED")
        own = ProcessBinding(os.getpid())
        try:
            if own.identity != self.identity or self.identity.uids != (0,) * 4:
                raise BrokerDenied("BROKER_PROCESS_PROVENANCE_DRIFT")
        finally:
            own.close()
        if peer.identity.uids[1] != 0:
            peer.identity.require_controller()
        # The peer is supplied through the trusted bootstrap's identity handoff;
        # SO_PEERCRED or peer-provided identity fields are never substituted.
        channel = BoundedSocketIPC(CredentialSocket(stream, peer), clock=self.clock)
        try:
            while self.clock() < self.end:
                request = channel.recv_bytes(MAX_REQUEST, deadline=self.end)
                channel.send_bytes(self.handle(request), deadline=min(self.end, self.clock() + 8))
        finally:
            channel.close()


class NativeReadCommands:
    """Actual contained read executor; pgrep/getent have no direct bypass."""
    def __init__(self, plan, *, capture, inventory):
        if not isinstance(capture, NativeBoundedCapture) or inventory is None:
            raise BrokerDenied("ATOMIC_READ_COMMAND_EXECUTOR_REQUIRED")
        self.allowed = frozenset(catalog(plan).values())
        self.capture, self.inventory = capture, inventory
        for argv, spec in capture.specs.items():
            if argv not in self.allowed or spec.role != "read-command":
                raise BrokerDenied("OBSERVER_CANNOT_INHERIT_GUARDIAN_WRITE_EXECUTOR")

    def __call__(self, argv, deadline):
        if type(argv) is not tuple or argv not in self.allowed:
            raise BrokerDenied("OBSERVER_WRITE_OR_UNKNOWN_COMMAND")
        if self.inventory.verify() is not True:
            raise BrokerDenied("OBSERVER_DEPENDENCY_DRIFT")
        if argv[0] == "/usr/bin/getent":
            require_local_passwd_nss()
        remaining = deadline - self.capture.clock()
        if not 0 < remaining <= 8:
            raise BrokerDenied("OBSERVER_DEADLINE")
        result = checked_reply(self.capture(argv, remaining))
        if self.inventory.verify() is not True:
            raise BrokerDenied("OBSERVER_DEPENDENCY_DRIFT")
        return result


class BrokerClient:
    """Adapter for existing ReadOnlyPostObserver/KernelReadback contracts."""
    def __init__(self, plan, *, channel, observer_identity, inventory_id):
        from probe_a_session import DelegatedProcessBinding
        if (not isinstance(channel, BoundedSocketIPC)
                or not isinstance(channel.stream, CredentialSocket)
                or not isinstance(channel.stream.peer, (ProcessBinding, DelegatedProcessBinding))
                or channel.stream.peer.identity != observer_identity
                or channel.stream.peer.verify() is not True):
            raise BrokerDenied("AUTHENTICATED_OBSERVER_CHANNEL_REQUIRED")
        self.reverse = {argv: key for key, argv in catalog(plan).items()}
        self.channel, self.identity, self.inventory_id = channel, observer_identity, inventory_id
        self.sequence = 0

    def query(self, op, deadline):
        if (self.sequence >= 4096 or type(deadline) not in (int, float)
                or not math.isfinite(deadline)
                or not self.channel.clock() < deadline <= self.channel.clock() + 8):
            raise BrokerDenied("CLIENT_REQUEST_DEADLINE_OR_SESSION_BOUNDS")
        self.sequence += 1
        raw = json.dumps({"v": 1, "seq": self.sequence, "op": op}, separators=(",", ":")).encode()
        self.channel.send_bytes(raw, deadline=deadline)
        response = unique_json(self.channel.recv_bytes(MAX_FRAME, deadline=deadline))
        if (type(response) is not dict or set(response) !=
                {"v", "seq", "op", "observer", "inventory", "code", "stdout", "evidence"}
                or type(response["v"]) is not int or response["v"] != 1
                or type(response["seq"]) is not int or response["seq"] != self.sequence
                or response["op"] != op
                or response["observer"] != [self.identity.pid, self.identity.starttime]
                or response["inventory"] != self.inventory_id
                or response["evidence"] != "UNVERIFIED_NOT_PROBE_PASS"):
            raise BrokerDenied("OBSERVER_PROVENANCE_OR_SEQUENCE_MISMATCH")
        return checked_reply(Reply(response["code"], response["stdout"]))

    def read(self, argv, deadline):
        if type(argv) is not tuple or argv not in self.reverse:
            raise BrokerDenied("CLIENT_WRITE_OR_UNKNOWN_READ")
        return self.query(self.reverse[argv], deadline)

    def readback(self, key, deadline):
        if key not in CLEANUP_READBACKS:
            raise BrokerDenied("UNKNOWN_RESOURCE")
        reply = self.query("resource:" + key, deadline)
        value = unique_json(reply.stdout.encode())
        if reply.code != 0 or type(value) is not dict or set(value) != {"observed"} or type(value["observed"]) is not bool:
            raise BrokerDenied("RESOURCE_OBSERVATION_INVALID")
        return value["observed"]  # observation only; cannot compose trusted PASS
