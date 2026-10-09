"""Sealed, one-attempt actor context. No launch, allocation or I/O on import.

The bootstrap seals the actual PID/starttime after atomic clone, before exec.
An inherited pidfd plus this root-controlled record lets an unprivileged
controller authenticate privileged peers without reading their /proc/exe.
No object in this module grants runtime authorization or produces Probe PASS.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import fcntl
import hashlib
import json
import math
import os
import re
import select
import stat
import time

from probe_contract import compile_plan, validate_plan
from probe_a_linux_identity import ProcessIdentity, ProcessBinding

ACTORS = ("guardian", "observer", "controller")
MAX_CONFIG = 65536
MAX_STARTUP = 2048
F_GET_SEALS, F_ADD_SEALS, SEALS = 1034, 1033, 15


class SessionDenied(RuntimeError):
    pass


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          allow_nan=False, ensure_ascii=True).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise SessionDenied("NONCANONICAL_CONTEXT") from None


def decode(raw, maximum=MAX_CONFIG):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise SessionDenied("DUPLICATE_CONTEXT_FIELD")
            result[key] = value
        return result
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise SessionDenied("CONTEXT_BOUNDS")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(SessionDenied("NONFINITE_CONTEXT")))
    except (ValueError, UnicodeError, RecursionError):
        raise SessionDenied("MALFORMED_CONTEXT") from None
    if canonical(value) != raw:
        raise SessionDenied("NONCANONICAL_CONTEXT")
    return value


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hexvalue(value, length):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def identity_record(identity):
    if not isinstance(identity, ProcessIdentity):
        raise SessionDenied("KERNEL_PROCESS_IDENTITY_REQUIRED")
    return json.loads(canonical(asdict(identity)))


def identity_from(record):
    fields = {"pid", "starttime", "uids", "gids", "groups", "capabilities", "no_new_privs", "executable"}
    if type(record) is not dict or set(record) != fields:
        raise SessionDenied("INCOMPLETE_PROCESS_IDENTITY")
    for key, count in (("uids", 4), ("gids", 4), ("capabilities", 5), ("executable", 2)):
        if (type(record[key]) is not list or len(record[key]) != count
                or any(type(n) is not int or n < 0 for n in record[key])):
            raise SessionDenied("INVALID_PROCESS_IDENTITY")
    if (type(record["groups"]) is not list or len(record["groups"]) > 64
            or any(type(n) is not int or n < 0 for n in record["groups"])
            or type(record["pid"]) is not int or record["pid"] <= 1
            or type(record["starttime"]) is not int or record["starttime"] <= 0
            or type(record["no_new_privs"]) is not int or record["no_new_privs"] not in (0, 1)):
        raise SessionDenied("INVALID_PROCESS_IDENTITY")
    values = dict(record)
    for key in ("uids", "gids", "groups", "capabilities", "executable"):
        values[key] = tuple(values[key])
    return ProcessIdentity(**values)


@dataclass(frozen=True)
class ExecutionContext:
    session: str
    source_commit: str
    inventory: str
    plan: object
    end: float
    cutoff: float

    def __post_init__(self):
        if (not hexvalue(self.session, 32) or not hexvalue(self.source_commit, 40)
                or not hexvalue(self.inventory, 64)
                or validate_plan(self.plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED"
                or any(type(x) not in (int, float) or not math.isfinite(x) for x in (self.end, self.cutoff))
                or self.end-self.cutoff != 60):
            raise SessionDenied("INVALID_IMMUTABLE_EXECUTION_CONTEXT")

    def record(self):
        return {"v": 1, "session": self.session, "source_commit": self.source_commit,
                "inventory": self.inventory, "plan": {"scope": self.plan.scope,
                    "uid": self.plan.uid, "dns": self.plan.dns},
                "end": self.end, "cutoff": self.cutoff}

    @property
    def identifier(self):
        return digest(self.record())

    def check_time(self, now, *, cleanup=False):
        limit = self.end if cleanup else self.cutoff
        if type(now) not in (float, int) or not math.isfinite(now) or not now < limit:
            raise SessionDenied("SHARED_DEADLINE_EXHAUSTED")

    @classmethod
    def from_record(cls, record):
        if (type(record) is not dict or set(record) != {
                "v", "session", "source_commit", "inventory", "plan", "end", "cutoff"}
                or type(record["v"]) is not int or record["v"] != 1
                or type(record["plan"]) is not dict or set(record["plan"]) != {"scope", "uid", "dns"}):
            raise SessionDenied("INVALID_CONTEXT_SCHEMA")
        return cls(record["session"], record["source_commit"], record["inventory"],
                   compile_plan(**record["plan"]), record["end"], record["cutoff"])


@dataclass(frozen=True)
class RoleConfiguration:
    context: ExecutionContext
    role: str
    identity: ProcessIdentity
    bootstrap: ProcessIdentity
    descriptors: tuple
    peers: tuple = ()

    def __post_init__(self):
        if self.role not in ACTORS:
            raise SessionDenied("ROLE_SUBSTITUTION")
        identity_from(identity_record(self.identity))
        identity_from(identity_record(self.bootstrap))
        if self.bootstrap.uids != (0,)*4:
            raise SessionDenied("TRUSTED_BOOTSTRAP_IDENTITY_REQUIRED")
        if self.role == "controller":
            self.identity.require_controller()
        elif self.identity.uids != (0,)*4 or self.identity.no_new_privs != 1:
            raise SessionDenied("ROOT_ACTOR_IDENTITY_REQUIRED")
        names, fds = set(), set()
        allowed = {"startup", "guardian", "observer", "controller", "audit",
                   "guardian-pidfd", "observer-pidfd", "startup-pidfd"}
        for name, fd in self.descriptors:
            if (name not in allowed or name in names or type(fd) is not int or fd < 3 or fd in fds):
                raise SessionDenied("DESCRIPTOR_SUBSTITUTION_OR_DUPLICATION")
            names.add(name); fds.add(fd)
        required = {"startup", "guardian", "observer", "guardian-pidfd", "observer-pidfd", "startup-pidfd"} \
            if self.role == "controller" else ({"startup", "controller"} if self.role == "guardian"
                                               else {"startup", "controller", "audit"})
        if names != required:
            raise SessionDenied("UNEXPECTED_ROLE_DESCRIPTORS")
        peer_roles = set()
        for role, identity in self.peers:
            if role not in ACTORS or role == self.role or role in peer_roles:
                raise SessionDenied("INVALID_PEER_HANDOFF")
            identity_from(identity_record(identity)); peer_roles.add(role)
        if self.role == "controller" and peer_roles != {"guardian", "observer"}:
            raise SessionDenied("PRIVILEGED_PEER_HANDOFF_REQUIRED")

    def record(self):
        return {"v": 1, "context": self.context.record(), "role": self.role,
                "identity": identity_record(self.identity), "bootstrap": identity_record(self.bootstrap),
                "descriptors": [list(x) for x in self.descriptors],
                "peers": [[r, identity_record(i)] for r, i in self.peers]}

    def encode(self):
        value = canonical(self.record())
        if len(value) > MAX_CONFIG:
            raise SessionDenied("ROLE_CONFIG_TOO_LARGE")
        return value

    @classmethod
    def from_bytes(cls, raw):
        value = decode(raw)
        if (type(value) is not dict or set(value) != {
                "v", "context", "role", "identity", "bootstrap", "descriptors", "peers"}
                or type(value["v"]) is not int or value["v"] != 1
                or type(value["descriptors"]) is not list or type(value["peers"]) is not list
                or any(type(p) is not list or len(p) != 2 for p in value["descriptors"] + value["peers"])):
            raise SessionDenied("INVALID_SEALED_ROLE_SCHEMA")
        return cls(ExecutionContext.from_record(value["context"]), value["role"],
                   identity_from(value["identity"]), identity_from(value["bootstrap"]),
                   tuple(tuple(p) for p in value["descriptors"]),
                   tuple((role, identity_from(record)) for role, record in value["peers"]))


def load_sealed(fd, *, read=os.pread, inspect=os.fstat, flags=fcntl.fcntl):
    if type(fd) is not int or fd < 3:
        raise SessionDenied("INVALID_CONFIG_DESCRIPTOR")
    before = inspect(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
            or not 0 < before.st_size <= MAX_CONFIG
            or flags(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
            or flags(fd, F_GET_SEALS) & SEALS != SEALS):
        raise SessionDenied("ROOT_CONTROLLED_SEALED_READONLY_CONFIG_REQUIRED")
    raw = read(fd, MAX_CONFIG+1, 0)
    if inspect(fd) != before or len(raw) != before.st_size:
        raise SessionDenied("CONFIG_DESCRIPTOR_DRIFT")
    return RoleConfiguration.from_bytes(raw)


class PendingRoleConfiguration:
    """Owned parent writer/read-only child view, sealed BEFORE exec.

    allocate is explicitly disabled and requires a separately issued attempt
    permit. It is never called by offline tests. The writable fd cannot cross
    exec. Completion derives PID/starttime from the kernel, never actor text.
    """
    def __init__(self, reader, writer, *, build, observe=ProcessBinding):
        self.reader, self.writer, self.build, self.observe = reader, writer, build, observe
        self.completed = False

    @classmethod
    def allocate(cls, *, build, permit=None, activated=False):
        if activated is not True or os.geteuid() != 0 or permit is None or not permit.active():
            raise SessionDenied("CONFIG_ALLOCATION_DISABLED")
        writer = os.memfd_create("probe-a-role", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        reader = None
        try:
            os.fchmod(writer, 0o600)
            reader = os.open(f"/proc/self/fd/{writer}", os.O_RDONLY | os.O_CLOEXEC)
            return cls(reader, writer, build=build)
        except BaseException:
            if reader is not None: os.close(reader)
            os.close(writer)
            raise

    def complete(self, pid, pidfd):
        if self.completed or self.writer is None:
            raise SessionDenied("CONFIG_COMPLETION_REPLAY")
        self.completed = True
        binding = self.observe(pid)
        try:
            if not binding.alive() or select.select([pidfd], [], [], 0)[0]:
                raise SessionDenied("ATOMIC_CHILD_DIED_DURING_HANDOFF")
            config = self.build(binding.identity)
            if (not isinstance(config, RoleConfiguration) or config.identity.pid != pid
                    or config.identity.starttime != binding.identity.starttime):
                raise SessionDenied("CONFIG_IDENTITY_NOT_KERNEL_DERIVED")
            data = config.encode()
            if os.write(self.writer, data) != len(data):
                raise SessionDenied("INCOMPLETE_CONFIG_WRITE")
            fcntl.fcntl(self.writer, F_ADD_SEALS, SEALS)
            os.close(self.writer); self.writer = None
            return config
        finally:
            binding.close()

    def close(self):
        for name in ("reader", "writer"):
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is not None: os.close(fd)


class DelegatedProcessBinding:
    """A sealed bootstrap identity + inherited, kernel-identified live pidfd.

    Only lifetime/credentials are checked here; the controller never claims
    independently to have inspected the root actor's executable or caps.
    The trusted coordinator owns those observations before controller start.
    """
    def __init__(self, identity, pidfd, *, sealed=None, role=None, inspect_fdinfo=None, alive=None):
        if not isinstance(sealed, RoleConfiguration) or sealed.role != "controller":
            raise SessionDenied("SEALED_CONTROLLER_HANDOFF_REQUIRED")
        identities = dict(sealed.peers) | {"startup": sealed.bootstrap}
        if (role not in identities or identities[role] != identity
                or dict(sealed.descriptors).get(role + "-pidfd") != pidfd
                or type(pidfd) is not int or pidfd < 3):
            raise SessionDenied("UNBOUND_PRIVILEGED_PEER_DESCRIPTOR")
        self.identity, self.pidfd = identity, pidfd
        self.inspect_fdinfo = inspect_fdinfo or self._fdinfo
        self.alive = alive or (lambda: not select.select([self.pidfd], [], [], 0)[0])
        self.verify()

    @staticmethod
    def _fdinfo(fd):
        handle = os.open(f"/proc/self/fdinfo/{fd}", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            data = os.read(handle, 4097)
            if len(data) > 4096:
                raise SessionDenied("PIDFD_INFO_UNBOUNDED")
            return data.decode("ascii")
        finally:
            os.close(handle)

    def verify(self):
        fields = [line.split(":", 1)[1].strip() for line in self.inspect_fdinfo(self.pidfd).splitlines()
                  if line.startswith("Pid:")]
        if fields != [str(self.identity.pid)] or self.alive() is not True:
            raise SessionDenied("STALE_OR_SUBSTITUTED_PIDFD")
        return True

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd); self.pidfd = None
