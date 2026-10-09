"""Disabled Linux atomic exec and independently supervised actor foundation.

This is not a runnable entry point. A reviewed root bootstrap, approved
inventory and pre-provisioned owned cgroup descriptors are required. No
fork/exec/cgroup/capability operation occurs on import or on disabled launch.
No controller Python callback is ever executed in a privileged child.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import fcntl
import math
import os
import resource
import select
import signal
import socket
import stat
import time

from probe_a_linux_identity import check_root_file, read_at
from probe_a_privilege import drop_controller, verify_unprivileged
from probe_a_exec_adapter import Reply, checked_reply
from probe_contract import (validate_plan, emergency_deny_commands, emergency_barrier_command)
from probe_a_os_boundary import SAVE4, SAVE6, VERSION4, VERSION6

CLONE_PIDFD = 0x1000
CLONE_INTO_CGROUP = 0x200000000
CGROUP2_SUPER_MAGIC = 0x63677270
# Linux asm-generic/fcntl.h ABI; some Python builds omit these bindings.
# The actual fcntl syscall must still succeed; there is no unsealed fallback.
F_GET_SEALS = 1034
SEALS = 0x000F  # SEAL_SEAL | SEAL_SHRINK | SEAL_GROW | SEAL_WRITE
ACTORS = ("guardian", "observer", "controller")
ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
EXECUTABLES = {
    **{role: frozenset(("/usr/bin/python3",)) for role in ACTORS},
    "peer": frozenset(("/usr/bin/python3",)),
    "worker": frozenset(("/usr/bin/setpriv",)),
    **{role: frozenset(("/usr/sbin/iptables", "/usr/sbin/ip6tables",
                       "/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save",
                       "/usr/bin/pgrep", "/usr/bin/getent"))
       for role in ("read-command", "guardian-command")},
}


class LaunchDenied(RuntimeError):
    pass


def deadline_pair(end, cutoff, now):
    if (any(type(x) not in (float, int) or not math.isfinite(x) for x in (end, cutoff, now))
            or end - cutoff != 60 or not now < cutoff < end <= now + 240):
        raise LaunchDenied("INVALID_SHARED_ABSOLUTE_DEADLINE")


def close_except(keep):
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if maximum == resource.RLIM_INFINITY or not 3 <= maximum <= 1048576:
        raise LaunchDenied("UNREVIEWED_DESCRIPTOR_LIMIT")
    start = 3
    for fd in sorted(set(keep)):
        if type(fd) is not int or not 3 <= fd < maximum:
            raise LaunchDenied("INVALID_DESCRIPTOR_HANDOFF")
        os.closerange(start, fd)
        start = fd + 1
    os.closerange(start, maximum)


def empty_group(events, procs):
    """Reject missing/duplicate/ambiguous kernel resource fields."""
    if type(events) is not str or type(procs) is not str:
        raise LaunchDenied("MALFORMED_CGROUP_OBSERVATION")
    values = {}
    for line in events.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in values or fields[1] not in ("0", "1"):
            raise LaunchDenied("AMBIGUOUS_CGROUP_EVENTS")
        values[fields[0]] = fields[1]
    if "populated" not in values:
        raise LaunchDenied("CGROUP_POPULATION_UNOBSERVED")
    if any(not line.isdecimal() or int(line) <= 1 for line in procs.splitlines()):
        raise LaunchDenied("AMBIGUOUS_CGROUP_PROCESS_LIST")
    return values["populated"] == "0" and not procs.strip()


def command_catalog(plan, role):
    if (validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED"
            or role not in ("read-command", "guardian-command")):
        raise LaunchDenied("FIXED_COMMAND_PLAN_REQUIRED")
    allowed = {c.argv for c in plan.inspect} | {SAVE4, SAVE6, VERSION4, VERSION6}
    allowed |= {(binary, "-w", "5", "-L", chain, "-v", "-n", "-x")
                for binary, chain in (("/usr/sbin/iptables", plan.chain4),
                                      ("/usr/sbin/ip6tables", plan.chain6))}
    if role == "guardian-command":
        allowed |= {c.argv for c in (*plan.setup, *plan.teardown,
                                     *emergency_deny_commands(plan), emergency_barrier_command(plan))}
    return frozenset(allowed)


class OwnedCgroup:
    """An already provisioned, nondelegated cgroup; no directory creation.

    The external provisioner must independently review ownership/ancestry,
    quotas and all role groups. This fd is never handed to the controller.
    """
    def __init__(self, fd, identity):
        self.fd, self.identity = fd, identity

    def verify(self, *, empty=False):
        st = os.fstat(self.fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                or (st.st_dev, st.st_ino) != self.identity):
            raise LaunchDenied("CGROUP_DESCRIPTOR_OWNERSHIP_DRIFT")
        # fstatfs layout is ABI-specific; use a sufficiently large aligned buffer.
        buf = (ctypes.c_long * 32)()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.fstatfs(self.fd, ctypes.byref(buf)) != 0 or buf[0] != CGROUP2_SUPER_MAGIC:
            raise LaunchDenied("CGROUP_V2_FILESYSTEM_REQUIRED")
        events, procs = self.readback()
        observed_empty = empty_group(events, procs)
        if empty and not observed_empty:
            raise LaunchDenied("CGROUP_NOT_EMPTY_BEFORE_ATOMIC_SPAWN")
        return True

    def readback(self):
        return read_at(self.fd, "cgroup.events"), read_at(self.fd, "cgroup.procs")

    def kill_all(self):
        if os.geteuid() != 0:
            raise LaunchDenied("TRUSTED_ROOT_CGROUP_OWNER_REQUIRED")
        self.verify()
        fd = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            st = os.fstat(fd)
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise LaunchDenied("UNTRUSTED_CGROUP_KILL_RESOURCE")
            if os.write(fd, b"1") != 1:
                raise LaunchDenied("UNCERTAIN_CGROUP_KILL")
        finally:
            os.close(fd)
        return False  # A write is NEVER independent cleanup evidence.


@dataclass(frozen=True)
class ExecSpec:
    role: str
    executable_fd: int
    argv: tuple[str, ...]
    group: OwnedCgroup
    inherited: tuple[tuple[str, int], ...] = ()

    def validate(self, *, pending_config=None):
        if self.role not in (*ACTORS, "read-command", "guardian-command", "worker", "peer"):
            raise LaunchDenied("UNREVIEWED_PROCESS_ROLE")
        if (not self.argv or type(self.argv) is not tuple
                or any(type(x) is not str or not x or "\x00" in x for x in self.argv)
                or len(self.argv) > 32 or sum(map(len, self.argv)) > 4096):
            raise LaunchDenied("UNBOUNDED_OR_INVALID_ARGV")
        if self.argv[0] not in EXECUTABLES[self.role]:
            raise LaunchDenied("NO_PRIVILEGED_SHELL_SUDO_OR_EXECUTABLE_WIDENING")
        if self.role in (*ACTORS, "peer"):
            if (len(self.argv) < 4 or self.argv[1:3] != ("-I", "-B")
                    or not self.argv[3].startswith("/")
                    or os.path.normpath(self.argv[3]) != self.argv[3]):
                raise LaunchDenied("ISOLATED_REVIEWED_PYTHON_SCRIPT_REQUIRED")
        if (type(self.executable_fd) is not int or self.executable_fd < 3
                or type(self.group.fd) is not int or self.group.fd < 3
                or self.executable_fd == self.group.fd):
            raise LaunchDenied("PRIVILEGED_DESCRIPTOR_OVERLAP")
        check_root_file(self.executable_fd, executable=True)
        if not fcntl.fcntl(self.executable_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise LaunchDenied("EXECUTABLE_FD_MUST_CLOSE_ON_EXEC")
        if fcntl.fcntl(self.executable_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise LaunchDenied("EXECUTABLE_FD_MUST_BE_READONLY")
        seen = {self.executable_fd, self.group.fd}
        for kind, fd in self.inherited:
            if type(fd) is not int or fd < 3 or fd in seen:
                raise LaunchDenied("DUPLICATE_OR_PRIVILEGED_DESCRIPTOR_HANDOFF")
            seen.add(fd)
            st = os.fstat(fd)
            if kind == "ipc" and stat.S_ISSOCK(st.st_mode):
                duplicate = socket.socket(fileno=os.dup(fd))
                try:
                    if (duplicate.family == socket.AF_UNIX
                            and duplicate.type & 0xf == socket.SOCK_STREAM
                            and duplicate.getsockname() == "" and duplicate.getpeername() == ""
                            and duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0):
                        continue
                finally:
                    duplicate.close()
            if kind == "config" and stat.S_ISREG(st.st_mode):
                if (st.st_uid == 0 and not st.st_mode & 0o022
                        and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
                        and (fcntl.fcntl(fd, F_GET_SEALS) & SEALS == SEALS
                             or pending_config is not None and fd == pending_config.reader
                             and not pending_config.completed)):
                    continue
            if kind == "pidfd" and self.role == "controller":
                from probe_a_session import DelegatedProcessBinding
                fields = DelegatedProcessBinding._fdinfo(fd)
                if os.readlink(f"/proc/self/fd/{fd}") == "anon_inode:[pidfd]" and "Pid:" in fields:
                    continue
            raise LaunchDenied("ONLY_PRIVATE_IPC_AND_SEALED_READONLY_CONFIG_MAY_CROSS")
        if self.role not in ACTORS and self.inherited:
            raise LaunchDenied("COMMAND_MUST_NOT_INHERIT_ACTOR_RESOURCES")
        if self.role in ACTORS:
            kinds = tuple(kind for kind, _ in self.inherited)
            if kinds.count("config") != 1 or not 1 <= kinds.count("ipc") <= 3:
                raise LaunchDenied("SEALED_ACTOR_CONFIG_AND_PRIVATE_CHANNELS_REQUIRED")
        return True


class CloneArgs(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "flags", "pidfd", "child_tid", "parent_tid", "exit_signal", "stack",
        "stack_size", "tls", "set_tid", "set_tid_size", "cgroup")]


class LinuxSyscalls:
    """Real Linux primitives, called ONLY behind NativeAtomicSpawner's gate."""
    def clone_into(self, group_fd):
        if os.geteuid() != 0 or os.uname().machine not in ("x86_64", "aarch64"):
            raise LaunchDenied("UNSUPPORTED_PRIVILEGED_CLONE3_ABI")
        pidfd = ctypes.c_int(-1)
        args = CloneArgs(flags=CLONE_PIDFD | CLONE_INTO_CGROUP,
                         pidfd=ctypes.addressof(pidfd), exit_signal=signal.SIGCHLD,
                         cgroup=group_fd)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        result = libc.syscall(ctypes.c_long(435), ctypes.byref(args), ctypes.sizeof(args))
        if result < 0:
            raise LaunchDenied("ATOMIC_CLONE3_FAILED_NO_FORK_FALLBACK")
        return result, pidfd.value

    def prepare_child(self, role, parent_pid):
        os.setsid()
        if role != "guardian":
            # Controller/observer/command actors stop if bootstrap disappears.
            # Guardian stays alive for EOF/deadline cleanup; it cannot survive host loss.
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
                raise LaunchDenied("PARENT_DEATH_PROTECTION_FAILED")
        if role == "controller":
            if drop_controller() is not True or verify_unprivileged() is not True:
                raise LaunchDenied("CONTROLLER_DROP_FAILED")
            # UID changes clear PDEATHSIG on Linux; restore it AFTER the drop.
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
                raise LaunchDenied("POST_DROP_PARENT_DEATH_PROTECTION_FAILED")


class ActorHandle:
    def __init__(self, pid, pidfd, group):
        self.pid, self.pidfd, self.group = pid, pidfd, group
        self.exitcode = None

    def exited(self):
        return self.exitcode is not None or bool(select.select([self.pidfd], [], [], 0)[0])

    def signal(self, value):
        if value not in (signal.SIGTERM, signal.SIGKILL) or self.exitcode is not None:
            raise LaunchDenied("INVALID_PIDFD_SIGNAL")
        signal.pidfd_send_signal(self.pidfd, value)

    def reap(self):
        if self.exitcode is None and self.exited():
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid != self.pid:
                raise LaunchDenied("CHILD_EXIT_NOT_REAPED")
            self.exitcode = os.waitstatus_to_exitcode(status)
        return self.exitcode

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


class NativeAtomicSpawner:
    """Pinned fd exec after kernel-atomic cgroup entry, never post-spawn migration.

    inventory.authorize_exec() must cover role, full argv, immutable binary,
    owned group and complete dependency/config inventory. No default approval.
    All privileged-child exceptions terminate via _exit, never caller Python.
    """
    def __init__(self, *, inventory=None, contract=None, syscalls=None, clock=time.monotonic):
        self.inventory = inventory
        self.contract = contract
        self.syscalls = LinuxSyscalls() if syscalls is None else syscalls
        self.clock = clock

    def spawn(self, spec, *, deadline, activated=False, approval=None, stdout_fd=None, pending=None):
        if (activated is not True or self.inventory is None or os.geteuid() != 0
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not 0 < deadline - self.clock() <= 240):
            raise LaunchDenied("DISABLED_OR_UNAPPROVED_OS_EXECUTION")
        if (len(os.listdir("/proc/self/task")) != 1
                or self.inventory.authorize_exec(spec, approval) is not True):
            raise LaunchDenied("UNREVIEWED_OR_MULTITHREADED_ROOT_BOOTSTRAP")
        from probe_a_execution_contract import ReviewedExecutionContract
        if (not isinstance(self.contract, ReviewedExecutionContract)
                or self.contract.inventory is not self.inventory
                or self.contract.before_spawn(spec, deadline) is not True):
            raise LaunchDenied("REVIEWED_OS_CONFINEMENT_CONTRACT_REQUIRED")
        if pending is not None:
            from probe_a_session import PendingRoleConfiguration
            if not isinstance(pending, PendingRoleConfiguration) or spec.role not in ACTORS:
                raise LaunchDenied("TRUSTED_PENDING_ROLE_CONFIGURATION_REQUIRED")
        spec.validate(pending_config=pending)
        spec.group.verify(empty=True)
        if self.clock() >= deadline:
            raise LaunchDenied("PREFLIGHT_EXHAUSTED_ABSOLUTE_DEADLINE")
        parent_pid = os.getpid()
        gate_read, gate_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            pid, pidfd = self.syscalls.clone_into(spec.group.fd)
        except BaseException:
            for fd in (gate_read, gate_write):
                if fd is not None: os.close(fd)
            raise
        if pid == 0:
            try:
                os.close(gate_write)
                if pending is not None:
                    os.close(pending.writer)  # writer NEVER reaches actor code
                while self.clock() < deadline:
                    if select.select([gate_read], [], [], max(0, deadline-self.clock()))[0]:
                        if os.read(gate_read, 2) != b"S":
                            raise LaunchDenied("UNSEALED_OR_INTERRUPTED_IDENTITY_HANDOFF")
                        break
                else:
                    raise LaunchDenied("IDENTITY_HANDOFF_DEADLINE")
                os.close(gate_read)
                if pending is not None:
                    spec.validate()  # the parent must have completed all seals
                # This is fixed TRUSTED bootstrap code, not a caller callback.
                if self.contract.child_ready_for_exec(spec) is not True:
                    raise LaunchDenied("CHILD_OS_POLICY_REQUIRED")
                self.syscalls.prepare_child(spec.role, parent_pid)
                if self.contract.verify_child_identity(spec) is not True:
                    raise LaunchDenied("UNVERIFIED_CHILD_EFFECTIVE_IDENTITY")
                devnull = os.open("/dev/null", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                null_stat = os.fstat(devnull)
                if (not stat.S_ISCHR(null_stat.st_mode) or null_stat.st_uid != 0
                        or null_stat.st_rdev != os.makedev(1, 3)):
                    raise LaunchDenied("TRUSTED_NULL_DEVICE_REQUIRED")
                os.dup2(devnull, 0)
                os.dup2(devnull if stdout_fd is None else stdout_fd, 1)
                os.dup2(devnull, 2)
                keep = {spec.executable_fd, *(fd for _, fd in spec.inherited)}
                close_except(keep)
                for _, fd in spec.inherited:
                    os.set_inheritable(fd, True)
                # execve(fd) avoids re-opening a mutable executable path.
                os.execve(spec.executable_fd, spec.argv, ENVIRONMENT)
            except BaseException:
                os._exit(77)
            os._exit(77)
        try:
            os.close(gate_read)
            if pid <= 1 or pidfd < 0:
                raise LaunchDenied("UNCERTAIN_ATOMIC_CHILD_CREATION")
            handle = ActorHandle(pid, pidfd, spec.group)
            if pending is not None:
                pending.complete(pid, pidfd)
            elif spec.role in ACTORS:
                raise LaunchDenied("ACTORS_REQUIRE_SEALED_INCARNATION_HANDOFF")
            else:
                self.contract.child_spawned(spec.role, handle)
            if os.write(gate_write, b"S") != 1:
                raise LaunchDenied("CHILD_HANDOFF_SIGNAL_FAILED")
        except BaseException:
            os._exit(76)
        finally:
            os.close(gate_write)
        return handle


class NativeBoundedCapture:
    """Actual bounded pipe capture through clone3, including read-only root tools.

    Specs are prepared by the trusted inventory/provisioner, not an RPC peer.
    All descendants share a pre-exec cgroup; uncertain shutdown raises and
    cannot supply a successful observation. No subprocess/Popen fallback.
    """
    def __init__(self, specs, *, spawner, plan=None, activated=False, approval=None,
                 clock=time.monotonic):
        self.specs = dict(specs)
        if plan is None or validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
            raise LaunchDenied("CAPTURE_REQUIRES_REVIEWED_PLAN")
        from probe_a_workload import CASES_ORDER, exact_argv, peer_argv
        for argv, spec in self.specs.items():
            if spec.role in ("read-command", "guardian-command"):
                allowed = command_catalog(plan, spec.role)
            elif spec.role == "worker":
                allowed = frozenset(exact_argv(plan, case) for case in CASES_ORDER)
            elif spec.role == "peer":
                allowed = frozenset((peer_argv(),))
            else:
                raise LaunchDenied("ACTOR_NOT_COMMAND_CAPTURE")
            if spec.argv != argv or argv not in allowed:
                raise LaunchDenied("CAPTURE_OUTSIDE_EXACT_COMMAND_ALLOWLIST")
        self.spawner, self.activated, self.approval = spawner, activated, approval
        self.clock = clock
        self.busy = False

    def __call__(self, argv, timeout, *, on_spawn=None, on_chunk=None):
        if (self.busy or type(argv) is not tuple or argv not in self.specs
                or type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 8):
            raise LaunchDenied("UNREVIEWED_CAPTURE_OR_REENTRANCY")
        spec = self.specs[argv]
        if spec.argv != argv or spec.role not in ("read-command", "guardian-command", "worker", "peer"):
            raise LaunchDenied("COMMAND_ROLE_MISMATCH")
        if self.activated is not True:
            raise LaunchDenied("OS_CAPTURE_DISABLED")
        if ((on_spawn is not None or on_chunk is not None) and spec.role != "worker"
                or any(cb is not None and not callable(cb) for cb in (on_spawn, on_chunk))):
            raise LaunchDenied("ONLY_REVIEWED_WORKER_OBSERVATION_CALLBACKS")
        self.busy = True
        read = write = None
        child = None
        output = bytearray()
        end = self.clock() + timeout
        clean = False
        try:
            read, write = os.pipe2(os.O_CLOEXEC)
            os.set_blocking(read, False)
            child = self.spawner.spawn(spec, deadline=end, activated=self.activated,
                                       approval=self.approval, stdout_fd=write)
            os.close(write)
            write = None
            if on_spawn is not None:
                on_spawn(child.pid)
            eof = False
            while self.clock() < end:
                readers = [child.pidfd] + ([] if eof else [read])
                ready, _, _ = select.select(readers, [], [], min(0.05, end - self.clock()))
                if read in ready:
                    try:
                        data = os.read(read, 8192)
                    except BlockingIOError:
                        continue
                    if not data:
                        eof = True
                    output.extend(data)
                    if len(output) > 131072:
                        raise LaunchDenied("COMMAND_OUTPUT_OVERFLOW")
                    if data and on_chunk is not None:
                        on_chunk(bytes(output))
                if eof and child.exited():
                    child.reap()
                    events, procs = spec.group.readback()
                    if empty_group(events, procs):
                        if self.spawner.contract is not None:
                            self.spawner.contract.scopes.check(spec.role, empty=True)
                        clean = True
                        return checked_reply(Reply(child.exitcode, output.decode("utf-8", "strict")))
            raise LaunchDenied("COMMAND_DEADLINE_OR_DESCENDANT_NOT_REAPED")
        finally:
            # A failed capture poisons this executor. Its owner must perform
            # independent group readback/reaping; a kill write is not proof.
            try:
                if child is not None and not clean:
                    self.activated = False
                    spec.group.kill_all()
                    if child.exited():
                        child.reap()
            finally:
                if child is not None:
                    if self.spawner.contract is not None:
                        self.spawner.contract.child_finished(spec.role)
                    child.close()
                for fd in (read, write):
                    if fd is not None:
                        os.close(fd)
                self.busy = False


class TrustedActorBootstrap:
    """One-use actor exec orchestration; never accepts a controller callback.

    The independently reviewed provisioner supplies immutable ExecSpecs,
    sealed actor configuration (including the SAME end/cutoff) and private
    channels. Actor-specific entrypoints and readiness/identity handoff remain
    an explicit integration gate; this class does not import those entrypoints.
    Any uncertainty AFTER the first clone attempt terminates the bootstrap.
    The guardian must handle channel EOF/shared deadline even if this parent
    dies. Controller/observer PDEATHSIG is independent of guardian cleanup.
    """
    def __init__(self, specs, *, spawner, end, cutoff, clock=time.monotonic):
        deadline_pair(end, cutoff, clock())
        if (set(specs) != set(ACTORS) or not isinstance(spawner, NativeAtomicSpawner)
                or any(spec.role != role for role, spec in specs.items())
                or len({spec.group.identity for spec in specs.values()}) != 3):
            raise LaunchDenied("DISTINCT_REVIEWED_ACTOR_GROUPS_REQUIRED")
        endpoints = [fd for spec in specs.values() for _, fd in spec.inherited]
        if len(endpoints) != len(set(endpoints)):
            raise LaunchDenied("ACTOR_ENDPOINTS_MUST_NOT_BE_SHARED_OR_DELEGATED")
        self.specs, self.spawner = dict(specs), spawner
        self.end, self.cutoff, self.clock = end, cutoff, clock
        self.used = False

    def launch(self, *, activated=False, approval=None):
        if activated is not True or self.used or os.geteuid() != 0:
            raise LaunchDenied("ACTOR_BOOTSTRAP_DISABLED_OR_CONSUMED")
        self.used = True  # failure consumes the one-use attempt
        actors = {}
        try:
            for spec in self.specs.values():
                spec.validate()
                if self.spawner.inventory is None:
                    raise LaunchDenied("BOOTSTRAP_INVENTORY_REQUIRED")
                self.spawner.inventory.authorize_exec(spec, approval)
                spec.group.verify(empty=True)
            # Start the independent observer and cleanup guardian before the
            # controller executable can run. No Popen or fork fallback exists.
            for role in ("observer", "guardian", "controller"):
                if self.clock() >= self.cutoff:
                    raise LaunchDenied("BOOTSTRAP_EXHAUSTED_WORK_WINDOW")
                actors[role] = self.spawner.spawn(
                    self.specs[role], deadline=self.cutoff,
                    activated=True, approval=approval)
            # The bootstrap owns/consumes the child endpoints/config FDs.
            # Keeping a parent copy would defeat authenticated socket EOF.
            # Its separate observer-audit endpoint is NOT a child endpoint.
            for fd in {fd for spec in self.specs.values() for _, fd in spec.inherited}:
                os.close(fd)
            return IndependentSupervisor(actors, end=self.end, cutoff=self.cutoff,
                                         clock=self.clock)
        except BaseException:
            if os.geteuid() == 0:
                # Every activated root preparation failure is irreversible,
                # including failures before or during uncertain spawning.
                # Parent death closes its FDs; guardian uses EOF/deadline.
                os._exit(76)
            raise

    def launch_integrated(self, *, factory, permit, evidence_audit=None, activated=False, approval=None):
        from probe_a_integrated_bootstrap import IntegratedBootstrap
        if self.used:
            raise LaunchDenied("ACTOR_BOOTSTRAP_ALREADY_CONSUMED")
        if activated is not True:
            raise LaunchDenied("ACTOR_BOOTSTRAP_DISABLED")
        if factory.context.end != self.end or factory.context.cutoff != self.cutoff:
            raise LaunchDenied("BOOTSTRAP_FACTORY_DEADLINE_MISMATCH")
        self.used = True
        return IntegratedBootstrap(spawner=self.spawner, factory=factory,
                                   permit=permit, clock=self.clock).launch(
                                       activated=activated, approval=approval, evidence_audit=evidence_audit)


class IndependentSupervisor:
    """Trusted parent monitors real pidfds against the same work/end deadline.

    Guardian cleanup remains owned by GuardianCore's reviewed journal. A
    guardian timeout/exit cannot be repaired by blind supervisor firewall
    writes. No recovery guarantee after guardian SIGKILL or runner destruction.
    """
    def __init__(self, actors, *, end, cutoff, clock=time.monotonic):
        deadline_pair(end, cutoff, clock())
        if set(actors) != set(ACTORS) or len({x.pid for x in actors.values()}) != 3:
            raise LaunchDenied("INDEPENDENT_ACTORS_REQUIRED")
        self.actors, self.end, self.cutoff, self.clock = dict(actors), end, cutoff, clock

    def _finish(self, result):
        # Observer cannot attest its own disappearance. The bootstrap owns
        # pidfd shutdown/reaping and exact actor-group readback after auditing.
        try:
            observer = self.actors["observer"]
            if not observer.exited():
                observer.signal(signal.SIGKILL)
            while not observer.exited() and self.clock() < self.end:
                select.select([observer.pidfd], [], [], min(0.05, self.end-self.clock()))
            for actor in self.actors.values():
                if not actor.exited() or actor.reap() is None:
                    return "BLOCKED_ACTOR_SHUTDOWN_UNCERTAIN"
                if not empty_group(*actor.group.readback()):
                    return "BLOCKED_ACTOR_CGROUP_CLEANUP_UNVERIFIED"
            coordinator = getattr(self, "coordinator", None)
            if coordinator is not None:
                coordinator.request_cleanup("SUPERVISOR_FINAL_INDEPENDENT_AUDIT")
                if not all(coordinator.independently_stopped(role) for role in ACTORS):
                    return "BLOCKED_INDEPENDENT_ACTOR_CGROUP_CLEANUP"
            evidence = getattr(self, "evidence_audit", None)
            if evidence is not None:
                self.evidence_package = evidence.after_observer_shutdown()
            return result
        except BaseException:
            return "BLOCKED_ACTOR_SHUTDOWN_UNCERTAIN"

    def run(self, *, close_controller_channel, observe_after, cancelled=lambda: False,
            activated=False):
        if activated is not True or os.geteuid() != 0:
            raise LaunchDenied("INDEPENDENT_SUPERVISION_DISABLED")
        try:
            if getattr(self, "evidence_audit", None) is not None:
                observe_after = self.evidence_audit.observe_after
            return self._run(close_controller_channel=close_controller_channel,
                             observe_after=observe_after, cancelled=cancelled, activated=True)
        except BaseException:
            # An interrupted trusted supervisor cannot skip controller shutdown
            # or independently certify cleanup. Guardian owns its same cutoff.
            coordinator = getattr(self, "coordinator", None)
            if coordinator is not None: coordinator.abort("SUPERVISOR_INTERRUPTED")
            try:
                close_controller_channel()
            except BaseException:
                pass
            try:
                controller = self.actors["controller"]
                if not controller.exited(): controller.signal(signal.SIGKILL)
                guardian = self.actors["guardian"]
                while not guardian.exited() and self.clock() < self.end:
                    select.select([guardian.pidfd], [], [], min(0.05, self.end-self.clock()))
            except BaseException:
                pass
            return self._finish("BLOCKED_SUPERVISOR_INTERRUPTED")
        finally:
            for binding in getattr(self, "bindings", {}).values():
                try: binding.close()
                except BaseException: pass

    def _run(self, *, close_controller_channel, observe_after, cancelled=lambda: False,
            activated=False):
        if activated is not True or os.geteuid() != 0:
            raise LaunchDenied("INDEPENDENT_SUPERVISION_DISABLED")
        stopped = False
        reason = "UNVERIFIED_NORMAL_LIFECYCLE"
        while self.clock() < self.end:
            guardian = self.actors["guardian"]
            controller = self.actors["controller"]
            observer = self.actors["observer"]
            if not stopped and (cancelled() or self.clock() >= self.cutoff
                                or controller.exited() or guardian.exited() or observer.exited()):
                stopped = True
                reason = "UNVERIFIED_ABORT_OR_DEADLINE"
                close_controller_channel()  # EOF triggers the existing guardian journal.
                if not controller.exited():
                    controller.signal(signal.SIGKILL)
                # Killing the controller closes the actual socket endpoint.
                # The guardian's own work cutoff initiates cleanup even when
                # the untrusted controller delegated an endpoint to a child.
                # No default SIGTERM is sent to an unverified handler.
            if guardian.exited() and controller.exited():
                guardian.reap()
                controller.reap()
                # Only the independent broker may observe AFTER guardian reaping.
                if (guardian.exitcode != 0 or observer.exited()
                        or observe_after() is not True):
                    return self._finish("BLOCKED_INDEPENDENT_POST_GUARDIAN_OBSERVATION")
                return self._finish(reason + "_NOT_PROBE_PASS")
            select.select([h.pidfd for h in self.actors.values() if not h.exited()],
                          [], [], min(0.05, max(0, self.end - self.clock())))
        return self._finish("BLOCKED_GUARDIAN_OR_DESCENDANT_CLEANUP_UNCERTAIN")
