"""Linux process/descriptor provenance for the disabled OS integration.

No privilege changes, process launch or host reads at import. A pidfd and an
open proc directory bind observations to one process incarnation. These
observations are inputs to a future acceptance review, never a Probe A PASS.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import select
import socket
import stat
import struct

CAP_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
MAX_PROC = 65536


class IdentityDenied(RuntimeError):
    pass


def read_fd(fd, maximum=MAX_PROC):
    chunks = bytearray()
    while len(chunks) <= maximum:
        block = os.read(fd, min(8192, maximum + 1 - len(chunks)))
        if not block:
            return bytes(chunks)
        chunks.extend(block)
    raise IdentityDenied("UNBOUNDED_KERNEL_RESOURCE")


def _read_fixed(directory_fd, name, allowed, maximum):
    if name not in allowed:
        raise IdentityDenied("RESOURCE_NOT_ALLOWLISTED")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=directory_fd)
    try:
        before=os.fstat(fd)
        text=read_fd(fd,maximum).decode('ascii')
        after=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
        if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):
            raise IdentityDenied('KERNEL_RESOURCE_PATH_SUBSTITUTION')
        return text
    except UnicodeError:raise IdentityDenied('MALFORMED_KERNEL_RESOURCE') from None
    finally:
        os.close(fd)


def read_at(directory_fd, name, maximum=MAX_PROC):
    """Fixed process/cgroup text; no paths, symlinks or caller-selected files."""
    return _read_fixed(directory_fd,name,
        ("stat","status","cgroup","cgroup.events","cgroup.procs",
         "cgroup.type","cgroup.subtree_control"),maximum)


def read_process_attribute(binding, name="current", maximum=4096):
    if name != "current" or not 0 < maximum <= 4096:
        raise IdentityDenied("RESOURCE_NOT_ALLOWLISTED")
    if binding.verify() is not True:
        raise IdentityDenied("PROCESS_IDENTITY_DRIFT")
    fd = os.open("attr",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                 dir_fd=binding.procfd)
    try:
        before=os.fstat(fd)
        text=_read_fixed(fd,name,("current",),maximum)
        after=os.stat("attr",dir_fd=binding.procfd,follow_symlinks=False)
        if ((before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino)
                or binding.verify() is not True):
            raise IdentityDenied("PROCESS_ATTRIBUTE_PATH_OR_INCARNATION_DRIFT")
        return text
    finally:os.close(fd)


def read_network_table(directory_fd, name):
    return _read_fixed(directory_fd,name,("tcp","tcp6"),131072)


def observe_numeric_uids(proc_root, name):
    """Narrow enumeration identity, including PID1 and kernel threads.

    No executable observation is needed for an unrelated UID. Do not weaken
    actor ProcessBinding. Missing, exiting, inaccessible or substituted entries
    remain uncertain; never skip them to claim numeric UID absence.
    """
    if type(name) is not str or not name.isascii() or not name.isdecimal() or str(int(name))!=name or int(name)<1:
        raise IdentityDenied('INVALID_ENUMERATION_PID')
    pid=int(name);pidfd=procfd=None
    def snapshot():
        raw=read_at(procfd,'stat');status=read_at(procfd,'status')
        try:
            left,separator,rest=raw.rpartition(') ')
            start=int(rest.split()[19])
            if not separator or int(left.split(' (',1)[0])!=pid or start<=0:raise ValueError()
            values={}
            for line in status.splitlines():
                key,sep,value=line.partition(':')
                if sep:
                    if key in values:raise ValueError()
                    values[key]=value.split()
            uids=values['Uid']
            if len(uids)!=4 or any(not n.isascii() or not n.isdecimal() for n in uids):raise ValueError()
            return start,tuple(int(n) for n in uids)
        except (ValueError,KeyError,IndexError):raise IdentityDenied('MALFORMED_ENUMERATION_IDENTITY') from None
    try:
        pidfd=os.pidfd_open(pid,0)
        procfd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=proc_root)
        before=os.fstat(procfd);first=snapshot();second=snapshot()
        current=os.stat(name,dir_fd=proc_root,follow_symlinks=False)
        if (first!=second or (before.st_dev,before.st_ino)!=(current.st_dev,current.st_ino)
                or select.select([pidfd],[],[],0)[0]):
            raise IdentityDenied('ENUMERATION_INCARNATION_OR_UID_CHANGED')
        return pid,first[0],first[1]
    finally:
        if procfd is not None:os.close(procfd)
        if pidfd is not None:os.close(pidfd)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    starttime: int
    uids: tuple[int, ...]
    gids: tuple[int, ...]
    groups: tuple[int, ...]
    capabilities: tuple[int, ...]
    no_new_privs: int
    executable: tuple[int, int]

    def credentials(self):
        return self.pid, self.uids[1], self.gids[1]

    def require_controller(self):
        if (self.uids != (65534,) * 4 or self.gids != (65534,) * 4
                or self.groups or any(self.capabilities) or self.no_new_privs != 1):
            raise IdentityDenied("CONTROLLER_NOT_IRREVERSIBLY_UNPRIVILEGED")
        return self


def parse_identity(pid, proc_stat, status, executable):
    try:
        # comm may contain spaces and parentheses; field 22 is starttime.
        left, _, rest = proc_stat.rpartition(") ")
        if int(left.split(" (", 1)[0]) != pid:
            raise ValueError()
        fields = rest.split()
        starttime = int(fields[19])
        values = {}
        for line in status.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                if key in values:
                    raise ValueError()
                values[key] = value.strip()
        uids = tuple(int(x) for x in values["Uid"].split())
        gids = tuple(int(x) for x in values["Gid"].split())
        groups = tuple(int(x) for x in values["Groups"].split())
        caps = tuple(int(values[key], 16) for key in CAP_FIELDS)
        nnp = int(values["NoNewPrivs"])
        if (type(pid) is not int or pid <= 1 or starttime <= 0
                or len(uids) != 4 or len(gids) != 4 or nnp not in (0, 1)
                or any(x < 0 for x in (*uids, *gids, *groups, *caps))):
            raise ValueError()
    except (ValueError, KeyError, IndexError):
        raise IdentityDenied("MALFORMED_PROCESS_IDENTITY") from None
    return ProcessIdentity(pid, starttime, uids, gids, groups, caps, nnp, executable)


class ProcessBinding:
    """Owned pidfd/procfd; freshness checks never follow a reused numeric PID."""
    def __init__(self, pid):
        if type(pid) is not int or pid <= 1:
            raise IdentityDenied("INVALID_PROCESS_ID")
        self.pid = pid
        self.pidfd = self.procfd = None
        try:
            self.pidfd = os.pidfd_open(pid, 0)
            self.procfd = os.open(f"/proc/{pid}",
                                  os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.identity = self.snapshot()
        except BaseException:
            self.close()
            raise

    def alive(self):
        if self.pidfd is None:
            return False
        return not select.select([self.pidfd], [], [], 0)[0]

    def snapshot(self):
        if not self.alive() or self.procfd is None:
            raise IdentityDenied("PROCESS_EXITED_OR_UNBOUND")
        first = read_at(self.procfd, "stat")
        status = read_at(self.procfd, "status")
        exe = os.stat("exe", dir_fd=self.procfd)
        last = read_at(self.procfd, "stat")
        value = parse_identity(self.pid, first, status, (exe.st_dev, exe.st_ino))
        if (parse_identity(self.pid, last, status, value.executable).starttime != value.starttime
                or not self.alive()):
            raise IdentityDenied("PROCESS_CHANGED_DURING_OBSERVATION")
        return value

    def verify(self):
        if self.snapshot() != self.identity:
            raise IdentityDenied("PROCESS_IDENTITY_DRIFT")
        return True

    def close(self):
        for name in ("procfd", "pidfd"):
            fd = getattr(self, name, None)
            setattr(self, name, None)
            if fd is not None:
                os.close(fd)


class CredentialSocket:
    """SCM_CREDENTIALS on every stream chunk, preserving BoundedSocketIPC.

    SO_PEERCRED alone on a pre-fork socketpair identifies its creator, not the
    post-drop controller. Per-message credentials plus fresh pidfd/procfs
    binding reject descriptor delegation to a different process. SCM_RIGHTS
    is never accepted; received descriptors are closed before refusal.
    """
    def __init__(self, stream, peer):
        if stream.family != socket.AF_UNIX or stream.type & 0xf != socket.SOCK_STREAM:
            raise IdentityDenied("PRIVATE_UNIX_STREAM_REQUIRED")
        self.stream, self.peer = stream, peer
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

    def fileno(self):
        return self.stream.fileno()

    def setblocking(self, value):
        self.stream.setblocking(value)

    def send(self, data):
        self.peer.verify()
        return self.stream.send(data)

    def recv(self, count):
        self.peer.verify()
        data, ancillary, flags, _ = self.stream.recvmsg(
            count, socket.CMSG_SPACE(12) + socket.CMSG_SPACE(32), socket.MSG_CMSG_CLOEXEC)
        credentials = []
        unexpected = False
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                for offset in range(0, len(payload) - 3, 4):
                    os.close(struct.unpack_from("i", payload, offset)[0])
                unexpected = True
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(payload) == 12:
                credentials.append(struct.unpack("3i", payload))
            else:
                unexpected = True
        if not data:
            raise EOFError("AUTHENTICATED_PEER_CLOSED")
        if (unexpected or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
                or credentials != [self.peer.identity.credentials()]):
            self.close()
            raise IdentityDenied("UNTRUSTED_MESSAGE_CREDENTIALS_OR_DESCRIPTORS")
        self.peer.verify()
        return data

    def close(self):
        self.stream.close()


def check_root_file(fd, *, executable=False):
    value = os.fstat(fd)
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0
            or value.st_mode & 0o022 or (executable and not value.st_mode & 0o111)):
        raise IdentityDenied("EXECUTABLE_OR_CONFIG_NOT_ROOT_CONTROLLED")
    return value.st_dev, value.st_ino
