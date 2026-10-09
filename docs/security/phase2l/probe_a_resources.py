"""Independent /proc and resource observations for Probe A.

Only read-only procfs and resolver reads. No commands, no sockets, no
automatic use. Caller must additionally observe kernel filter snapshots.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


class ResourceDenied(RuntimeError):
    pass


def numeric_identity(pid, uid, *, read_text=None):
    if type(pid) is not int or pid <= 1 or type(uid) is not int or not 42000 <= uid <= 59999:
        raise ResourceDenied("INVALID_PID_OR_UID")
    reader = read_text or (lambda path: Path(path).read_text(encoding="ascii"))
    try:
        info = reader("/proc/" + str(pid) + "/status")
        values = {}
        for line in info.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                values[key] = value.strip()
        four_uid = [int(x) for x in values["Uid"].split()]
        four_gid = [int(x) for x in values["Gid"].split()]
        groups = values["Groups"].split()
        caps = [int(values[k], 16) for k in ("CapEff", "CapBnd", "CapAmb")]
    except (OSError, KeyError, ValueError):
        raise ResourceDenied("UNREADABLE_PROCESS_IDENTITY") from None
    if (four_uid != [uid]*4 or four_gid != [uid]*4 or
            groups or any(caps)):
        raise ResourceDenied("WRONG_UID_GROUP_OR_CAPS")
    return True


def _listeners(port, *, read_text=None):
    reader = read_text or (lambda path: Path(path).read_text(encoding="ascii"))
    found = []
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = reader(table).splitlines()[1:]
        except OSError:
            raise ResourceDenied("LISTENER_INVENTORY_MISSING") from None
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                raise ResourceDenied("BAD_KERNEL_SOCKET_ROW")
            try:
                local, state, inode = fields[1], fields[3], fields[9]
                encoded_addr, encoded_port = local.split(":")
                if int(encoded_port,16) != port or state != "0A":
                    continue
                found.append((table, encoded_addr, int(inode)))
            except (ValueError, IndexError):
                raise ResourceDenied("BAD_KERNEL_SOCKET_ROW") from None
    return tuple(found)


def attest_listener(pid, *, port=19468, read_text=None, list_fds=os.listdir,
                    read_link=os.readlink):
    if type(pid) is not int or pid <= 1 or port != 19468:
        raise ResourceDenied("UNREVIEWED_LISTENER")
    matches = _listeners(port, read_text=read_text)
    if len(matches) != 1 or matches[0][:2] != ("/proc/net/tcp", "0100007F"):
        raise ResourceDenied("LISTENER_NOT_EXACTLY_LOOPBACK")
    inode = matches[0][2]
    try:
        links = [read_link("/proc/" + str(pid) + "/fd/" + fd)
                 for fd in list_fds("/proc/" + str(pid) + "/fd")]
    except OSError:
        raise ResourceDenied("UNREADABLE_FD_OWNERSHIP") from None
    if "socket:[" + str(inode) + "]" not in links:
        raise ResourceDenied("LISTENER_NOT_OWNED_BY_WORKER")
    return True


class LocalResourceReadback:
    """All baseline data is captured before any firewall write."""
    def __init__(self, scope, *, read_bytes=None, lstat=None, read_link=None,
                 lexists=None, read_text=None):
        if not isinstance(scope,str) or len(scope)!=8 or not all(x in "0123456789ABCDEF" for x in scope):
            raise ResourceDenied("INVALID_SCOPE")
        self.scratch = "/tmp/p2a-" + scope
        self.read_bytes = read_bytes or (lambda p: Path(p).read_bytes())
        self.lstat = lstat or os.lstat
        self.read_link = read_link or os.readlink
        self.lexists = lexists or os.path.lexists
        self.read_text = read_text
        self.baseline = None

    def _resolver(self):
        try:
            path = "/etc/resolv.conf"
            s = self.lstat(path)
            link = self.read_link(path) if stat.S_ISLNK(s.st_mode) else None
            content = self.read_bytes(path)
            if len(content)>65536:
                raise ResourceDenied("RESOLVER_OVERSIZE")
            return (s.st_dev, s.st_ino, s.st_mode, link, hashlib.sha256(content).hexdigest())
        except (OSError, ValueError):
            raise ResourceDenied("RESOLVER_UNREADABLE") from None

    def preflight(self):
        if self.baseline is not None or self.lexists(self.scratch) or _listeners(19468,read_text=self.read_text):
            raise ResourceDenied("PREEXISTING_RESOURCE")
        self.baseline = self._resolver()
        return True

    def readback(self,key,deadline):
        try:
            if key == "test_listeners_absent":
                return not _listeners(19468,read_text=self.read_text)
            if key == "temporary_files_absent":
                return not self.lexists(self.scratch)
            if key == "resolver_unchanged":
                return self.baseline is not None and self._resolver() == self.baseline
            # A running guardian cannot declare its own absence.
            if key == "watchdog_absent":
                return False
        except BaseException:
            return False
        return False
