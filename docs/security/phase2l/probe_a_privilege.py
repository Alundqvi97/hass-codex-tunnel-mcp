"""Inert OS privilege-drop and explicitly read-only post-observer contracts.

Only an out-of-band approved root bootstrap may call drop_controller().
A mock cannot attest OS enforcement; real execution is unactivated.
"""
from __future__ import annotations
import ctypes
import os
from pathlib import Path

class PrivilegeDenied(RuntimeError):
    pass

CONTROLLER_UID = 65534
CONTROLLER_GID = 65534
PR_SET_NO_NEW_PRIVS = 38

def verify_unprivileged(uid=CONTROLLER_UID, gid=CONTROLLER_GID, *, read_text=None):
    reader=read_text or (lambda p: Path(p).read_text(encoding="ascii"))
    try:
        values=dict(line.split(":",1) for line in reader("/proc/self/status").splitlines() if ":" in line)
        ids=tuple(int(x) for x in values["Uid"].split())
        gids=tuple(int(x) for x in values["Gid"].split())
        groups=values["Groups"].split()
        caps=tuple(int(values[k].strip(),16) for k in ("CapInh","CapPrm","CapEff","CapBnd","CapAmb"))
        nonew=values["NoNewPrivs"].strip()
    except (OSError, KeyError, ValueError):
        raise PrivilegeDenied("CONTROLLER_PROVENANCE_UNREADABLE") from None
    if ids!=(uid,)*4 or gids!=(gid,)*4 or groups or any(caps) or nonew!="1":
        raise PrivilegeDenied("CONTROLLER_STILL_PRIVILEGED")
    return True

def drop_controller(*, uid=CONTROLLER_UID, gid=CONTROLLER_GID,
                    getuid=os.geteuid, setgroups=os.setgroups,
                    setgid=os.setresgid, setuid=os.setresuid,
                    prctl=None, verify=verify_unprivileged):
    if (type(uid) is not int or type(gid) is not int or
            (uid,gid)!=(CONTROLLER_UID,CONTROLLER_GID) or getuid()!=0):
        raise PrivilegeDenied("UNREVIEWED_CONTROLLER_IDENTITY")
    if prctl is None:
        libc=ctypes.CDLL(None, use_errno=True)
        prctl=lambda: libc.prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)
    try:
        # NoNewPrivs first, then remove every inherited supplementary group,
        # real/effective/saved group and UID; never keep a saved root UID.
        if prctl()!=0:
            raise PrivilegeDenied("NO_NEW_PRIVS_FAILED")
        setgroups([])
        setgid(gid,gid,gid)
        setuid(uid,uid,uid)
        if verify(uid,gid) is not True:
            raise PrivilegeDenied("CONTROLLER_NOT_ATTESTED")
    except BaseException:
        raise PrivilegeDenied("OS_PRIVILEGE_DROP_FAILED") from None
    return True

class ReadOnlyPostObserver:
    """Injected independently reviewed reader: explicit read-only commands.

    This is a *gate*, not the currently absent root-owned readback broker.
    No backend is supplied by default; a future launcher must have its own
    review and must never expose a writable root capability to the controller.
    """
    def __init__(self, plan, *, read, check=verify_unprivileged):
        if not callable(read) or not callable(check):
            raise PrivilegeDenied("MISSING_INDEPENDENT_READONLY_BROKER")
        from probe_a_os_boundary import SAVE4,SAVE6,VERSION4,VERSION6
        self.allow=frozenset(x.argv for x in plan.inspect) | {SAVE4,SAVE6,VERSION4,VERSION6}
        self.allow |= frozenset((
            ("/usr/sbin/iptables","-w","5","-L",plan.chain4,"-v","-n","-x"),
            ("/usr/sbin/ip6tables","-w","5","-L",plan.chain6,"-v","-n","-x")))
        self.read=read
        self.check=check
    def __call__(self,argv,deadline):
        if not isinstance(argv,tuple) or argv not in self.allow:
            raise PrivilegeDenied("OBSERVER_WRITE_OR_UNKNOWN_COMMAND")
        if self.check() is not True:
            raise PrivilegeDenied("CONTROLLER_PRIVILEGE_UNVERIFIED")
        return self.read(argv,deadline)
