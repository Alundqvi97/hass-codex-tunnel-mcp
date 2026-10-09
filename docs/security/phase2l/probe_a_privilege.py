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
PR_CAPBSET_READ = 23
PR_CAPBSET_DROP = 24
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
MAX_REVIEWED_CAPABILITY = 63


def verify_unprivileged(uid=CONTROLLER_UID, gid=CONTROLLER_GID, *, read_text=None):
    """Verify all real/effective/saved/fs IDs and five Linux capability sets."""
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


class NativeCapabilityOps:
    """Linux-only primitives. Nothing effectful until explicitly called.

    PR_CAPBSET_DROP requires CAP_SETPCAP and must precede setresuid();
    cap_set_proc(empty) follows UID/GID changes to clear any residual
    inheritable/permitted/effective sets. All errors fail closed.
    See capabilities(7), PR_CAPBSET_DROP(2const), and libcap(3).
    """
    def _prctl(self, operation, argument=0, extra=0):
        libc=ctypes.CDLL(None, use_errno=True)
        fn=libc.prctl
        fn.restype=ctypes.c_int
        fn.argtypes=(ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,
                     ctypes.c_ulong,ctypes.c_ulong)
        result=fn(operation,argument,extra,0,0)
        if result < 0:
            raise PrivilegeDenied("LINUX_CAPABILITY_PRCTL_FAILED")
        return result

    def thread_count(self):
        return len(tuple(Path("/proc/self/task").iterdir()))

    def last_capability(self):
        try:
            text=Path("/proc/sys/kernel/cap_last_cap").read_text(encoding="ascii").strip()
            if not text.isascii() or not text.isdecimal() or len(text)>3:
                raise ValueError("invalid cap range")
            number=int(text)
        except (OSError,ValueError):
            raise PrivilegeDenied("UNTRUSTED_CAPABILITY_RANGE") from None
        if not 0 <= number <= MAX_REVIEWED_CAPABILITY:
            raise PrivilegeDenied("UNREVIEWED_CAPABILITY_RANGE")
        return number

    def no_new_privs(self):
        return self._prctl(PR_SET_NO_NEW_PRIVS,1)==0

    def clear_ambient(self):
        return self._prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL)==0

    def bounding_member(self, capability):
        result=self._prctl(PR_CAPBSET_READ,capability)
        if result not in (0,1):
            raise PrivilegeDenied("BAD_CAPABILITY_BOUNDING_READ")
        return result==1

    def drop_bounding(self, capability):
        return self._prctl(PR_CAPBSET_DROP,capability)==0

    def clear_process_sets(self):
        """libcap's empty cap_t clears inheritable, permitted and effective."""
        try:
            libcap=ctypes.CDLL("libcap.so.2",use_errno=True)
            libcap.cap_init.argtypes=()
            libcap.cap_init.restype=ctypes.c_void_p
            libcap.cap_set_proc.argtypes=(ctypes.c_void_p,)
            libcap.cap_set_proc.restype=ctypes.c_int
            libcap.cap_free.argtypes=(ctypes.c_void_p,)
            libcap.cap_free.restype=ctypes.c_int
            empty=libcap.cap_init()
            if not empty:
                raise PrivilegeDenied("LIBCAP_INIT_FAILED")
            try:
                ok=libcap.cap_set_proc(empty)==0
            finally:
                freed=libcap.cap_free(empty)==0
            if not ok or not freed:
                raise PrivilegeDenied("LIBCAP_CLEAR_FAILED")
        except (OSError,AttributeError):
            raise PrivilegeDenied("LIBCAP_UNAVAILABLE") from None
        return True


def drop_controller(*, uid=CONTROLLER_UID, gid=CONTROLLER_GID,
                    getuid=os.geteuid, setgroups=os.setgroups,
                    setgid=os.setresgid, setuid=os.setresuid,
                    capability_ops=None, verify=verify_unprivileged):
    """Fail closed across every step; no syscall is run at import.

    Linux capabilities are thread-scoped, so a multi-threaded privileged
    Python bootstrap is refused rather than dropping just one thread's sets.
    The runner independently invokes verify_unprivileged again before IPC.
    """
    if (type(uid) is not int or type(gid) is not int or
            (uid,gid)!=(CONTROLLER_UID,CONTROLLER_GID) or getuid()!=0):
        raise PrivilegeDenied("UNREVIEWED_CONTROLLER_IDENTITY")
    ops=NativeCapabilityOps() if capability_ops is None else capability_ops
    required=("thread_count","last_capability","no_new_privs","clear_ambient",
              "bounding_member","drop_bounding","clear_process_sets")
    if not all(callable(getattr(ops,k,None)) for k in required):
        raise PrivilegeDenied("UNREVIEWED_CAPABILITY_BACKEND")
    try:
        if ops.thread_count()!=1:
            raise PrivilegeDenied("MULTITHREADED_PRIVILEGED_BOOTSTRAP")
        capmax=ops.last_capability()
        if type(capmax) is not int or not 0 <= capmax <= MAX_REVIEWED_CAPABILITY:
            raise PrivilegeDenied("UNREVIEWED_CAPABILITY_RANGE")
        if ops.no_new_privs() is not True:
            raise PrivilegeDenied("NO_NEW_PRIVS_FAILED")
        if ops.clear_ambient() is not True:
            raise PrivilegeDenied("AMBIENT_CLEAR_FAILED")
        # Drop every present bounding capability while CAP_SETPCAP is
        # available. Never silently skip a failed or unreadable capability.
        for cap in range(capmax+1):
            present=ops.bounding_member(cap)
            if type(present) is not bool:
                raise PrivilegeDenied("UNTRUSTED_BOUNDING_READ")
            if present and ops.drop_bounding(cap) is not True:
                raise PrivilegeDenied("BOUNDING_DROP_FAILED")
        setgroups([])
        setgid(gid,gid,gid)
        setuid(uid,uid,uid)
        if ops.clear_process_sets() is not True:
            raise PrivilegeDenied("INHERITABLE_PERMITTED_EFFECTIVE_NOT_CLEARED")
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
