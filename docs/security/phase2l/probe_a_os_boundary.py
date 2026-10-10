"""Inert, allowlisted host I/O boundary for a future approved Probe A.

No entry point, workflow or process at import. The reviewed supervisor and
post-termination watchdog are still MISSING.
"""
from __future__ import annotations
import subprocess
import time
import os
import re
import stat
from pathlib import Path
from probe_a_stream import capture, StreamFailure
from probe_contract import validate_plan, emergency_deny_commands, emergency_barrier_command
from probe_a_exec_adapter import Reply, checked_reply, RUN_LIMIT_SECONDS

class HostBlocked(RuntimeError):
    pass

MAX_OUTPUT=131072
NSSWITCH="/etc/nsswitch.conf"
MAX_NSS_BYTES=65536


def require_local_passwd_nss(*, read_text=None, lstat=None):
    """Reject NSS sources that might perform out-of-scope network lookups.

    getent passwd UID is approved only when the sole passwd service is
    files. Runtime review must additionally pin NSS configuration, libc,
    libnss_files and the loader. This is a source preflight, not proof of
    immutable OS configuration or absence of NSS implementation flaws.
    """
    reader=read_text or (lambda p: Path(p).read_text(encoding="ascii"))
    stat_file=lstat or os.lstat
    try:
        st=stat_file(NSSWITCH)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or
                st.st_mode & 0o022):
            raise HostBlocked("UNTRUSTED_NSS_OWNERSHIP")
        config=reader(NSSWITCH)
        if (type(config) is not str or not config.isascii() or
                "\x00" in config or len(config.encode("ascii"))>MAX_NSS_BYTES):
            raise HostBlocked("UNTRUSTED_NSS_FORMAT")
    except (OSError, UnicodeError, ValueError):
        raise HostBlocked("UNREADABLE_NSS_POLICY") from None
    services=[]
    for raw in config.splitlines():
        body=raw.split("#",1)[0].strip()
        if re.match(r"^passwd\s*:",body):
            if not re.fullmatch(r"passwd\s*:\s*files\s*",body):
                raise HostBlocked("NSS_EXTERNAL_PASSWD_SERVICE")
            services.append(body)
    if len(services)!=1:
        raise HostBlocked("NSS_PASSWD_POLICY_AMBIGUOUS")
    return True


SAVE4=("/usr/sbin/iptables-save","-t","filter")
SAVE6=("/usr/sbin/ip6tables-save","-t","filter")
VERSION4=("/usr/sbin/iptables","-V")
VERSION6=("/usr/sbin/ip6tables","-V")

class RestrictedHost:
    """Only commands in the exact reviewed plan and readback inventory."""
    def __init__(self,plan,*,call,clock=time.monotonic):
        if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
            raise HostBlocked("INVALID_PLAN")
        if not callable(call) or not callable(clock):
            raise HostBlocked("MISSING_BACKEND")
        self.plan=plan
        self.call=call
        self.clock=clock
        self.allowed=frozenset(x.argv for x in plan.inspect) | {SAVE4,SAVE6,VERSION4,VERSION6}
        self.allowed |= frozenset(x.argv for x in (*plan.setup,*plan.teardown,*emergency_deny_commands(plan),emergency_barrier_command(plan)))
        self.allowed |= frozenset((
            (b,"-w","5","-L",chain,"-v","-n","-x")
            for b,chain in (("/usr/sbin/iptables",plan.chain4),("/usr/sbin/ip6tables",plan.chain6))
        ))
    def execute(self,argv,*,deadline):
        if not isinstance(argv,tuple) or argv not in self.allowed:
            raise HostBlocked("UNAPPROVED_COMMAND")
        remaining=deadline-self.clock()
        if remaining<=0: raise HostBlocked("DEADLINE_EXPIRED")
        try:
            return checked_reply(self.call(argv,min(float(RUN_LIMIT_SECONDS),float(remaining))))
        except BaseException:
            raise HostBlocked("FAILED_WITHOUT_RAW_LOGS") from None

def bounded_process(argv,timeout,*,reviewed_plan,privileged_capture=None):
    """Effectful only if called explicitly after separate approval.

    No shell. Does not guarantee clean-up after SIGKILL or runner cancellation,
    so a separate fail-safe supervisor remains mandatory.
    """
    # Defense in depth: the low-level helper must not become a bypass of
    # the exact-argv contract simply because its caller is miswired.
    if validate_plan(reviewed_plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise HostBlocked("INVALID_REVIEWED_PLAN")
    allowed=frozenset(x.argv for x in (*reviewed_plan.inspect,*reviewed_plan.setup,*reviewed_plan.teardown,*emergency_deny_commands(reviewed_plan),emergency_barrier_command(reviewed_plan)))
    allowed|={SAVE4,SAVE6,VERSION4,VERSION6}
    allowed|=frozenset((
        (b,"-w","5","-L",chain,"-v","-n","-x")
        for b,chain in (("/usr/sbin/iptables",reviewed_plan.chain4),("/usr/sbin/ip6tables",reviewed_plan.chain6))
    ))
    if not isinstance(argv,tuple) or argv not in allowed:
        raise HostBlocked("LOW_LEVEL_COMMAND_NOT_REVIEWED")
    if not isinstance(argv,tuple) or not argv or argv[0] not in (
        "/usr/sbin/iptables","/usr/sbin/ip6tables",
        "/usr/sbin/iptables-save","/usr/sbin/ip6tables-save",
        "/usr/bin/getent","/usr/bin/pgrep",
    ): raise HostBlocked("BINARY_NOT_ALLOWED")
    if type(timeout) not in (int,float) or not 0<timeout<=RUN_LIMIT_SECONDS:
        raise HostBlocked("INVALID_DEADLINE")
    # This host boundary is guardian-root-only. An unprivileged read-only
    # observer has its own separately authorized and audited OS broker.
    # Executable directories do NOT determine process authority.
    if os.geteuid()!=0:
        raise HostBlocked("GUARDIAN_ROOT_IDENTITY_REQUIRED")
    if not callable(privileged_capture):
        raise HostBlocked("PRIVILEGED_COMMAND_CONTAINMENT_NOT_APPROVED")
    if argv[0]=="/usr/bin/getent":
        require_local_passwd_nss()
    try:
        # ALL root-executed tools, including pgrep and getent, must enter the
        # reviewed atomic process-tree containment backend. No direct Popen
        # fallback or path-based exception is permitted.
        return checked_reply(privileged_capture(argv, timeout))
    except BaseException:
        raise HostBlocked("CONTAINED_COMMAND_FAILED") from None
