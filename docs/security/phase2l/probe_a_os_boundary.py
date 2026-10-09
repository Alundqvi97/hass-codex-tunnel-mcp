"""Inert, allowlisted host I/O boundary for a future approved Probe A.

No entry point, workflow or process at import. The reviewed supervisor and
post-termination watchdog are still MISSING.
"""
from __future__ import annotations
import subprocess
import time
from probe_a_stream import capture, StreamFailure
from probe_contract import validate_plan
from probe_a_exec_adapter import Reply, checked_reply, RUN_LIMIT_SECONDS

class HostBlocked(RuntimeError):
    pass

MAX_OUTPUT=131072
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
        self.allowed |= frozenset(x.argv for x in (*plan.setup,*plan.teardown))
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

def bounded_process(argv,timeout,*,reviewed_plan):
    """Effectful only if called explicitly after separate approval.

    No shell. Does not guarantee clean-up after SIGKILL or runner cancellation,
    so a separate fail-safe supervisor remains mandatory.
    """
    # Defense in depth: the low-level helper must not become a bypass of
    # the exact-argv contract simply because its caller is miswired.
    if validate_plan(reviewed_plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        raise HostBlocked("INVALID_REVIEWED_PLAN")
    allowed=frozenset(x.argv for x in (*reviewed_plan.inspect,*reviewed_plan.setup,*reviewed_plan.teardown))
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
    privileged=argv[0].startswith("/usr/sbin/")
    cmd=("/usr/bin/sudo","-n",*argv) if privileged else argv
    try:
        # Streamed hard cap is enforced while the child runs; no unbounded
        # subprocess.run(..., PIPE) buffering and no stderr exposure.
        return capture(cmd, timeout)
    except BaseException:
        raise HostBlocked("STREAMED_COMMAND_FAILED") from None
