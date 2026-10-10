"""Allowlisted command gate for *future* Probe A runtime integration.

No entry point and no default system backend. All executions go through an
explicitly injected callable. An approved GitHub-only supervisor/watcher is
still missing. The code cannot launch anything by import or by CI.
"""
from __future__ import annotations
from dataclasses import dataclass
from probe_contract import validate_plan, Command

MAX_TEXT_BYTES=131072
RUN_LIMIT_SECONDS=8

class UnsafeCommand(ValueError):
    pass

@dataclass(frozen=True)
class Reply:
    code: int
    stdout: str

def checked_reply(reply) -> Reply:
    if not isinstance(reply,Reply) or type(reply.code) is not int or not isinstance(reply.stdout,str):
        raise UnsafeCommand("BAD_BACKEND_RESPONSE")
    if len(reply.stdout.encode("utf-8"))>MAX_TEXT_BYTES or "\x00" in reply.stdout:
        raise UnsafeCommand("OVERSIZED_OR_UNSAFE_OUTPUT")
    if reply.code not in (0,1,2,3,4):
        raise UnsafeCommand("UNEXPECTED_EXIT_CODE")
    return reply

class ExactArgvGate:
    """No command synthesis and no unapproved write; adapter is not live.

    A future privileged supervisor must wrap checked commands with sudo -n,
    use the standard library's bounded process runner with shell disabled,
    stderr=DEVNULL, timeout <=RUN_LIMIT_SECONDS), verify actual binary
    versions and identity, and independently check the resulting kernel.
    """
    def __init__(self,plan,*,invoke):
        if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
            raise UnsafeCommand("INVALID_CONTRACT")
        if not callable(invoke):
            raise UnsafeCommand("NO_INJECTED_EXECUTOR")
        self.plan=plan
        self._invoke=invoke
        self._setup_at=0
        self._teardown_at=0
        self._read_only=frozenset(plan.inspect)
    def preflight_read(self,command,*,timeout=RUN_LIMIT_SECONDS):
        if command not in self._read_only:
            raise UnsafeCommand("UNREVIEWED_OBSERVER")
        return self._call(command.argv,timeout)
    def setup(self,command,*,timeout=RUN_LIMIT_SECONDS):
        if self._setup_at>=len(self.plan.setup) or command!=self.plan.setup[self._setup_at]:
            raise UnsafeCommand("UNREVIEWED_SETUP_OR_RETRY")
        # Advance BEFORE invoking so a crashed/uncertain command cannot
        # be retried automatically. Cleanup must read the real state.
        self._setup_at+=1
        return self._call(command.argv,timeout)
    def teardown(self,command,*,confirmed_owned: bool,timeout=RUN_LIMIT_SECONDS):
        if confirmed_owned is not True:
            raise UnsafeCommand("OWNERSHIP_NOT_CONFIRMED")
        if self._teardown_at>=len(self.plan.teardown) or command!=self.plan.teardown[self._teardown_at]:
            raise UnsafeCommand("UNREVIEWED_TEARDOWN_OR_RETRY")
        self._teardown_at+=1
        return self._call(command.argv,timeout)
    def _call(self,argv,timeout):
        if type(timeout) not in (int,float) or not 0<timeout<=RUN_LIMIT_SECONDS:
            raise UnsafeCommand("INVALID_DEADLINE")
        if not isinstance(argv,tuple) or not all(isinstance(x,str) for x in argv):
            raise UnsafeCommand("INVALID_ARGV")
        try:
            # Injected callable returns Reply; never handle raw stderr or
            # send sensitive command arguments to public GitHub log output.
            return checked_reply(self._invoke(argv,timeout))
        except BaseException:
            raise UnsafeCommand("BACKEND_FAILED_NO_DETAILS") from None
