"""Inert Probe A guardian protocol.

A distinct process can own all firewall commands and the cleanup reserve.
The controller only sends fixed, reviewed operations; the guardian keeps the
baseline and will run cleanup on controller disconnect, SIGTERM or deadline.
The guardian itself cannot survive SIGKILL, runner destruction or host loss.
There is NO implicit launcher or CLI in this module.
"""
from __future__ import annotations

import json
import signal
import time

from probe_contract import CASES, validate_plan, CLEANUP_READBACKS
from probe_a_exec_adapter import ExactArgvGate
from probe_a_observer import KernelReadback
from probe_a_recovery import recover_owned, inspect_partial, emergency_deny_only
from probe_a_ipc import IpcDenied



class GuardianDenied(RuntimeError):
    pass


# Guardian-internal lifecycle claims are NEVER independent kernel evidence.
LIFECYCLE_COMPLETE = "POST_CLEANUP_AUDIT_REQUIRED"
LIFECYCLE_CANCELLED = "CONTROLLER_DISCONNECTED_CLEANUP_ATTEMPTED"
LIFECYCLE_DEADLINE = "DEADLINE_CLEANUP_ATTEMPTED"
LIFECYCLE_INCOMPLETE = "CLEANUP_NOT_VERIFIED"
LIFECYCLE_FAULT = "SUPERVISION_FAULT"


class GuardianCore:
    """Ownership and bounded command authority stay with this actor.

    command(argv,timeout)->Reply must be a RestrictedHost with a bounded
    streaming low-level backend. work and resources are separately injected;
    no mock status is ever reported as genuine evidence.
    """
    def __init__(self, plan, *, command, work, resources, clock=time.monotonic):
        if validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
            raise GuardianDenied("INVALID_PLAN")
        if not all(callable(x) for x in (command, clock)):
            raise GuardianDenied("INVALID_BOUNDARY")
        self.plan = plan
        self.clock = clock
        self.command = command
        self.work = work
        self.resources = resources
        self.observer = KernelReadback(plan, read=lambda argv, deadline: command(argv, deadline),
                                       clock=clock)
        self.gate = ExactArgvGate(plan, invoke=lambda argv, timeout: command(argv, clock()+timeout))
        self.baseline = None
        self.started = False
        self.cleanup_state = "NOT_STARTED"
        self.cleanup_attempts = set()
        self.emergency_attempts = set()
        self.cleanup_result = None
        self.receipts = None
        self.client_started = False
        self.writes_attempted = False

    @property
    def cleaned(self):
        return self.cleanup_state != "NOT_STARTED"

    def handle(self, method, argument, deadline):
        if self.clock() >= deadline or (self.cleaned and method not in ("cleanup","cleanup_readback", "snapshot")):
            raise GuardianDenied("NO_MORE_WORK")
        if method == "preflight":
            if self.started or argument != "START":
                raise GuardianDenied("PREFLIGHT_NOT_ONCE")
            if self.resources.preflight() is not True:
                raise GuardianDenied("RESOURCE_PREFLIGHT_FAILED")
            self.observer.preflight(deadline)
            self.baseline = self.observer.baseline
            self.started = True
            return True
        if not self.started:
            raise GuardianDenied("NOT_ARMED")
        if method == "snapshot" and argument is None:
            return self.observer.snapshot(deadline)
        if method == "issue":
            if argument not in self.plan.setup:
                raise GuardianDenied("UNKNOWN_WRITE")
            # ExactArgvGate enforces full sequence, one attempt, no retry.
            self.writes_attempted = True
            reply = self.gate.setup(argument, timeout=min(8, max(0.01, deadline-self.clock())))
            # Every response, including a nonzero exit, must be checked by
            # independent readback before further work is eligible.
            inspect_partial(self.plan, self.baseline, self.observer.snapshot(deadline))
            return reply.code == 0
        if method == "counters" and argument in ("ipv4", "ipv6"):
            self.observer.require_active(deadline, final=True)
            return self.observer.counters(argument, deadline)
        if method == "exercise" and argument in tuple(x[0] for x in CASES):
            self.observer.require_active(deadline, final=True)
            self.client_started = True
            return self.work.exercise(argument, self.plan, deadline) is True
        if method == "stop" and argument is None:
            return self.work.stop(deadline) is True
        if method == "cleanup" and argument is None:
            return self.cleanup(deadline)
        if method == "cleanup_readback" and argument in CLEANUP_READBACKS:
            if self.receipts is None:
                raise GuardianDenied("NOT_CLEANED")
            return self.receipts[argument]
        raise GuardianDenied("UNREVIEWED_OPERATION")

    def cleanup(self, deadline):
        """Resume safely from fresh readbacks, never replay a logged mutation.

        Guardian may verify its owned rules but may NEVER attest its own exit.
        The parent must separately re-observe the post-guardian host.
        """
        if self.cleanup_state == "POST_AUDIT_REQUIRED":
            # Only the reaping parent can perform the final independent audit.
            # Avoid restarting teardown after all owned resources were checked.
            return False
        if self.cleanup_state == "IN_PROGRESS":
            # An asynchronous SIGTERM may have interrupted an earlier call.
            # The recorded argv journal and fresh snapshots make a resumed
            # call safe without replaying an uncertain firewall mutation.
            self.cleanup_state = "PARTIAL"
        self.cleanup_state = "IN_PROGRESS"
        try:
            stopped = self.work.stop(deadline) is True
        except BaseException:
            stopped = False
        self.cleanup_result = "BLOCKED_UID_STILL_ACTIVE"
        absent = False
        if self.baseline is not None:
            try:
                absent = self.observer._query(
                    ("/usr/bin/pgrep","-u",str(self.plan.uid)),deadline,codes=(1,)
                ) == ""
            except BaseException:
                absent = False
            if not absent:
                # Deny the still-running UID's temporary allowed traffic.
                # Do not expose its IPv4/IPv6 hooks through partial teardown.
                try:
                    self.cleanup_result, _ = emergency_deny_only(
                        self.plan,self.baseline,snapshot=self.observer.snapshot,
                        execute=lambda argv,limit:self.command(argv,limit).code==0,
                        deadline=deadline,clock=self.clock,
                        previous_attempts=self.emergency_attempts,
                        on_attempt=self.emergency_attempts.add
                    )
                except BaseException:
                    self.cleanup_result="BLOCKED_EMERGENCY_UNVERIFIED"
            elif stopped:
                try:
                    self.cleanup_result, _ = recover_owned(
                        self.plan,self.baseline,snapshot=self.observer.snapshot,
                        execute=lambda argv,limit:self.command(argv,limit).code==0,
                        deadline=deadline,clock=self.clock,
                        previous_attempts=self.cleanup_attempts,
                        on_attempt=self.cleanup_attempts.add
                    )
                except BaseException:
                    self.cleanup_result="BLOCKED_CLEANUP_UNVERIFIED"
        try:
            self.receipts = self.observer.mandatory_readbacks(
                deadline,independent_resources=self.resources
            )
        except BaseException:
            self.receipts={key:False for key in CLEANUP_READBACKS}
        # No response can claim this same guardian has exited.
        self.receipts["watchdog_absent"]=False
        if (self.cleanup_result=="SYNTHETIC_RECOVERED_NOT_KERNEL_ATTESTED"
                and absent and stopped
                and all(self.receipts.get(k) is True for k in CLEANUP_READBACKS
                        if k!="watchdog_absent")):
            self.cleanup_state="POST_AUDIT_REQUIRED"
        elif self.cleanup_result and self.cleanup_result.startswith("BLOCKED"):
            self.cleanup_state="BLOCKED"
        else:
            self.cleanup_state="PARTIAL"
        return False


class GuardianChannel:
    """JSON RPC over shared, nonblocking, four-byte-length-framed IPC.

    The real launcher supplies BoundedSocketIPC (AF_UNIX socketpair).
    Both recv_bytes and send_bytes require absolute work-window deadlines.
    Test-only synthetic channels must implement this same bounded API.
    """
    def __init__(self, core, *, clock=time.monotonic, sleep=time.sleep):
        self.core = core
        self.clock = clock
        self.sleep = sleep

    def serve(self, channel, *, end, cleanup_reserve=60, cleanup_cutoff=None):
        if (not 45 <= cleanup_reserve <= 90 or
                type(end) not in (int,float) or
                end-self.clock() > 240 or end <= self.clock()):
            raise GuardianDenied("INVALID_SUPERVISOR_DEADLINE")
        work_end = end-cleanup_reserve if cleanup_cutoff is None else cleanup_cutoff
        if (type(work_end) not in (int,float) or
                end-work_end !=cleanup_reserve):
            raise GuardianDenied("SUPERVISOR_CUTOFF_MISMATCH")
        # Each invocation re-observes ownership. The core's before-write
        # journals prevent an uncertain firewall operation being replayed.
        next_cleanup_at = work_end
        retry_seconds = 0.5
        disconnected = False
        cleanup_requested = False
        cancelled = False
        fault = False
        try:
            while self.clock() < end:
                now = self.clock()
                recovering = disconnected or cleanup_requested or now >= work_end
                if (recovering and self.core.cleanup_state != "POST_AUDIT_REQUIRED"
                        and now >= next_cleanup_at):
                    try:
                        self.core.cleanup(end)
                    except BaseException:
                        # Continue safely through journal + new ownership reads,
                        # but preserve that this was a supervision fault.
                        fault = True
                    next_cleanup_at = self.clock() + retry_seconds
                if recovering:
                    # Recovery is exclusively guardian-owned. Never service
                    # snapshots, counters or other controller requests inside
                    # the reserved cleanup window, even under IPC flooding.
                    if not disconnected:
                        disconnected = True
                        try:
                            channel.close()
                        except BaseException:
                            fault = True
                    if self.core.cleanup_state == "POST_AUDIT_REQUIRED":
                        break
                    now = self.clock()
                    remaining = min(end-now, next_cleanup_at-now, 0.20)
                    if remaining > 0:
                        self.sleep(remaining)
                    continue
                remaining = max(0, end-self.clock())
                try:
                    # Never poll across the work/cleanup boundary.
                    ready = channel.poll(min(0.20, remaining,
                                             max(0,work_end-self.clock())))
                except BaseException:
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                if not ready:
                    continue
                try:
                    # A readable header is not a complete frame. The
                    # transport bounds the entire header+payload transaction.
                    wire = channel.recv_bytes(256,deadline=work_end)
                    request = json.loads(wire.decode("utf-8", "strict"))
                except EOFError:
                    cancelled = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                except (OSError, ValueError, UnicodeError, IpcDenied):
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                if (type(request) is not dict or
                        set(request) != {"method", "value", "deadline"} or
                        type(request["method"]) is not str or
                        type(request["deadline"]) not in (int, float) or
                        not self.clock() < request["deadline"] <= end):
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                method = request["method"]
                arg = request["value"]
                requested_end = request["deadline"]
                if method not in ("preflight", "snapshot", "issue", "counters",
                                  "exercise", "stop", "cleanup", "cleanup_readback"):
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                if method == "issue":
                    if type(arg) is not int or not 0 <= arg < len(self.core.plan.setup):
                        fault = True
                        disconnected = True
                        next_cleanup_at = self.clock()
                        continue
                    arg = self.core.plan.setup[arg]
                elif method == "preflight":
                    if arg != "START":
                        fault = True
                        disconnected = True
                        next_cleanup_at = self.clock()
                        continue
                elif method in ("snapshot", "stop", "cleanup") and arg is not None:
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                elif method == "counters" and arg not in ("ipv4", "ipv6"):
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                elif method == "exercise" and arg not in tuple(
                        c[0] for c in CASES):
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                elif method == "cleanup_readback" and arg not in CLEANUP_READBACKS:
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                if recovering and method not in ("stop", "cleanup", "cleanup_readback", "snapshot"):
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
                    continue
                try:
                    value = self.core.handle(
                        method, arg,
                        min(requested_end, work_end)
                        if method not in ("stop", "cleanup")
                        else min(requested_end, end))
                    # Even cleanup responses may not consume the guardian's
                    # reserved recovery time. The controller can rely on
                    # independent post-guardian evidence instead.
                    channel.send_bytes(
                        json.dumps({"ok": True, "value": value},
                                   separators=(",", ":")).encode("utf-8"),
                        deadline=work_end)
                    if method == "cleanup":
                        cleanup_requested = True
                        next_cleanup_at = self.clock() + retry_seconds
                except BaseException:
                    try:
                        channel.send_bytes(b'{"ok":false,"value":null}',
                                           deadline=work_end)
                    except BaseException:
                        pass
                    fault = True
                    disconnected = True
                    next_cleanup_at = self.clock()
        except BaseException:
            fault = True
        finally:
            try:
                if (self.clock() < end and
                        self.core.cleanup_state != "POST_AUDIT_REQUIRED"):
                    self.core.cleanup(end)
            except BaseException:
                fault = True
            try:
                channel.close()
            except BaseException:
                fault = True
        # A normal return is possible only after owned cleanup and readbacks.
        # Parent must STILL independently observe guardian exit and host state.
        if self.core.cleanup_state != "POST_AUDIT_REQUIRED":
            return LIFECYCLE_INCOMPLETE
        if fault:
            return LIFECYCLE_FAULT
        if cancelled:
            return LIFECYCLE_CANCELLED
        if not cleanup_requested:
            return LIFECYCLE_DEADLINE
        return LIFECYCLE_COMPLETE


class RemoteIO:
    """Controller-side narrow RPC interface. No root access."""
    def __init__(self, channel, plan, *, clock=time.monotonic):
        if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
            raise GuardianDenied("INVALID_REMOTE_PLAN")
        self.plan=plan
        self.channel=channel
        self.clock=clock

    def _call(self, method, value, deadline):
        if self.clock() >= deadline:
            raise GuardianDenied("REMOTE_DEADLINE")
        payload=json.dumps({"method":method,"value":value,"deadline":deadline},separators=(",",":")).encode("utf-8")
        if len(payload)>256:
            raise GuardianDenied("MESSAGE_TOO_LARGE")
        # The same absolute RPC deadline bounds send, frame header, complete
        # reply and any partial/readable payload. No Connection framing is used.
        try:
            self.channel.send_bytes(payload,deadline=deadline)
            reply = json.loads(
                self.channel.recv_bytes(300000,deadline=deadline)
                .decode("utf-8","strict"))
        except (EOFError, OSError, IpcDenied, UnicodeError, ValueError):
            raise GuardianDenied("GUARDIAN_DISCONNECTED") from None
        if type(reply) is not dict or set(reply)!={"ok","value"} or reply["ok"] is not True:
            raise GuardianDenied("GUARDIAN_REFUSED")
        return reply["value"]

    def preflight(self, plan):
        if plan!=self.plan: raise GuardianDenied("REMOTE_PLAN_MISMATCH")
        return self._call("preflight","START",self.clock()+8)
    def snapshot(self):
        result=self._call("snapshot",None,self.clock()+8)
        if (type(result) is not list or len(result)!=2 or
                any(type(x) is not str for x in result)):
            raise GuardianDenied("BAD_KERNEL_SNAPSHOT_SHAPE")
        return tuple(result)
    def issue(self,command,deadline):
        if command not in self.plan.setup: raise GuardianDenied("UNREVIEWED_REMOTE_COMMAND")
        return self._call("issue",self.plan.setup.index(command),deadline) is True
    def counters(self,family):
        rows=self._call("counters",family,self.clock()+8)
        if type(rows) is not list or len(rows)>16 or not rows:
            raise GuardianDenied("BAD_COUNTER_SHAPE")
        return tuple(tuple(row) for row in rows)
    def exercise(self,case,deadline):
        return self._call("exercise",case,deadline) is True
    def stop(self,deadline):
        return self._call("stop",None,deadline) is True
    def cleanup(self,plan,attempted,deadline):
        return self._call("cleanup",None,deadline) is True
    def cleanup_readback(self,key,baseline,deadline):
        return self._call("cleanup_readback",key,deadline) is True


def installed_signal_abort(terminate):
    """Optional guardian-local SIGTERM handler; never called at import."""
    if not callable(terminate):
        raise GuardianDenied("INVALID_TERMINATION_HANDLER")
    def handler(signum, frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        terminate()
        raise GuardianDenied("SIGTERM_INTERRUPT")
    signal.signal(signal.SIGTERM, handler)
