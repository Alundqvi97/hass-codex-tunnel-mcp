"""Inert Probe A guardian protocol.

A distinct process can own all firewall commands and the cleanup reserve.
The controller only sends fixed, reviewed operations; the guardian keeps the
baseline and will run cleanup on controller disconnect, SIGTERM or deadline.
The guardian itself cannot survive SIGKILL, runner destruction or host loss.
There is NO implicit launcher or CLI in this module.
"""
from __future__ import annotations

import signal
import time

from probe_contract import validate_plan, CLEANUP_READBACKS
from probe_a_exec_adapter import ExactArgvGate
from probe_a_observer import KernelReadback
from probe_a_recovery import recover_owned, inspect_partial


class GuardianDenied(RuntimeError):
    pass


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
        self.cleaned = False
        self.cleanup_result = None
        self.receipts = None
        self.client_started = False
        self.writes_attempted = False

    def handle(self, method, argument, deadline):
        if self.clock() >= deadline or (self.cleaned and method not in ("cleanup_readback", "snapshot")):
            raise GuardianDenied("NO_MORE_WORK")
        if method == "preflight":
            if self.started or argument != self.plan:
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
        if method == "exercise" and argument in tuple(x[0] for x in __import__("probe_a_controller").CASES):
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
        if self.cleaned:
            return self.cleanup_result == "SYNTHETIC_RECOVERED_NOT_KERNEL_ATTESTED"
        self.cleaned = True
        # Cleanup must never accidentally release a still-running test UID.
        try:
            stopped = self.work.stop(deadline) is True
        except BaseException:
            stopped = False
        self.cleanup_result = "BLOCKED_UID_STILL_ACTIVE"
        if self.baseline is not None and stopped:
            try:
                absent = self.observer._query(
                    ("/usr/bin/pgrep", "-u", str(self.plan.uid)), deadline, codes=(1,)
                ) == ""
                if absent:
                    self.cleanup_result, _ = recover_owned(
                        self.plan, self.baseline, snapshot=self.observer.snapshot,
                        execute=lambda argv, limit: self.command(argv, limit).code == 0,
                        deadline=deadline, clock=self.clock
                    )
            except BaseException:
                self.cleanup_result = "BLOCKED_CLEANUP_UNVERIFIED"
        # Read back every check even when an earlier one fails.
        try:
            self.receipts = self.observer.mandatory_readbacks(
                deadline, independent_resources=self.resources
            )
        except BaseException:
            self.receipts = {key: False for key in CLEANUP_READBACKS}
        # Cleanup itself cannot attest that this guardian has exited.
        self.receipts["watchdog_absent"] = False
        return False  # never assert live or synthetic completeness here


class GuardianChannel:
    """Interface receives ('method', arg, deadline) or EOF; sends safe reply.

    poll(timeout)->bool, recv()->request, send(reply). Caller must provide a
    distinct OS process for actual independence. No live channel by default.
    """
    def __init__(self, core, *, clock=time.monotonic):
        self.core = core
        self.clock = clock

    def serve(self, channel, *, end, cleanup_reserve=60):
        if not 45 <= cleanup_reserve <= 90 or end-self.clock() > 240:
            raise GuardianDenied("INVALID_SUPERVISOR_DEADLINE")
        work_end = end-cleanup_reserve
        done = False
        try:
            while self.clock() < end:
                if self.clock() >= work_end and not self.core.cleaned:
                    self.core.cleanup(end)
                    done = True
                remaining = max(0, end-self.clock())
                if not channel.poll(min(0.20, remaining)):
                    continue
                try:
                    request = channel.recv()
                except (EOFError, OSError):
                    break
                if (not isinstance(request, tuple) or len(request) != 3 or
                        request[0] not in ("preflight", "snapshot", "issue", "counters",
                                          "exercise", "stop", "cleanup", "cleanup_readback") or
                        type(request[2]) not in (int, float) or
                        not self.clock() < request[2] <= end):
                    break
                method, arg, requested_end = request
                if self.clock() >= work_end and method not in ("stop", "cleanup", "cleanup_readback", "snapshot"):
                    break
                if done and method not in ("cleanup_readback", "snapshot"):
                    break
                try:
                    value = self.core.handle(method, arg, min(requested_end, work_end)
                                             if method not in ("stop","cleanup","cleanup_readback","snapshot")
                                             else min(requested_end, end))
                    channel.send(("OK", value))
                    if method == "cleanup":
                        done = True
                except BaseException:
                    try:
                        channel.send(("BLOCKED", None))
                    except BaseException:
                        pass
                    break
        except BaseException:
            pass
        finally:
            try:
                self.core.cleanup(end)
            except BaseException:
                pass
            try:
                channel.close()
            except BaseException:
                pass


class RemoteIO:
    """Controller-side narrow RPC interface. No root access."""
    def __init__(self, channel, *, clock=time.monotonic):
        self.channel=channel
        self.clock=clock

    def _call(self, method, value, deadline):
        if self.clock() >= deadline:
            raise GuardianDenied("REMOTE_DEADLINE")
        self.channel.send((method, value, deadline))
        if not self.channel.poll(min(8, max(0, deadline-self.clock()))):
            raise GuardianDenied("GUARDIAN_UNRESPONSIVE")
        try:
            reply = self.channel.recv()
        except (EOFError, OSError):
            raise GuardianDenied("GUARDIAN_DISCONNECTED") from None
        if not isinstance(reply, tuple) or len(reply)!=2 or reply[0]!="OK":
            raise GuardianDenied("GUARDIAN_REFUSED")
        return reply[1]

    def preflight(self, plan):
        return self._call("preflight",plan,self.clock()+8)
    def snapshot(self):
        return self._call("snapshot",None,self.clock()+8)
    def issue(self,command,deadline):
        return self._call("issue",command,deadline) is True
    def counters(self,family):
        return self._call("counters",family,self.clock()+8)
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
