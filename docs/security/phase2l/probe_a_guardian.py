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

    poll(timeout)->bool, recv_bytes(limit)->bytes, send_bytes(bytes). Caller must provide a
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
                    wire = channel.recv_bytes(256)
                    request = json.loads(wire.decode("utf-8", "strict"))
                except (EOFError, OSError, ValueError, UnicodeError):
                    break
                if (type(request) is not dict or
                        set(request) != {"method", "value", "deadline"} or
                        type(request["method"]) is not str or
                        type(request["deadline"]) not in (int, float) or
                        not self.clock() < request["deadline"] <= end):
                    break
                method=request["method"]
                arg=request["value"]
                requested_end=request["deadline"]
                if method not in ("preflight", "snapshot", "issue", "counters",
                                  "exercise", "stop", "cleanup", "cleanup_readback"):
                    break
                if method=="issue":
                    if type(arg) is not int or not 0<=arg<len(self.core.plan.setup):
                        break
                    arg=self.core.plan.setup[arg]
                elif method=="preflight":
                    if arg!="START":break
                elif method in ("snapshot","stop","cleanup") and arg is not None:
                    break
                elif method=="counters" and arg not in ("ipv4","ipv6"):
                    break
                elif method=="exercise" and arg not in tuple(c[0] for c in __import__("probe_a_controller").CASES):
                    break
                elif method=="cleanup_readback" and arg not in CLEANUP_READBACKS:
                    break
                if self.clock() >= work_end and method not in ("stop", "cleanup", "cleanup_readback", "snapshot"):
                    break
                if done and method not in ("cleanup_readback", "snapshot"):
                    break
                try:
                    value = self.core.handle(method, arg, min(requested_end, work_end)
                                             if method not in ("stop","cleanup","cleanup_readback","snapshot")
                                             else min(requested_end, end))
                    channel.send_bytes(json.dumps({"ok":True,"value":value},separators=(",",":")).encode("utf-8"))
                    if method == "cleanup":
                        done = True
                except BaseException:
                    try:
                        channel.send_bytes(b'{"ok":false,"value":null}')
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
        self.channel.send_bytes(payload)
        if not self.channel.poll(min(8, max(0, deadline-self.clock()))):
            raise GuardianDenied("GUARDIAN_UNRESPONSIVE")
        try:
            reply = json.loads(self.channel.recv_bytes(300000).decode("utf-8","strict"))
        except (EOFError, OSError):
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
