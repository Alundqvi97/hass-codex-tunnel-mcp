"""Bounded Probe A controller with injected I/O, NOT a runnable workflow.

Deliberately no shell/socket/firewall dependency. The sole output is a
candidate evidence classification, never independent live attestation.
Requires an independently reviewed privileged adapter before use.
"""
from __future__ import annotations
from dataclasses import dataclass
from probe_contract import CLEANUP_READBACKS, validate_plan
from probe_a_kernel import (InvalidEvidence, expect_active, compare_after,
                            require_counter_delta)

CASES=(
    ("approved-udp","ipv4",2),
    ("approved-tcp","ipv4",1),
    ("alternate-udp","ipv4",3),
    ("alternate-tcp","ipv4",3),
    ("private","ipv4",3),
    ("link-local","ipv4",3),
    ("ipv6-loopback","ipv6",0),
    ("loopback-new","ipv4",3),
    ("public-web","ipv4",3),
    ("loopback-established","ipv4",0),
)

@dataclass(frozen=True)
class Outcome:
    label: str
    setup_steps: int
    completed_cases: int
    cleanup_checks: int
    def receipt(self):
        # Label-only, not a kernel attestation.
        return "PROBE_A="+self.label

def control(plan,io,clock,*,budget_seconds=240,cleanup_reserve_seconds=60):
    """I/O adapter protocol:
    io.preflight(plan), io.snapshot()->(str4,str6),
    io.issue(Command,deadline)->bool, io.counters(family)->tuple,
    io.exercise(case,deadline)->bool, io.stop(deadline)->bool,
    io.cleanup(plan,attempted,deadline)->bool,
    io.cleanup_readback(key,baselines,deadline)->bool.

    Each I/O operation MUST implement its own bounded timeout and
    reject unapproved identity, destination, command, or kernel drift.
    """
    if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        return Outcome("BLOCKED_BAD_PLAN",0,0,0)
    if type(budget_seconds) is not int or type(cleanup_reserve_seconds) is not int or budget_seconds>240 or budget_seconds<120 or not 45<=cleanup_reserve_seconds<=90 or budget_seconds-cleanup_reserve_seconds<30:
        return Outcome("BLOCKED_BUDGET",0,0,0)
    start=clock()
    deadline=start+budget_seconds
    work_end=deadline-cleanup_reserve_seconds
    setup=0; completed=0; checks=0
    label="BLOCKED_PREFLIGHT"
    before=None
    setup_attempts=[]
    def check_time(limit):
        if clock()>=limit:
            raise TimeoutError("BOUNDED_DEADLINE")
    try:
        check_time(work_end)
        if io.preflight(plan) is not True:
            raise ValueError("PREFLIGHT_DENIED")
        before=io.snapshot()
        if not isinstance(before,tuple) or len(before)!=2:
            raise ValueError("SNAPSHOT_MISSING")
        label="BLOCKED_SETUP"
        for idx,cmd in enumerate(plan.setup):
            check_time(work_end)
            setup_attempts.append(cmd)
            setup+=1
            if io.issue(cmd,work_end) is not True:
                raise ValueError("COMMAND_UNVERIFIED")
            if idx==5:
                check_time(work_end)
                now=io.snapshot()
                expect_active(*now,*before,plan,final=False)
        check_time(work_end)
        expect_active(*io.snapshot(),*before,plan,final=True)
        label="BLOCKED_CASE_EVIDENCE"
        for case,family,index in CASES:
            check_time(work_end)
            before_c=io.counters(family)
            if io.exercise(case,work_end) is not True:
                raise ValueError("CLIENT_NOT_VERIFIED")
            check_time(work_end)
            after_c=io.counters(family)
            require_counter_delta(before_c,after_c,index)
            # Prevent a test process from altering the filtering rules.
            expect_active(*io.snapshot(),*before,plan,final=True)
            completed+=1
        label="SYNTHETIC_OR_ADAPTER_REPORTED_COMPLETE_NOT_ATTESTED"
    except TimeoutError:
        label="BLOCKED_TIMEOUT"
    except (Exception,BaseException):
        # Includes KeyboardInterrupt from injected adapter. Caller must also
        # have an external watchdog for SIGKILL/runner termination.
        label="BLOCKED_SETUP_OR_EVIDENCE"
    finally:
        # Cleanup has a separately reserved time window. Never call workload
        # after cleanup begins and never skip later independent readbacks.
        stop_ok=False; cleanup_ok=False
        try:
            check_time(deadline)
            stop_ok=io.stop(deadline) is True
        except BaseException:
            label="BLOCKED_STOP"
        try:
            check_time(deadline)
            # Observer must ownership-check all partially created resources
            # before deletion, not blindly replay a stale command list.
            cleanup_ok=io.cleanup(plan,tuple(setup_attempts),deadline) is True
        except BaseException:
            label="BLOCKED_CLEANUP"
        bad=not stop_ok or not cleanup_ok
        for key in CLEANUP_READBACKS:
            checks+=1
            try:
                check_time(deadline)
                if io.cleanup_readback(key,before,deadline) is not True:
                    bad=True
            except BaseException:
                bad=True
        if before is not None:
            try:
                check_time(deadline)
                compare_after(*io.snapshot(),*before)
            except BaseException:
                bad=True
        else:
            bad=True
        if bad:
            label="BLOCKED_RESTORATION_UNVERIFIED"
    return Outcome(label,setup,completed,checks)
