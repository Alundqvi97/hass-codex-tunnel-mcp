"""Pure injectable transaction rehearsal; NO system effects or kernel claims.

Caller injects *synthetic* callbacks. The real privileged process/controller
and trusted observer are intentionally ABSENT. Every exit is non-success.
"""
from __future__ import annotations
from dataclasses import dataclass
from probe_contract import validate_plan, CLEANUP_READBACKS

@dataclass(frozen=True)
class Rehearsal:
    result: str
    setup_attempts: int
    teardown_attempts: int
    workload_attempts: int

def rehearse(plan, *, preflight, issue, observe, workload, stop, cleanup_readback):
    """Callbacks are offline-only fakes; always teardown and never return PASS.

    No retry of a command, client or entire run; never suppress one cleanup
    error merely because another cleanup step completed.
    """
    if validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED":
        return Rehearsal("BLOCKED_INVALID_PLAN",0,0,0)
    state="BLOCKED_SETUP_OR_READBACK"
    setup_count=0
    teardown_count=0
    workload_count=0
    try:
        # Even if preflight aborts, cleanup is attempted because unknown
        # pre-existing partial state must not be silently ignored.
        if preflight() is not True:
            state="BLOCKED_PREFLIGHT"
        else:
            ready=True
            for index,command in enumerate(plan.setup):
                setup_count+=1
                if issue(command) is not True:
                    ready=False
                    break
                if index==5 and observe("dual_stack_deny_hooks") is not True:
                    ready=False
                    break
            if ready:
                if observe("effective_rule_order") is True and observe("exact_uid") is True:
                    workload_count+=1
                    if workload() is True:
                        state="SYNTHETIC_WORKLOAD_COMPLETE_NOT_KERNEL_PROOF"
                    else:
                        state="BLOCKED_WORKLOAD"
                else:
                    state="BLOCKED_EFFECTIVE_RULES"
    except Exception:
        state="BLOCKED_CALLBACK_EXCEPTION"
    finally:
        try:
            stop()
        except Exception:
            state="BLOCKED_PROCESS_STOP"
        # Do NOT short circuit subsequent cleanup commands after errors.
        for command in plan.teardown:
            teardown_count+=1
            try:
                if issue(command) is not True:
                    state="BLOCKED_TEARDOWN"
            except Exception:
                state="BLOCKED_TEARDOWN"
        # Every required cleanup readback must be attempted independently;
        # short-circuiting after an early failed check hides later residue.
        bad=False
        for key in CLEANUP_READBACKS:
            try:
                if cleanup_readback(key) is not True:
                    bad=True
            except Exception:
                bad=True
        if bad:
            state="BLOCKED_CLEANUP_READBACK"
    return Rehearsal(state,setup_count,teardown_count,workload_count)
