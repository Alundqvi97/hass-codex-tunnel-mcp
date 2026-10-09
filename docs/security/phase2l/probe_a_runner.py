"""Disabled-by-default single Probe A runner with independent guardian process.

No CLI, automatic main, workflow, hidden environment opt-in, subprocess or
network at import. Actual execution additionally requires an explicit
out-of-band activation verifier AND an explicitly supplied launcher. A
qualified independent code review and single separate authorization must
precede connecting any launcher to GitHub Actions.
"""
from __future__ import annotations

import multiprocessing
import os
import time

from probe_contract import validate_plan
from probe_a_controller import control
from probe_a_guardian import GuardianCore, GuardianChannel, RemoteIO, installed_signal_abort


class RunnerDenied(RuntimeError):
    pass


class OneShotRunner:
    def __init__(self, plan, *, launcher=None, verify_activation=None, clock=time.monotonic):
        self.plan=plan
        self.launcher=launcher
        self.verify_activation=verify_activation
        self.clock=clock
        self.used=False

    def run(self, *, activated=False, approval=None):
        if self.used:
            return "BLOCKED_REPLAY"
        self.used=True  # even a failed authorization consumes this object
        if (activated is not True or
                validate_plan(self.plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED" or
                not callable(self.verify_activation) or self.launcher is None or
                self.verify_activation(self.plan, approval) is not True):
            return "BLOCKED_DISABLED_OR_UNAPPROVED"
        deadline=self.clock()+240
        channel=None
        try:
            channel=self.launcher.launch(self.plan,deadline)
            outcome=control(self.plan,RemoteIO(channel,clock=self.clock),self.clock)
            # A channel result is NOT kernel proof, and final process exit /
            # post-guardian readback must be independently established.
            return outcome.receipt()
        except BaseException:
            return "BLOCKED_SUPERVISION_FAILURE"
        finally:
            if channel is not None:
                try: channel.close()
                except BaseException: pass
            # Must never kill guardian as part of closing the controller;
            # it independently owns the cleanup reserve until completion.


class ForkGuardianLauncher:
    """Explicit, Linux-only launch into an independent OS session.

    Nothing starts until launch() is called by an externally authorized
    OneShotRunner. No default arbitrary process executors are available.
    """
    def __init__(self, *, backend_factory, root_check=os.geteuid,
                 context_factory=multiprocessing.get_context, clock=time.monotonic):
        if not callable(backend_factory):
            raise RunnerDenied("MISSING_REVIEWED_BACKEND")
        self.backend_factory=backend_factory
        self.root_check=root_check
        self.context_factory=context_factory
        self.clock=clock
        self.child=None

    def launch(self, plan, deadline):
        if (self.child is not None or self.root_check()!=0 or
                validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED" or
                not self.clock()<deadline<=self.clock()+240):
            raise RunnerDenied("GUARDIAN_LAUNCH_REFUSED")
        ctx=self.context_factory("fork")
        parent,child=ctx.Pipe(duplex=True)
        # The child holds the backend; the controller never receives root I/O.
        def child_main():
            try:
                parent.close()
                os.setsid()  # separate from caller's process group (not CI job kill proof)
                command,work,resources=self.backend_factory(plan)
                core=GuardianCore(plan,command=command,work=work,resources=resources,
                                  clock=self.clock)
                installed_signal_abort(lambda: None)
                GuardianChannel(core,clock=self.clock).serve(child,end=deadline)
            except BaseException:
                # No stdout or raw command output; OS kill of THIS guardian
                # cannot be recovered from within this same actor.
                pass
            finally:
                try: child.close()
                except BaseException: pass
        process=ctx.Process(target=child_main,daemon=False,name="p2a-owned-guardian")
        try:
            process.start()
            self.child=process
            child.close()
            return parent
        except BaseException:
            parent.close()
            child.close()
            raise RunnerDenied("GUARDIAN_START_FAILED") from None

    def wait_for_exit(self, *, deadline):
        if self.child is None:
            raise RunnerDenied("NOT_STARTED")
        remaining=max(0,deadline-self.clock())
        self.child.join(timeout=remaining)
        if self.child.is_alive() or self.child.exitcode != 0:
            return "BLOCKED_GUARDIAN_NOT_CONFIRMED_EXITED"
        return "GUARDIAN_EXITED_NEEDS_EXTERNAL_KERNEL_READBACK"


def reviewed_boundary_factory(plan):
    """Concrete low-level wiring, effectful ONLY when guardian explicitly runs.

    Every firewall command must cross RestrictedHost's exact argv gate. The
    client has a separate exact UID/argv gate and independent procfs checks.
    """
    from probe_a_os_boundary import RestrictedHost, bounded_process
    from probe_a_workload import FixedWorkload
    from probe_a_client_process import ClientProcess
    from probe_a_resources import LocalResourceReadback

    restricted=RestrictedHost(
        plan,
        call=lambda argv,seconds: bounded_process(argv,seconds,reviewed_plan=plan),
    )
    command=lambda argv,deadline: restricted.execute(argv,deadline=deadline)
    client=ClientProcess(plan)
    work=FixedWorkload(plan,invoke=client,stop=client.stop)
    resources=LocalResourceReadback(plan.scope)
    return command,work,resources
