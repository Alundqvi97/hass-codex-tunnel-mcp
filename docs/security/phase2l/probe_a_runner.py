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
from probe_a_privilege import drop_controller, ReadOnlyPostObserver, PrivilegeDenied


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
        status="BLOCKED_SUPERVISION_FAILURE"
        try:
            channel=self.launcher.launch(self.plan,deadline)
            outcome=control(self.plan,RemoteIO(channel,self.plan,clock=self.clock),self.clock)
            status=outcome.receipt()
        except BaseException:
            status="BLOCKED_SUPERVISION_FAILURE"
        finally:
            if channel is not None:
                try: channel.close()
                except BaseException: pass
        # A parent that survives must independently observe guardian exit,
        # both filter tables and every residual resource. This audit also
        # executes when the controller aborted. NEVER return runtime PASS.
        try:
            post=self.launcher.verify_after(self.plan,deadline)
        except BaseException:
            post="BLOCKED_POST_GUARDIAN_AUDIT"
        return status+";POST="+post


class ForkGuardianLauncher:
    """Explicit, Linux-only launch into an independent OS session.

    Nothing starts until launch() is called by an externally authorized
    OneShotRunner. No default arbitrary process executors are available.
    """
    def __init__(self, *, backend_factory, post_observer_factory=None,
                 controller_drop=drop_controller, root_check=os.geteuid,
                 context_factory=multiprocessing.get_context, clock=time.monotonic):
        if not callable(backend_factory):
            raise RunnerDenied("MISSING_REVIEWED_BACKEND")
        if not callable(controller_drop):
            raise RunnerDenied("MISSING_OS_PRIVILEGE_BOUNDARY")
        # No read-only broker is bundled: without a reviewed external actor
        # launch is refused rather than inheriting privileged commands.
        self.post_observer_factory=post_observer_factory
        self.controller_drop=controller_drop
        self.backend_factory=backend_factory
        self.root_check=root_check
        self.context_factory=context_factory
        self.clock=clock
        self.child=None
        self.parent_observer=None
        self.parent_resources=None

    def launch(self, plan, deadline):
        if (self.child is not None or not callable(self.post_observer_factory)
                or self.root_check()!=0 or
                validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED" or
                not self.clock()<deadline<=self.clock()+240):
            raise RunnerDenied("GUARDIAN_LAUNCH_REFUSED")
        # Independent parent pre-change inventory BEFORE any guardian writes.
        from probe_a_observer import KernelReadback
        command, _unused_work, resources=self.backend_factory(plan)
        if resources.preflight() is not True:
            raise RunnerDenied("PARENT_RESOURCES_NOT_CLEAN")
        observer=KernelReadback(plan,read=command,clock=self.clock)
        observer.preflight(deadline)
        post_read=self.post_observer_factory(plan)
        read_only=ReadOnlyPostObserver(plan,read=post_read)
        # Preflight uses the privileged bootstrap; after the drop every
        # post-guardian observation passes through an independent read-only
        # broker and checks real unprivileged controller identity.
        self.parent_observer=KernelReadback(plan,read=read_only,clock=self.clock)
        self.parent_observer.baseline=observer.baseline
        self.parent_observer.versions=observer.versions
        self.parent_resources=resources
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
            # Bootstrap privilege must be irreversibly dropped BEFORE the
            # root guardian channel reaches the controller. Never allow
            # parent-side sudo as an alternate firewall mutation boundary.
            self.controller_drop()
            return parent
        except BaseException:
            parent.close()
            child.close()
            raise RunnerDenied("GUARDIAN_LAUNCH_OR_DROP_FAILED") from None

    def wait_for_exit(self, *, deadline):
        if self.child is None:
            raise RunnerDenied("NOT_STARTED")
        remaining=max(0,deadline-self.clock())
        self.child.join(timeout=remaining)
        if self.child.is_alive() or self.child.exitcode != 0:
            return "BLOCKED_GUARDIAN_NOT_CONFIRMED_EXITED"
        return "GUARDIAN_EXITED_NEEDS_EXTERNAL_KERNEL_READBACK"


    def verify_after(self, plan, deadline):
        """Read fresh evidence AFTER the separate guardian is reaped.

        This is a separate observer from the guardian, not a cryptographic
        attestation or qualified human/security review.
        """
        if (self.child is None or self.parent_observer is None or
                self.parent_resources is None or plan!=self.parent_observer.plan):
            return "BLOCKED_NO_INDEPENDENT_BASELINE"
        if self.wait_for_exit(deadline)!="GUARDIAN_EXITED_NEEDS_EXTERNAL_KERNEL_READBACK":
            return "BLOCKED_GUARDIAN_ALIVE_OR_FAILED"
        try:
            import os as _os
            pid=self.child.pid
            absent=(type(pid) is int and pid>1 and not self.child.is_alive()
                    and not _os.path.exists("/proc/"+str(pid)))
            audit=self.parent_observer.mandatory_readbacks(
                deadline,independent_resources=self.parent_resources
            )
            # Guardian cannot check its own exit; only reaping parent can.
            audit["watchdog_absent"] = absent is True
            self.parent_observer.require_restored(deadline)
            if set(audit)==set(__import__("probe_contract").CLEANUP_READBACKS) and all(
                    type(v) is bool and v for v in audit.values()):
                return "POST_RESTORED_INDEPENDENTLY_OBSERVED_NOT_PROBE_PASS"
        except BaseException:
            pass
        return "BLOCKED_POST_RESTORE_UNVERIFIED"

def reviewed_boundary_factory(plan, *, attestor):
    """Concrete low-level wiring, effectful ONLY when guardian explicitly runs.

    Every firewall command must cross RestrictedHost's exact argv gate. The
    client has a separate exact UID/argv gate and independent procfs checks.
    """
    from probe_a_os_boundary import RestrictedHost, bounded_process
    from probe_a_workload import FixedWorkload
    from probe_a_client_process import ClientProcess
    from probe_a_resources import LocalResourceReadback

    if attestor is None or attestor.verify() is not True:
        raise RunnerDenied("UNPINNED_EXECUTION_BOUNDARY")
    def guarded_command(argv,seconds):
        if attestor.verify() is not True:
            raise RunnerDenied("HOST_DRIFT_BEFORE_COMMAND")
        reply=bounded_process(argv,seconds,reviewed_plan=plan)
        if attestor.verify() is not True:
            raise RunnerDenied("HOST_DRIFT_AFTER_COMMAND")
        return reply
    restricted=RestrictedHost(plan,call=guarded_command)
    command=lambda argv,deadline: restricted.execute(argv,deadline=deadline)
    client=ClientProcess(plan)
    def guarded_client(*args):
        if attestor.verify() is not True:
            raise RunnerDenied("HOST_DRIFT_BEFORE_CLIENT")
        reply=client(*args)
        if attestor.verify() is not True:
            raise RunnerDenied("HOST_DRIFT_AFTER_CLIENT")
        return reply
    work=FixedWorkload(plan,invoke=guarded_client,stop=client.stop)
    resources=LocalResourceReadback(plan.scope)
    return command,work,resources
