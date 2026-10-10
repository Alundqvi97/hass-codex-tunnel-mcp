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
from probe_a_ipc import socket_channel_pair

from probe_contract import validate_plan
from probe_a_controller import control
from probe_a_guardian import (
    GuardianCore, GuardianChannel, RemoteIO, installed_signal_abort,
    LIFECYCLE_COMPLETE, LIFECYCLE_CANCELLED, LIFECYCLE_DEADLINE,
    LIFECYCLE_INCOMPLETE, LIFECYCLE_FAULT
)
from probe_a_privilege import drop_controller, verify_unprivileged, ReadOnlyPostObserver, PrivilegeDenied


class RunnerDenied(RuntimeError):
    pass


def _require_unprivileged_or_failstop(started_as_root):
    """Never return to an original root caller unless /proc proves full drop.

    Called on every normal/exceptional runner exit and immediately after
    launcher return or error. os._exit cannot be intercepted by Python
    BaseException, finally blocks or caller code. No OS mutation at import.
    """
    if not started_as_root:
        return
    verified = False
    try:
        verified = verify_unprivileged() is True
    except BaseException:
        pass
    if not verified:
        os._exit(77)




class OneShotRunner:
    def __init__(self, plan, *, launcher=None, verify_activation=None, clock=time.monotonic):
        self.plan=plan
        self.launcher=launcher
        self.verify_activation=verify_activation
        self.clock=clock
        self.used=False

    def run(self, *, activated=False, approval=None):
        # Snapshot the original authority BEFORE any user-controlled verifier,
        # clock or launcher callback is invoked. An early refusal must not
        # return control to an untrusted Python caller still running as root.
        started_as_root = os.geteuid() == 0
        try:
            return self._run_checked(
                activated=activated, approval=approval,
                started_as_root=started_as_root)
        finally:
            _require_unprivileged_or_failstop(started_as_root)

    def _run_checked(self, *, activated, approval, started_as_root):
        if self.used:
            return "BLOCKED_REPLAY"
        self.used=True  # even a failed authorization consumes this object
        if (activated is not True or
                validate_plan(self.plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED" or
                not callable(self.verify_activation) or self.launcher is None or
                self.verify_activation(self.plan, approval) is not True):
            return "BLOCKED_DISABLED_OR_UNAPPROVED"
        deadline=self.clock()+240
        cleanup_cutoff=deadline-60
        channel=None
        status="BLOCKED_SUPERVISION_FAILURE"
        try:
            channel=self.launcher.launch(self.plan,deadline,cleanup_cutoff)
            # Do not execute ANY controller work if a supplied launcher
            # returned without proving the root-to-unprivileged transition.
            _require_unprivileged_or_failstop(started_as_root)
            outcome=control(
                self.plan, RemoteIO(channel,self.plan,clock=self.clock),self.clock,
                absolute_deadline=deadline,cleanup_cutoff=cleanup_cutoff)
            status=outcome.receipt()
        except BaseException:
            # A failed launcher may have retained root. Never proceed to
            # parent audit or return a status before this check.
            _require_unprivileged_or_failstop(started_as_root)
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
                 context_factory=multiprocessing.get_context,
                 transport_pair_factory=socket_channel_pair, clock=time.monotonic):
        started_as_root = os.geteuid() == 0
        try:
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
            if not callable(transport_pair_factory):
                raise RunnerDenied("MISSING_BOUNDED_IPC_TRANSPORT")
            self.transport_pair_factory=transport_pair_factory
            self.clock=clock
            self.child=None
            self.parent_observer=None
            self.parent_resources=None

        except BaseException:
            # Constructor denial is part of privileged bootstrap, not a
            # recoverable error for an untrusted original root caller.
            if started_as_root:
                # No guardian exists during constructor validation.
                os._exit(76)
            raise RunnerDenied("GUARDIAN_INITIALIZATION_REFUSED") from None

    def launch(self, plan, deadline, cleanup_cutoff=None):
        # The first effectful privileged preparation step is INSIDE this
        # failure boundary. None of the backend/observer/context/socket/process
        # operations may raise back to an original root caller.
        started_as_root = os.geteuid() == 0
        parent = None
        child = None
        attempted_spawn = False
        try:
            if (self.child is not None or not callable(self.post_observer_factory)
                    or self.root_check()!=0 or
                    validate_plan(plan)!="OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED" or
                    type(deadline) not in (int,float) or
                    type(cleanup_cutoff) not in (int,float) or
                    deadline-cleanup_cutoff!=60 or
                    not self.clock()<cleanup_cutoff<deadline<=self.clock()+240):
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
            if self.clock() >= cleanup_cutoff:
                raise RunnerDenied("BOOTSTRAP_CONSUMED_WORK_WINDOW")
            # Preflight uses the privileged bootstrap; after the drop every
            # post-guardian observation passes through an independent read-only
            # broker and checks real unprivileged controller identity.
            self.parent_observer=KernelReadback(plan,read=read_only,clock=self.clock)
            self.parent_observer.baseline=observer.baseline
            self.parent_observer.versions=observer.versions
            self.parent_resources=resources
            ctx=self.context_factory("fork")
            # A single AF_UNIX SOCK_STREAM framing contract replaces
            # multiprocessing.Connection entirely. Both sides are nonblocking,
            # and every transaction has an absolute monotonic deadline.
            pair=self.transport_pair_factory(clock=self.clock)
            if not isinstance(pair,tuple) or len(pair)!=2:
                # A faulty injected factory can return one partially-created
                # endpoint. Close that bounded known handle before fail-stop;
                # the real socket factory closes its own handles on errors.
                if isinstance(pair,tuple) and len(pair)<=2:
                    for endpoint in pair:
                        try:
                            if callable(getattr(endpoint,"close",None)):
                                endpoint.close()
                        except BaseException:
                            pass
                raise RunnerDenied("INVALID_BOUNDED_IPC_PAIR")
            parent,child=pair
            if parent is None or child is None or parent is child:
                raise RunnerDenied("INVALID_BOUNDED_IPC_ENDPOINTS")
            # The child holds the backend; the controller never receives root I/O.
            def child_main():
                interrupted=[False]
                exit_code=13
                try:
                    parent.close()
                    os.setsid()  # separate session is NOT a CI job survival guarantee
                    command,work,resources=self.backend_factory(plan)
                    core=GuardianCore(plan,command=command,work=work,resources=resources,
                                      clock=self.clock)
                    installed_signal_abort(lambda: interrupted.__setitem__(0,True))
                    state=GuardianChannel(core,clock=self.clock).serve(
                        child,end=deadline,cleanup_cutoff=cleanup_cutoff)
                    # Zero is possible ONLY after normal verified guardian lifecycle.
                    # It is still not trusted kernel evidence or Probe A PASS.
                    if interrupted[0] or state==LIFECYCLE_CANCELLED:
                        exit_code=10
                    elif state==LIFECYCLE_DEADLINE:
                        exit_code=11
                    elif state==LIFECYCLE_INCOMPLETE:
                        exit_code=12
                    elif state==LIFECYCLE_COMPLETE:
                        exit_code=0
                except BaseException:
                    # Includes rogue SystemExit(0): exceptions cannot forge a
                    # normal lifecycle. Never expose raw exception content.
                    exit_code=13
                finally:
                    try:
                        child.close()
                    except BaseException:
                        exit_code=13
                if exit_code:
                    raise SystemExit(exit_code) from None
            process=ctx.Process(target=child_main,daemon=False,name="p2a-owned-guardian")
            if self.clock() >= cleanup_cutoff:
                raise RunnerDenied("BOOTSTRAP_CONSUMED_WORK_WINDOW")
            # A failed process.start may have forked before throwing: treat
            # that outcome as uncertain and always hard-stop the bootstrap.
            attempted_spawn = True
            process.start()
            self.child=process
            child.close()
            # Bootstrap privilege must be irreversibly dropped BEFORE the
            # root guardian channel reaches the controller. Never allow
            # parent-side sudo as an alternate firewall mutation boundary.
            if self.controller_drop() is not True:
                raise RunnerDenied("CONTROLLER_DROP_UNCONFIRMED")
            # The launcher must independently read /proc/self/status AFTER
            # the injected drop callback, BEFORE returning root guardian IPC.
            # No injectable verification callback is accepted here.
            if verify_unprivileged() is not True:
                raise RunnerDenied("CONTROLLER_IDENTITY_UNVERIFIED")
            if self.clock() >= cleanup_cutoff:
                raise RunnerDenied("WORK_WINDOW_EXPIRED_AFTER_DROP")
            return parent
        except BaseException:
            # An aborted bootstrap cannot produce trusted cleanup evidence.
            # Close only endpoints which demonstrably exist. After a fork,
            # EOF allows the separately running guardian to own its cleanup;
            # before a fork there is no guardian to audit.
            try:
                for endpoint in (parent,child):
                    if endpoint is not None:
                        try:
                            endpoint.close()
                        except BaseException:
                            pass
            finally:
                if started_as_root or attempted_spawn:
                    # 76 = root preparation failed before any fork attempt.
                    # 77 = guardian start attempted/uncertain, may need EOF
                    # recovery by the independent child. Neither is a
                    # cleanup result or post-guardian audit.
                    os._exit(77 if attempted_spawn else 76)
            raise RunnerDenied("GUARDIAN_BOOTSTRAP_ABORTED") from None

    def wait_for_exit(self, *, deadline):
        if self.child is None:
            raise RunnerDenied("NOT_STARTED")
        remaining=max(0,deadline-self.clock())
        self.child.join(timeout=remaining)
        if self.child.is_alive():
            return "BLOCKED_GUARDIAN_STILL_ALIVE"
        exit_code=self.child.exitcode
        if exit_code==0:
            return "GUARDIAN_EXITED_NEEDS_EXTERNAL_KERNEL_READBACK"
        if exit_code==10 or exit_code == -15:
            return "BLOCKED_GUARDIAN_CANCELLED"
        if exit_code==11:
            return "BLOCKED_GUARDIAN_DEADLINE"
        if exit_code==12:
            return "BLOCKED_GUARDIAN_CLEANUP_UNVERIFIED"
        return "BLOCKED_GUARDIAN_UNEXPECTED_FAILURE"


    def verify_after(self, plan, deadline):
        """Read fresh evidence AFTER the separate guardian is reaped.

        This is a separate observer from the guardian, not a cryptographic
        attestation or qualified human/security review.
        """
        if (self.child is None or self.parent_observer is None or
                self.parent_resources is None or plan!=self.parent_observer.plan):
            return "BLOCKED_NO_INDEPENDENT_BASELINE"
        lifecycle=self.wait_for_exit(deadline=deadline)
        if lifecycle!="GUARDIAN_EXITED_NEEDS_EXTERNAL_KERNEL_READBACK":
            return lifecycle
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

def reviewed_boundary_factory(plan, *, attestor, containment=None,
                              privileged_command_capture=None):
    """Concrete low-level wiring, effectful ONLY when guardian explicitly runs.

    Every firewall command must cross RestrictedHost's exact argv gate. The
    client has a separate exact UID/argv gate and independent procfs checks.
    """
    from probe_a_os_boundary import RestrictedHost, bounded_process
    from probe_a_workload import FixedWorkload
    from probe_a_client_process import ClientProcess
    from probe_a_resources import LocalResourceReadback
    from probe_a_containment import CgroupV2Containment

    if attestor is None or attestor.verify() is not True:
        raise RunnerDenied("UNPINNED_EXECUTION_BOUNDARY")
    if (not isinstance(containment,CgroupV2Containment)
            or containment.plan != plan or not containment.armed):
        raise RunnerDenied("ATOMIC_PROCESS_CONTAINMENT_NOT_APPROVED")
    if not callable(privileged_command_capture):
        raise RunnerDenied("PRIVILEGED_COMMAND_CONTAINMENT_NOT_APPROVED")
    def guarded_command(argv,seconds):
        if attestor.verify() is not True:
            raise RunnerDenied("HOST_DRIFT_BEFORE_COMMAND")
        reply=bounded_process(
            argv,seconds,reviewed_plan=plan,
            privileged_capture=privileged_command_capture)
        if attestor.verify() is not True:
            raise RunnerDenied("HOST_DRIFT_AFTER_COMMAND")
        return reply
    restricted=RestrictedHost(plan,call=guarded_command)
    command=lambda argv,deadline: restricted.execute(argv,deadline=deadline)
    client=ClientProcess(plan,stream=containment.capture,containment=containment)
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
