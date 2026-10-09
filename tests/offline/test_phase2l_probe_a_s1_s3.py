"""Probe A S1-S3 adversarial tests. Offline mocks only; never spawn a process.

No firewall, NSS query, privileged operation, Linux signal or network is used.
A positive mock result is never real kernel evidence or Probe A authorization.
"""
import json
import signal
import stat
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_a_exec_adapter import Reply
from probe_a_os_boundary import (
    bounded_process, require_local_passwd_nss, HostBlocked
)
from probe_a_attestation import PINNED
from probe_a_guardian import (
    GuardianChannel, LIFECYCLE_COMPLETE, LIFECYCLE_CANCELLED,
    LIFECYCLE_DEADLINE, LIFECYCLE_INCOMPLETE, LIFECYCLE_FAULT
)
from probe_a_runner import ForkGuardianLauncher, RunnerDenied
from test_phase2l_probe_a_runtime import P, FakeKernel, FakeReader, MockWork, MockResources
from test_phase2l_probe_a_final_supervision import Clock, Link, ScriptedCleanup

GETENT=("/usr/bin/getent","passwd",str(P.uid))
PGREP=("/usr/bin/pgrep","-u",str(P.uid))


class RootExecutionBoundaryTests(unittest.TestCase):
    def test_both_root_usr_bin_commands_require_containment(self):
        for argv in (PGREP,GETENT):
            with self.subTest(argv=argv):
                with patch("probe_a_os_boundary.os.geteuid",return_value=0), \
                     patch("probe_a_os_boundary.capture",
                           side_effect=AssertionError("unsafe process launched")) as direct:
                    with self.assertRaises(HostBlocked) as error:
                        bounded_process(argv,2,reviewed_plan=P)
                self.assertEqual(str(error.exception),
                                 "PRIVILEGED_COMMAND_CONTAINMENT_NOT_APPROVED")
                direct.assert_not_called()

    def test_root_utility_uses_only_injected_contained_backend(self):
        captured=[]
        def enclosed(argv, seconds):
            captured.append((argv,seconds))
            return Reply(1 if argv==PGREP else 2,"")
        with patch("probe_a_os_boundary.os.geteuid",return_value=0), \
             patch("probe_a_os_boundary.require_local_passwd_nss",return_value=True), \
             patch("probe_a_os_boundary.capture",
                   side_effect=AssertionError("direct Popen")) as direct:
            self.assertEqual(bounded_process(PGREP,2,reviewed_plan=P,
                                               privileged_capture=enclosed).code,1)
            self.assertEqual(bounded_process(GETENT,2,reviewed_plan=P,
                                               privileged_capture=enclosed).code,2)
        self.assertEqual(captured,[(PGREP,2),(GETENT,2)])
        direct.assert_not_called()

    def test_unexpected_nonroot_caller_is_denied_even_with_capture(self):
        dispatched=[]
        with patch("probe_a_os_boundary.os.geteuid",return_value=65534):
            for argv in (PGREP,GETENT,P.setup[0].argv):
                with self.subTest(argv=argv), self.assertRaises(HostBlocked):
                    bounded_process(argv,2,reviewed_plan=P,
                                    privileged_capture=lambda *x:dispatched.append(x))
        self.assertFalse(dispatched)

    def test_nss_policy_exactly_local_files_and_root_owned(self):
        fake=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0)
        self.assertTrue(require_local_passwd_nss(
            lstat=lambda p:fake,
            read_text=lambda p:"passwd: files  # reviewed local only\n"
                               "group: files\nhosts: files dns\n"))
        self.assertIn("/etc/nsswitch.conf",PINNED)
        self.assertIn("/etc/passwd",PINNED)

    def test_unsafe_nss_services_duplicates_and_missing_policy_refused(self):
        unsafe=(
            "passwd: files systemd\n",
            "passwd: files sss\n",
            "passwd: compat\n",
            "passwd: files [NOTFOUND=return] ldap\n",
            "group: files\n",
            "passwd: files\npasswd: files\n",
            "passwd: files\npasswd: files ldap\n",
            "passwd: files\x00\n",
        )
        fake=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0)
        for cfg in unsafe:
            with self.subTest(config=repr(cfg)),self.assertRaises(HostBlocked):
                require_local_passwd_nss(read_text=lambda p,c=cfg:c,
                                         lstat=lambda p:fake)

    def test_untrusted_nss_metadata_and_unreadable_file_refused(self):
        for metadata in (
            SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0),
            SimpleNamespace(st_mode=stat.S_IFREG|0o666,st_uid=0),
            SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=1000),
        ):
            with self.subTest(mode=metadata.st_mode,uid=metadata.st_uid):
                with self.assertRaises(HostBlocked):
                    require_local_passwd_nss(read_text=lambda p:"passwd: files\n",
                                             lstat=lambda p,m=metadata:m)
        with self.assertRaises(HostBlocked):
            require_local_passwd_nss(lstat=lambda p:(_ for _ in ()).throw(OSError()),
                                     read_text=lambda p:"passwd: files\n")

    def test_nss_denial_happens_before_root_contained_command(self):
        commands=[]
        with patch("probe_a_os_boundary.os.geteuid",return_value=0), \
             patch("probe_a_os_boundary.require_local_passwd_nss",
                   side_effect=HostBlocked("NSS_EXTERNAL_PASSWD_SERVICE")):
            with self.assertRaises(HostBlocked):
                bounded_process(GETENT,2,reviewed_plan=P,
                    privileged_capture=lambda argv,t:commands.append(argv))
        self.assertEqual(commands,[])


class LifecycleTests(unittest.TestCase):
    def test_normal_lifecycle_only_after_explicit_cleanup(self):
        clock=Clock(10)
        core=ScriptedCleanup(clock,["POST_AUDIT_REQUIRED"])
        request=json.dumps({"method":"cleanup","value":None,"deadline":220}).encode()
        channel=Link(clock,first=request)
        state=GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            channel,end=240,cleanup_cutoff=180)
        self.assertEqual(state,LIFECYCLE_COMPLETE)
        self.assertEqual(len(core.calls),1)

    def test_eof_and_deadline_are_not_normal_completion(self):
        clock=Clock(10)
        cancelled=GuardianChannel(ScriptedCleanup(clock,["POST_AUDIT_REQUIRED"]),
                     clock=clock,sleep=clock.advance).serve(
                         Link(clock,eof_after=1),end=240,cleanup_cutoff=180)
        self.assertEqual(cancelled,LIFECYCLE_CANCELLED)
        clock=Clock(180)
        timed=GuardianChannel(ScriptedCleanup(clock,["POST_AUDIT_REQUIRED"]),
                     clock=clock,sleep=clock.advance).serve(
                         Link(clock,eof_after=None),end=240,cleanup_cutoff=180)
        self.assertEqual(timed,LIFECYCLE_DEADLINE)

    def test_channel_errors_and_incomplete_cleanup_are_non_normal(self):
        clock=Clock(10)
        fault=GuardianChannel(ScriptedCleanup(clock,["POST_AUDIT_REQUIRED"]),
                     clock=clock,sleep=clock.advance).serve(
                         Link(clock,first=b"bad-json"),end=240,cleanup_cutoff=180)
        self.assertEqual(fault,LIFECYCLE_FAULT)
        clock=Clock(239.8)
        incomplete=GuardianChannel(ScriptedCleanup(clock,["BLOCKED"]),
                     clock=clock,sleep=clock.advance).serve(
                         Link(clock,eof_after=None),end=240,cleanup_cutoff=180)
        self.assertEqual(incomplete,LIFECYCLE_INCOMPLETE)

    def test_poll_failure_and_interrupted_cleanup_never_return_normal(self):
        class Broken:
            def poll(self,*a):raise BrokenPipeError()
            def close(self):pass
        clock=Clock(10)
        result=GuardianChannel(ScriptedCleanup(clock,["POST_AUDIT_REQUIRED"]),
                 clock=clock,sleep=clock.advance).serve(
                     Broken(),end=240,cleanup_cutoff=180)
        self.assertEqual(result,LIFECYCLE_FAULT)
        clock=Clock(185)
        interrupted=GuardianChannel(ScriptedCleanup(clock,["INTERRUPT",
                           "POST_AUDIT_REQUIRED"]),
                 clock=clock,sleep=clock.advance).serve(
                     Link(clock,eof_after=None),end=240,cleanup_cutoff=180)
        self.assertEqual(interrupted,LIFECYCLE_FAULT)


class OfflineProcess:
    def __init__(self,target):
        self.target=target
        self.started=False
    def start(self):
        self.started=True


class OfflineContext:
    def Pipe(self,**kwargs):
        class Endpoint:
            def close(self):pass
        self.parent=Endpoint()
        self.child=Endpoint()
        return self.parent,self.child
    def Process(self,**kwargs):
        self.proc=OfflineProcess(kwargs["target"])
        return self.proc


class GuardianProcessLifecycleTests(unittest.TestCase):
    def prepare(self, *, backend_failure=False):
        ctx=OfflineContext()
        calls=[]
        def backend(plan):
            calls.append("factory")
            if backend_failure and len(calls)>=2:
                raise RuntimeError("private startup failure")
            return FakeReader(FakeKernel(0)),MockWork(),MockResources()
        launcher=ForkGuardianLauncher(backend_factory=backend,
                    post_observer_factory=lambda p:lambda *a:Reply(0,""),
                    controller_drop=lambda:True,root_check=lambda:0,
                    context_factory=lambda _:ctx,clock=lambda:1)
        with patch("probe_a_runner.verify_unprivileged",return_value=True):
            launcher.launch(P,200,140)
        self.assertTrue(ctx.proc.started)
        return ctx,launcher

    def test_startup_failure_exits_nonzero_without_raw_exception(self):
        ctx,_=self.prepare(backend_failure=True)
        with patch("probe_a_runner.os.setsid"), \
             patch("probe_a_runner.installed_signal_abort"):
            with self.assertRaises(SystemExit) as result:
                ctx.proc.target()
        self.assertEqual(result.exception.code,13)
        self.assertNotIn("private",str(result.exception))

    def test_supervision_exception_and_fake_systemexit_zero_rejected(self):
        for error in (RuntimeError("private failure"),SystemExit(0)):
            with self.subTest(error=type(error).__name__):
                ctx,_=self.prepare()
                with patch("probe_a_runner.os.setsid"), \
                     patch("probe_a_runner.installed_signal_abort"), \
                     patch("probe_a_runner.GuardianChannel.serve",side_effect=error):
                    with self.assertRaises(SystemExit) as result:
                        ctx.proc.target()
                self.assertEqual(result.exception.code,13)

    def test_only_completed_lifecycle_has_zero_exit(self):
        for state,expected in (
            (LIFECYCLE_COMPLETE,0),
            (LIFECYCLE_CANCELLED,10),
            (LIFECYCLE_DEADLINE,11),
            (LIFECYCLE_INCOMPLETE,12),
            (LIFECYCLE_FAULT,13),
        ):
            with self.subTest(state=state):
                ctx,_=self.prepare()
                with patch("probe_a_runner.os.setsid"), \
                     patch("probe_a_runner.installed_signal_abort"), \
                     patch("probe_a_runner.GuardianChannel.serve",return_value=state):
                    if expected==0:
                        self.assertIsNone(ctx.proc.target())
                    else:
                        with self.assertRaises(SystemExit) as result:
                            ctx.proc.target()
                        self.assertEqual(result.exception.code,expected)

    def test_mocked_signal_cancellation_never_exits_zero(self):
        ctx,_=self.prepare()
        with patch("probe_a_runner.os.setsid"), \
             patch("probe_a_runner.installed_signal_abort",
                   side_effect=lambda cancel:cancel()), \
             patch("probe_a_runner.GuardianChannel.serve",
                   return_value=LIFECYCLE_COMPLETE):
            with self.assertRaises(SystemExit) as result:
                ctx.proc.target()
        self.assertEqual(result.exception.code,10)

    def test_parent_differentiates_exit_causes_without_promoting_pass(self):
        launcher=ForkGuardianLauncher(backend_factory=lambda p:None,
                                      clock=lambda:1)
        for code,expected in (
            (0,"GUARDIAN_EXITED_NEEDS_EXTERNAL_KERNEL_READBACK"),
            (10,"BLOCKED_GUARDIAN_CANCELLED"),
            (11,"BLOCKED_GUARDIAN_DEADLINE"),
            (12,"BLOCKED_GUARDIAN_CLEANUP_UNVERIFIED"),
            (13,"BLOCKED_GUARDIAN_UNEXPECTED_FAILURE"),
            (-signal.SIGTERM,"BLOCKED_GUARDIAN_CANCELLED"),
            (-signal.SIGKILL,"BLOCKED_GUARDIAN_UNEXPECTED_FAILURE"),
        ):
            with self.subTest(exit_code=code):
                launcher.child=SimpleNamespace(join=lambda **kw:None,
                    is_alive=lambda:False,exitcode=code)
                self.assertEqual(launcher.wait_for_exit(deadline=240),expected)
        # Guardian failure is sufficient to block post-audit labels even if a
        # simulated observer falsely declares every host resource clean.
        launcher.child=SimpleNamespace(join=lambda **kw:None,
            is_alive=lambda:False,exitcode=13)
        launcher.parent_observer=SimpleNamespace(plan=P,
            mandatory_readbacks=lambda *a,**k:self.fail("must not audit faulty exit"))
        launcher.parent_resources=object()
        self.assertEqual(launcher.verify_after(P,240),
                         "BLOCKED_GUARDIAN_UNEXPECTED_FAILURE")


class SnapshotCutoffTests(unittest.TestCase):
    def test_snapshot_admitted_just_before_cutoff_gets_work_deadline(self):
        clock=Clock(179.8)
        class Snapshot(ScriptedCleanup):
            def __init__(self):
                super().__init__(clock,["POST_AUDIT_REQUIRED"])
                self.received=[]
            def handle(self,method,arg,deadline):
                if method=="snapshot":
                    self.received.append(deadline)
                    clock.t=deadline
                    raise TimeoutError("synthetic bounded read")
                return super().handle(method,arg,deadline)
        snapshot=Snapshot()
        wire=json.dumps({"method":"snapshot","value":None,
                          "deadline":235}).encode()
        link=Link(clock,first=wire)
        state=GuardianChannel(snapshot,clock=clock,sleep=clock.advance).serve(
            link,end=240,cleanup_cutoff=180)
        self.assertEqual(snapshot.received,[180])
        self.assertLess(snapshot.calls[0],181)
        self.assertEqual(state,LIFECYCLE_FAULT)

    def test_at_cutoff_controller_snapshot_is_not_dispatched(self):
        clock=Clock(180)
        class Probe(ScriptedCleanup):
            def handle(self,method,arg,deadline):
                if method=="snapshot":
                    self.fail_unexpected=True
                    raise AssertionError("snapshot after cutoff")
                return super().handle(method,arg,deadline)
        core=Probe(clock,["POST_AUDIT_REQUIRED"])
        req=json.dumps({"method":"snapshot","value":None,
                        "deadline":235}).encode()
        state=GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            Link(clock,first=req),end=240,cleanup_cutoff=180)
        self.assertFalse(getattr(core,"fail_unexpected",False))
        self.assertEqual(state,LIFECYCLE_DEADLINE)

    def test_snapshot_flood_never_extends_any_query_past_cutoff(self):
        clock=Clock(179.5)
        class FloodCore(ScriptedCleanup):
            def __init__(self):
                super().__init__(clock,["POST_AUDIT_REQUIRED"])
                self.read_deadlines=[]
            def handle(self,method,arg,deadline):
                if method=="snapshot":
                    self.read_deadlines.append(deadline)
                    clock.advance(0.2)
                    return ["fixture","fixture"]
                return super().handle(method,arg,deadline)
        class Flood:
            def __init__(self):
                self.closed=False
                self.polls=0
            def poll(self,t):
                clock.advance(0.1)
                self.polls+=1
                return True
            def recv_bytes(self,limit):
                return json.dumps({"method":"snapshot",
                                   "value":None,"deadline":239}).encode()
            def send_bytes(self,wire):pass
            def close(self):self.closed=True
        core=FloodCore()
        pipe=Flood()
        state=GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            pipe,end=240,cleanup_cutoff=180)
        self.assertTrue(core.read_deadlines)
        self.assertTrue(all(d<=180 for d in core.read_deadlines))
        self.assertTrue(pipe.closed)
        self.assertLessEqual(pipe.polls,2)
        self.assertEqual(state,LIFECYCLE_DEADLINE)


if __name__=="__main__":
    unittest.main()
