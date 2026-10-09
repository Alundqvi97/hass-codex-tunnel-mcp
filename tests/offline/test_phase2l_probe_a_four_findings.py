"""Four-source-finding adversarial regressions: entirely injected/offline.

No elevated subprocess, firewall, signal, network call, cgroup or VM runs.
Injected successes MUST NOT count as actual OS/kernel evidence.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))

from probe_contract import compile_plan
from probe_a_privilege import drop_controller, PrivilegeDenied, NativeCapabilityOps
from probe_a_controller import control, Outcome
from probe_a_runner import OneShotRunner, ForkGuardianLauncher, RunnerDenied
from probe_a_guardian import GuardianChannel, GuardianDenied
from probe_a_stream import capture, StreamFailure, _owns_unreaped_session
from probe_a_os_boundary import bounded_process, HostBlocked
from probe_a_exec_adapter import Reply
from test_phase2l_probe_a_runtime import FakeKernel, FakeReader, MockWork, MockResources
from test_phase2l_probe_a_final_supervision import (
    Clock, ScriptedCleanup, SAFE_STATUS
)

PLAN=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")


class CapabilityOps:
    def __init__(self, *, present=(0,8,10), fail=None, threads=1, last=10):
        self.present=set(present)
        self.events=[]
        self.fail=fail
        self.threads=threads
        self.last=last
    def _ok(self,name):
        self.events.append(name)
        if name==self.fail: raise PermissionError("synthetic EPERM")
        return True
    def thread_count(self):
        self.events.append("threads")
        return self.threads
    def last_capability(self):
        self.events.append("last")
        return self.last
    def no_new_privs(self):return self._ok("nnp")
    def clear_ambient(self):return self._ok("ambient")
    def bounding_member(self,c):
        self.events.append(("read",c))
        return c in self.present
    def drop_bounding(self,c):
        self._ok(("drop",c))
        self.present.discard(c)
        return True
    def clear_process_sets(self):return self._ok("capset")


def simulated_drop(ops, *, verify=None, setgroups=None, setgid=None, setuid=None):
    sequence=ops.events
    return drop_controller(
        capability_ops=ops,getuid=lambda:0,
        setgroups=setgroups or (lambda value:sequence.append("groups")),
        setgid=setgid or (lambda *values:sequence.append("gid")),
        setuid=setuid or (lambda *values:sequence.append("uid")),
        verify=verify or (lambda *a:sequence.append("verify") or True))


class BoundingCapabilityTests(unittest.TestCase):
    def test_nonzero_initial_capabilities_dropped_before_gid_and_uid(self):
        ops=CapabilityOps(present=(0,8,10))
        self.assertTrue(simulated_drop(ops))
        self.assertEqual(ops.present,set())
        self.assertEqual([v for v in ops.events if isinstance(v,tuple) and v[0]=="drop"],
                         [("drop",0),("drop",8),("drop",10)])
        self.assertLess(ops.events.index("nnp"),ops.events.index(("drop",0)))
        self.assertLess(ops.events.index(("drop",10)),ops.events.index("groups"))
        self.assertLess(ops.events.index("groups"),ops.events.index("gid"))
        self.assertLess(ops.events.index("gid"),ops.events.index("uid"))
        self.assertLess(ops.events.index("uid"),ops.events.index("capset"))
        self.assertLess(ops.events.index("capset"),ops.events.index("verify"))

    def test_insufficient_setpcap_denies_before_credentials_change(self):
        ops=CapabilityOps(fail=("drop",8))
        with self.assertRaises(PrivilegeDenied):
            simulated_drop(ops)
        self.assertNotIn("groups",ops.events)
        self.assertNotIn("uid",ops.events)
        self.assertNotIn("verify",ops.events)

    def test_partial_failures_never_verify_success(self):
        for step in ("nnp","ambient",("drop",0),"capset"):
            with self.subTest(step=step):
                ops=CapabilityOps(fail=step)
                with self.assertRaises(PrivilegeDenied):
                    simulated_drop(ops)
                self.assertNotIn("verify",ops.events)

    def test_unreviewed_capability_number_and_multithreading_block(self):
        for kwargs in ({"last":64},{"threads":2}):
            ops=CapabilityOps(**kwargs)
            with self.assertRaises(PrivilegeDenied):
                simulated_drop(ops)
            self.assertNotIn("nnp",ops.events)
        self.assertFalse(hasattr(NativeCapabilityOps,"permit_capability_reattach"))

    def test_identity_syscall_error_and_bad_final_evidence_block(self):
        ops=CapabilityOps()
        def bad_gid(*values):
            raise OSError("synthetic error")
        with self.assertRaises(PrivilegeDenied):
            simulated_drop(ops,setgid=bad_gid)
        self.assertNotIn("capset",ops.events)
        ops=CapabilityOps()
        with self.assertRaises(PrivilegeDenied):
            simulated_drop(ops,verify=lambda *a:False)
        self.assertEqual(ops.events[-1],"capset")

    def test_native_capability_syscall_failures_are_checked_without_syscalls(self):
        native=NativeCapabilityOps()
        with patch.object(native,"_prctl",return_value=-1):
            # Native wrappers compare exact success and cannot promote -1.
            self.assertFalse(native.no_new_privs())
            self.assertFalse(native.clear_ambient())
            self.assertFalse(native.drop_bounding(8))
        with patch("probe_a_privilege.ctypes.CDLL",side_effect=OSError("no libcap")):
            with self.assertRaises(PrivilegeDenied):
                native.clear_process_sets()


class DeadlineTests(unittest.TestCase):
    def test_one_runner_deadline_is_not_extended_by_launcher_time(self):
        clock=Clock(0)
        seen=[]
        class Launcher:
            def launch(self,plan,end,cutoff):
                seen.append(("launch",end,cutoff))
                clock.advance(70)
                return SimpleNamespace(close=lambda:None)
            def verify_after(self,plan,end):
                seen.append(("audit",end))
                return "BLOCKED_POST_RESTORE_UNVERIFIED"
        with patch("probe_a_runner.control") as controller:
            controller.side_effect=lambda *args,**kw: (
                seen.append(("controller",kw["absolute_deadline"],kw["cleanup_cutoff"],clock()))
                or Outcome("SYNTHETIC_OR_ADAPTER_REPORTED_COMPLETE_NOT_ATTESTED",0,0,0))
            runner=OneShotRunner(PLAN,launcher=Launcher(),
                                 verify_activation=lambda *a:True,clock=clock)
            receipt=runner.run(activated=True,approval="fixture")
        self.assertEqual(seen,[("launch",240.0,180.0),
                               ("controller",240.0,180.0,70.0),
                               ("audit",240.0)])
        self.assertNotIn("=PASS",receipt)

    def test_expired_work_window_never_starts_setup(self):
        clock=Clock(185)
        actions=[]
        class FakeIO:
            def preflight(self,plan):actions.append("preflight");return True
            def stop(self,deadline):actions.append("stop");return True
            def cleanup(self,*a):actions.append("cleanup");return False
            def cleanup_readback(self,*a):return False
        result=control(PLAN,FakeIO(),clock,absolute_deadline=240,cleanup_cutoff=180)
        self.assertNotIn("preflight",actions)
        self.assertEqual(actions,["stop","cleanup"])
        self.assertTrue(result.label.startswith("BLOCKED"))
        self.assertEqual(control(PLAN,FakeIO(),clock,
            absolute_deadline=240,cleanup_cutoff=181).label,"BLOCKED_ABSOLUTE_DEADLINE")

    def test_launcher_expired_during_preflight_never_starts_guardian(self):
        clock=Clock(0)
        process_started=[]
        class Context:
            def Pipe(self,**kw):
                process_started.append("pipe")
                raise AssertionError("expired work window must not create IPC")
        def post_reader(plan):
            clock.advance(185)
            return lambda *a:Reply(0,"")
        launcher=ForkGuardianLauncher(
            backend_factory=lambda plan:(FakeReader(FakeKernel(0)),MockWork(),MockResources()),
            post_observer_factory=post_reader,controller_drop=lambda:True,
            root_check=lambda:0,context_factory=lambda *_:Context(),clock=clock)
        with self.assertRaises(RunnerDenied):
            launcher.launch(PLAN,240,180)
        self.assertEqual(process_started,[])

    def test_guardian_rejects_inconsistent_absolute_cleanup_cutoff(self):
        core=ScriptedCleanup(Clock(0),["POST_AUDIT_REQUIRED"])
        with self.assertRaises(GuardianDenied):
            GuardianChannel(core,clock=lambda:1).serve(
                SimpleNamespace(),end=240,cleanup_cutoff=179)


class FloodTests(unittest.TestCase):
    def test_expensive_snapshot_flood_stops_at_recovery_cutoff(self):
        clock=Clock(178)
        class Expensive(ScriptedCleanup):
            def __init__(self):
                super().__init__(clock,["PARTIAL","POST_AUDIT_REQUIRED"])
                self.snapshots=0
            def handle(self,method,arg,deadline):
                if method=="snapshot":
                    self.snapshots+=1
                    clock.advance(4)  # consumes remaining work time
                    return ("fixture4","fixture6")
                return super().handle(method,arg,deadline)
        class Flood:
            def __init__(self):self.polls=0;self.closed=False
            def poll(self,timeout):
                self.polls+=1
                clock.advance(timeout)
                return True
            def recv_bytes(self,limit):
                return b'{"method":"snapshot","value":null,"deadline":200}'
            def send_bytes(self,data):pass
            def close(self):self.closed=True
        core=Expensive()
        link=Flood()
        GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            link,end=240,cleanup_cutoff=180)
        self.assertEqual(core.snapshots,1)
        self.assertEqual(len(core.calls),2)
        self.assertTrue(link.closed)
        self.assertLessEqual(link.polls,1)

    def test_disconnection_and_deadline_preserve_guardian_only_cleanup(self):
        clock=Clock(239.6)
        core=ScriptedCleanup(clock,["BLOCKED"])
        class Broken:
            def poll(self,timeout):raise BrokenPipeError()
            def close(self):pass
        GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            Broken(),end=240,cleanup_cutoff=180)
        self.assertEqual(len(core.calls),1)
        self.assertLess(core.calls[0],240)


class DummyPipe:
    def fileno(self):return 1543
    def close(self):pass


class DummyProcess:
    def __init__(self,*,returncode=0):
        self.pid=88222
        self.stdout=DummyPipe()
        self.returncode=returncode
        self.waited=False
        self.polls=0
    def poll(self):
        self.polls+=1
        return 0  # leader exited but descendants can retain stdout
    def wait(self,timeout):
        self.waited=True
        return self.returncode


class HungSelector:
    def __init__(self,clock):self.clock=clock
    def register(self,*args):pass
    def get_map(self):return {1543:True}
    def select(self,timeout):
        self.clock.advance(timeout)
        return []
    def close(self):pass


class ExitSelector:
    def register(self,*args):pass
    def get_map(self):
        return {} if getattr(self,"finished",False) else {1543:True}
    def select(self,t):
        self.finished=True
        return [(SimpleNamespace(fileobj=DummyPipe()),1)]
    def unregister(self,*args):self.finished=True
    def close(self):pass


class ProcessTerminationTests(unittest.TestCase):
    def test_exited_leader_with_pipe_held_by_descendants_kills_owned_group(self):
        clock=Clock(0)
        proc=DummyProcess()
        killed=[]
        with self.assertRaises(StreamFailure):
            capture(("/usr/bin/true",),1,
                    spawn=lambda *a,**kw:proc,
                    selector_factory=lambda:HungSelector(clock),clock=clock,
                    group_owner=lambda pid:True,
                    group_kill=lambda pid,sig:killed.append((pid,sig)))
        self.assertEqual(killed,[(proc.pid,__import__("signal").SIGKILL)])
        self.assertTrue(proc.waited)
        self.assertEqual(proc.polls,0)  # poll() must not reap before killpg()

    def test_detached_or_mismatched_group_must_not_signal_unowned_pgid(self):
        proc=DummyProcess()
        called=[]
        with self.assertRaises(StreamFailure):
            capture(("/usr/bin/true",),1,spawn=lambda *a,**kw:proc,
                    group_owner=lambda pid:False,
                    group_kill=lambda *a:called.append(a))
        self.assertEqual(called,[])
        self.assertFalse(_owns_unreaped_session(2,getpgid=lambda pid:pid+1,
                                               getsid=lambda pid:pid))
        self.assertTrue(_owns_unreaped_session(2,getpgid=lambda pid:pid,
                                              getsid=lambda pid:pid))

    def test_failed_kill_is_blocked_and_sanitized(self):
        clock=Clock(0)
        proc=DummyProcess()
        with self.assertRaises(StreamFailure) as e:
            capture(("/usr/bin/true",),1,spawn=lambda *a,**kw:proc,
                    selector_factory=lambda:HungSelector(clock),clock=clock,
                    group_owner=lambda pid:True,
                    group_kill=lambda *a:(_ for _ in ()).throw(PermissionError("private")))
        self.assertEqual(str(e.exception),"GROUP_TERMINATION_UNVERIFIED")
        self.assertTrue(proc.waited)

    def test_post_reap_pid_is_never_signaled_due_to_possible_reuse(self):
        proc=DummyProcess(returncode=9)
        killed=[]
        with patch("probe_a_stream.os.set_blocking"), \
             patch("probe_a_stream.os.read",return_value=b""):
            with self.assertRaises(StreamFailure) as e:
                capture(("/usr/bin/true",),1,spawn=lambda *a,**kw:proc,
                        selector_factory=ExitSelector,
                        group_owner=lambda pid:True,
                        group_kill=lambda *a:killed.append(a))
        self.assertEqual(str(e.exception),"GROUP_TERMINATION_UNVERIFIED")
        self.assertEqual(killed,[])

    def test_privileged_command_needs_separate_tree_supervisor(self):
        with patch("probe_a_os_boundary.os.geteuid",return_value=0), \
             patch("probe_a_os_boundary.capture",side_effect=AssertionError("should not run")):
            with self.assertRaises(HostBlocked) as e:
                bounded_process(PLAN.setup[0].argv,2,reviewed_plan=PLAN)
        self.assertEqual(str(e.exception),"PRIVILEGED_COMMAND_CONTAINMENT_NOT_APPROVED")
        with patch("probe_a_os_boundary.os.geteuid",return_value=0):
            fake=bounded_process(PLAN.setup[0].argv,2,reviewed_plan=PLAN,
                    privileged_capture=lambda argv,t:Reply(0,"mock-only"))
        self.assertEqual(fake.stdout,"mock-only")
        from probe_a_runner import reviewed_boundary_factory
        with self.assertRaises(RunnerDenied):
            reviewed_boundary_factory(PLAN,attestor=SimpleNamespace(verify=lambda:True))


if __name__=="__main__":
    unittest.main()
