"""Final Probe A guardian scheduling and OS privilege gates: offline-only.

All IPC, time, processes, procfs, and kernel readbacks are synthetic. Tests
must NEVER spawn a subprocess, run a privileged command, or claim live proof.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "docs/security/phase2l"))
from probe_a_guardian import GuardianChannel, GuardianCore
from probe_a_runner import ForkGuardianLauncher, OneShotRunner, RunnerDenied
from probe_a_exec_adapter import Reply
from test_phase2l_probe_a_runtime import P, BASE, FakeKernel, FakeReader, MockResources, MockWork
from probe_a_kernel import normalize_snapshot


SAFE_STATUS = (
    "Uid:\t65534 65534 65534 65534\n"
    "Gid:\t65534 65534 65534 65534\nGroups:\t\n"
    "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
    "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
    "CapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
)


class Clock:
    def __init__(self, t=185.0):
        self.t=float(t)
    def __call__(self):
        return self.t
    def advance(self, seconds):
        self.t += max(0.01, float(seconds))


class Link:
    def __init__(self, clock, *, first=None, eof_after=8):
        self.clock=clock
        self.first=first
        self.eof_after=eof_after
        self.polls=0
        self.closed=False
        self.replies=[]
    def poll(self, timeout):
        self.polls += 1
        if self.first is not None:
            return True
        if self.eof_after is not None and self.polls >= self.eof_after:
            return True
        self.clock.advance(max(timeout, 0.02))
        return False
    def recv_bytes(self, maxsize):
        if self.first is not None:
            msg=self.first
            self.first=None
            return msg
        raise EOFError()
    def send_bytes(self, payload):
        self.replies.append(json.loads(payload))
    def close(self):
        self.closed=True


class ScriptedCleanup:
    """No kernel access; always returns False, never any trusted PASS."""
    def __init__(self, clock, sequence):
        self.clock=clock
        self.sequence=list(sequence)
        self.cleanup_state="NOT_STARTED"
        self.calls=[]
        self.plan=P
        self.writes=[]
    def cleanup(self, deadline):
        self.calls.append(self.clock())
        next_state=self.sequence.pop(0) if self.sequence else self.cleanup_state
        if next_state=="INTERRUPT":
            self.cleanup_state="IN_PROGRESS"
            raise KeyboardInterrupt("synthetic")
        self.cleanup_state=next_state
        return False
    def handle(self, method, arg, deadline):
        if method=="cleanup":
            return self.cleanup(deadline)
        if method in ("snapshot", "cleanup_readback", "stop"):
            return False
        raise AssertionError("work after recovery is forbidden")


class SupervisionSchedulingTests(unittest.TestCase):
    def test_partial_and_blocked_state_are_retried_during_cleanup_reserve(self):
        clock=Clock(185)
        core=ScriptedCleanup(clock,["PARTIAL","BLOCKED","POST_AUDIT_REQUIRED"])
        link=Link(clock,eof_after=12)
        GuardianChannel(core,clock=clock,sleep=clock.advance).serve(link,end=240)
        self.assertEqual(len(core.calls),3)
        self.assertTrue(all(180<=x<240 for x in core.calls))
        self.assertTrue(all(b-a >= 0.5 for a,b in zip(core.calls,core.calls[1:])))
        self.assertEqual(core.cleanup_state,"POST_AUDIT_REQUIRED")
        self.assertTrue(link.closed)

    def test_cleanup_resumes_after_interrupt_and_controller_eof(self):
        clock=Clock(10)
        core=ScriptedCleanup(clock,["INTERRUPT","PARTIAL","POST_AUDIT_REQUIRED"])
        link=Link(clock,first=b'not-json',eof_after=1)
        GuardianChannel(core,clock=clock,sleep=clock.advance).serve(link,end=240)
        self.assertEqual(len(core.calls),3)
        self.assertEqual(core.cleanup_state,"POST_AUDIT_REQUIRED")
        self.assertTrue(link.closed)
        self.assertFalse(core.writes)

    def test_explicit_cleanup_rpc_does_not_disable_recovery_loop(self):
        clock=Clock(10)
        request=json.dumps({"method":"cleanup","value":None,"deadline":220}).encode()
        core=ScriptedCleanup(clock,["PARTIAL","POST_AUDIT_REQUIRED"])
        link=Link(clock,first=request,eof_after=12)
        GuardianChannel(core,clock=clock,sleep=clock.advance).serve(link,end=240)
        self.assertEqual(len(core.calls),2)
        self.assertEqual(core.cleanup_state,"POST_AUDIT_REQUIRED")
        self.assertEqual(link.replies,[{"ok":True,"value":False}])
        self.assertTrue(link.closed)

    def test_exhausted_deadline_does_not_run_mutations_after_expiry(self):
        clock=Clock(239.8)
        core=ScriptedCleanup(clock,["BLOCKED"])
        link=Link(clock,eof_after=None)
        GuardianChannel(core,clock=clock,sleep=clock.advance).serve(link,end=240)
        self.assertEqual(len(core.calls),1)
        self.assertLess(core.calls[0],240)
        self.assertEqual(core.cleanup_state,"BLOCKED")
        self.assertTrue(link.closed)
        self.assertFalse(core.writes)

    def test_retry_invokes_fresh_kernel_reads_and_never_repeats_journaled_write(self):
        clock=Clock(185)
        kernel=FakeKernel(9)
        host=FakeReader(kernel)
        class StopAfterSecond(MockWork):
            def stop(self, deadline):
                self.stops+=1
                return self.stops > 1
        core=GuardianCore(P,command=host,work=StopAfterSecond(),
                          resources=MockResources(),clock=clock)
        core.started=True
        core.baseline=(normalize_snapshot(BASE,family="ipv4"),
                       normalize_snapshot(BASE,family="ipv6"))
        core.observer.baseline=core.baseline
        link=Link(clock,eof_after=12)
        GuardianChannel(core,clock=clock,sleep=clock.advance).serve(link,end=240)
        self.assertEqual(core.cleanup_state,"POST_AUDIT_REQUIRED")
        self.assertEqual(kernel.snapshot(240),(BASE,BASE))
        writes=kernel.writes
        self.assertEqual(len(writes),len(set(writes)))
        self.assertTrue(writes)
        saves=[x for x in host.commands if x[0].endswith("tables-save")]
        self.assertGreater(len(saves),len(writes))
        self.assertFalse(core.receipts["watchdog_absent"])
        self.assertTrue(link.closed)


class FakeConn:
    def __init__(self):
        self.closed=False
    def close(self):
        self.closed=True


class FakeContext:
    def Pipe(self, duplex=True):
        self.parent=FakeConn()
        self.child=FakeConn()
        return self.parent,self.child
    def Process(self, **kwargs):
        class Process:
            def start(self):
                self.started=True
        self.process=Process()
        self.process.started=False
        return self.process


class PrivilegeGateTests(unittest.TestCase):
    def launcher(self, *, drop, clock=lambda:1):
        fake=FakeContext()
        events=[]
        def backend(plan):
            events.append("preflight")
            return FakeReader(FakeKernel(0)),MockWork(),MockResources()
        def wrapped_drop():
            events.append("drop")
            return drop()
        launcher=ForkGuardianLauncher(
            backend_factory=backend,
            post_observer_factory=lambda plan:lambda argv,deadline:Reply(0,""),
            controller_drop=wrapped_drop,
            root_check=lambda:0,
            context_factory=lambda mode:fake,
            clock=clock
        )
        return launcher,fake,events

    def test_success_callback_without_real_identity_is_denied_and_channel_closed(self):
        runner,ctx,events=self.launcher(drop=lambda:True)
        with patch("probe_a_privilege.Path.read_text",
                   return_value=SAFE_STATUS.replace("65534 65534 65534 65534",
                                                    "0 0 0 0",1)):
            with self.assertRaises(RunnerDenied):
                runner.launch(P,200)
        self.assertTrue(ctx.process.started)
        self.assertTrue(ctx.parent.closed)
        self.assertTrue(ctx.child.closed)
        self.assertEqual(events,["preflight","drop"])

    def test_capabilities_and_gid_mismatch_fail_closed(self):
        mismatches=(
            SAFE_STATUS.replace("CapEff:\t0000000000000000",
                                "CapEff:\t0000000000000001"),
            SAFE_STATUS.replace("Gid:\t65534 65534 65534 65534",
                                "Gid:\t65534 0 65534 65534"),
            SAFE_STATUS.replace("NoNewPrivs:\t1","NoNewPrivs:\t0"),
        )
        for status in mismatches:
            with self.subTest(status=status.splitlines()[0]):
                runner,ctx,_=self.launcher(drop=lambda:True)
                with patch("probe_a_privilege.Path.read_text",return_value=status):
                    with self.assertRaises(RunnerDenied):
                        runner.launch(P,200)
                self.assertTrue(ctx.parent.closed)
                self.assertTrue(ctx.child.closed)

    def test_false_or_raising_drop_never_exposes_channel_even_if_status_claims_safe(self):
        for drop in (lambda:False, lambda:None,
                     lambda:(_ for _ in ()).throw(RuntimeError("synthetic"))):
            runner,ctx,_=self.launcher(drop=drop)
            with patch("probe_a_privilege.Path.read_text",return_value=SAFE_STATUS):
                with self.assertRaises(RunnerDenied):
                    runner.launch(P,200)
            self.assertTrue(ctx.parent.closed)
            self.assertTrue(ctx.child.closed)

    def test_verifier_uses_os_status_only_after_drop_before_return(self):
        events=[]
        runner,ctx,order=self.launcher(drop=lambda:events.append("drop") or True)
        def verify_file(*args, **kwargs):
            self.assertEqual(events,["drop"])
            self.assertFalse(ctx.parent.closed)
            events.append("read-proc")
            return SAFE_STATUS
        with patch("probe_a_privilege.Path.read_text",side_effect=verify_file):
            parent=runner.launch(P,200)
        self.assertIs(parent,ctx.parent)
        self.assertEqual(events,["drop","read-proc"])
        self.assertEqual(order,["preflight","drop"])
        self.assertFalse(parent.closed)

    def test_one_shot_launcher_failure_still_requests_independent_post_audit(self):
        calls=[]
        class FailLauncher:
            def launch(self,*a):
                calls.append("launch")
                raise RunnerDenied("synthetic")
            def verify_after(self,*a):
                calls.append("post-audit")
                return "BLOCKED_POST_RESTORE_UNVERIFIED"
        runner=OneShotRunner(P,launcher=FailLauncher(),verify_activation=lambda p,a:True,
                             clock=lambda:1)
        receipt=runner.run(activated=True,approval="synthetic")
        self.assertEqual(calls,["launch","post-audit"])
        self.assertIn("BLOCKED_SUPERVISION_FAILURE",receipt)
        self.assertNotIn("=PASS",receipt)


if __name__=="__main__":
    unittest.main()
