"""Adversarial fake I/O for bounded controller — no network/kernel access."""
import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_contract import compile_plan,CLEANUP_READBACKS
from probe_a_controller import control,CASES
from test_phase2l_probe_a_protocol import BASE,snapshot

PLAN=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")

class FakeClock:
    def __init__(self): self.now=10.0
    def __call__(self):
        self.now+=0.01
        return self.now

class FakeIO:
    def __init__(self,*,bad_at=None, fail_case=None,fail_cleanup=None,bad_readback=None,fail_stop=False):
        self.bad_at=bad_at;self.fail_case=fail_case;self.fail_cleanup=fail_cleanup
        self.bad_readback=bad_readback;self.fail_stop=fail_stop
        self.n=0;self.issued=[];self.calls=[];self.complete=False
        self.hooks=set();self.rules={"ipv4":[],"ipv6":[]}
        self.counter_values={"ipv4":[[0,0,"ACCEPT"],[0,0,"ACCEPT"],[0,0,"ACCEPT"],[0,0,"REJECT"]],
                             "ipv6":[[0,0,"REJECT"]]}
        self.cleaned=False;self.running=False
    def preflight(self,plan):
        self.calls.append("preflight")
        return True
    def issue(self,cmd,deadline):
        self.calls.append("issue:"+cmd.phase)
        idx=self.n;self.n+=1;self.issued.append(cmd)
        if idx==self.bad_at:
            return False
        if cmd.phase=="hook":self.hooks.add(cmd.family)
        if cmd.phase=="allow-loopback-reply":self.complete=True
        return True
    def snapshot(self):
        self.calls.append("snapshot")
        if self.cleaned or not self.hooks:
            return (BASE,BASE)
        return (
            snapshot(PLAN,complete=self.complete,hook=("ipv4" in self.hooks)) if any(c.phase=="create" and c.family=="ipv4" for c in self.issued) else BASE,
            snapshot(PLAN,family="ipv6",complete=self.complete,hook=("ipv6" in self.hooks)) if any(c.phase=="create" and c.family=="ipv6" for c in self.issued) else BASE,
        )
    def counters(self,family):
        self.calls.append("counters:"+family)
        return tuple(tuple(x) for x in self.counter_values[family])
    def exercise(self,case,deadline):
        self.calls.append("case:"+case)
        if case==self.fail_case:return False
        mapping={name:(family,index) for name,family,index in CASES}
        family,index=mapping[case]
        self.counter_values[family][index][0]+=1
        self.counter_values[family][index][1]+=60
        return True
    def stop(self,deadline):
        self.calls.append("stop")
        return not self.fail_stop
    def cleanup(self,plan,attempted,deadline):
        self.calls.append("cleanup")
        self.cleaned=self.fail_cleanup is not True
        return self.cleaned
    def cleanup_readback(self,key,baselines,deadline):
        self.calls.append("cleanup:"+key)
        return self.cleaned and key!=self.bad_readback

class ControllerTests(unittest.TestCase):
    def run_fake(self,io=None,clock=None):
        io=io or FakeIO()
        return control(PLAN,io,clock or FakeClock()),io
    def test_success_is_not_live_attestation(self):
        x,io=self.run_fake()
        self.assertEqual(x.label,"SYNTHETIC_OR_ADAPTER_REPORTED_COMPLETE_NOT_ATTESTED")
        self.assertEqual(x.completed_cases,len(CASES))
        self.assertEqual(x.cleanup_checks,len(CLEANUP_READBACKS))
        self.assertEqual(io.calls.count("cleanup"),1)
    def test_every_failed_command_rolls_back(self):
        for i in range(len(PLAN.setup)):
            with self.subTest(i=i):
                x,io=self.run_fake(FakeIO(bad_at=i))
                self.assertEqual(x.completed_cases,0)
                self.assertIn("cleanup",io.calls)
                self.assertEqual(x.cleanup_checks,len(CLEANUP_READBACKS))
                self.assertNotIn(x.label,("PASS","VERIFIED"))
    def test_failed_client_denied_and_cleanup(self):
        for case,_,_ in CASES:
            with self.subTest(case=case):
                x,io=self.run_fake(FakeIO(fail_case=case))
                self.assertEqual(x.label,"BLOCKED_SETUP_OR_EVIDENCE")
                self.assertIn("cleanup",io.calls)
    def test_cleanup_failure_never_returns_candidate_complete(self):
        for kwargs in ({"fail_cleanup":True},{"fail_stop":True},
                       {"bad_readback":CLEANUP_READBACKS[0]},
                       {"bad_readback":CLEANUP_READBACKS[-1]}):
            x,io=self.run_fake(FakeIO(**kwargs))
            self.assertEqual(x.label,"BLOCKED_RESTORATION_UNVERIFIED")
            self.assertEqual(x.cleanup_checks,len(CLEANUP_READBACKS))
    def test_preflight_missing_does_not_run_workload(self):
        io=FakeIO()
        io.preflight=lambda p: False
        x,_=self.run_fake(io)
        self.assertEqual(x.completed_cases,0)
        self.assertFalse(any(v.startswith("case:") for v in io.calls))
        self.assertIn("cleanup",io.calls)
    def test_timing_budget_restrictions(self):
        for seconds in (0,20,119,241,100000):
            x=control(PLAN,FakeIO(),FakeClock(),budget_seconds=seconds)
            self.assertEqual(x.label,"BLOCKED_BUDGET")
    def test_timeout_before_first_preflight(self):
        class Clock:
            def __init__(self):self.v=0
            def __call__(self):
                self.v+=200
                return self.v
        x,io=self.run_fake(clock=Clock())
        self.assertNotEqual(x.label,"SYNTHETIC_OR_ADAPTER_REPORTED_COMPLETE_NOT_ATTESTED")
        self.assertEqual(x.completed_cases,0)
    def test_partial_snapshot_mismatch_blocks_workload(self):
        io=FakeIO()
        orig=io.snapshot
        def changed():
            x,y=orig()
            if io.hooks:return x+"-A OUTPUT -j OTHER\n",y
            return x,y
        io.snapshot=changed
        x,_=self.run_fake(io)
        self.assertEqual(x.completed_cases,0)
    def test_all_observers_required_and_ordered(self):
        x,io=self.run_fake()
        self.assertLess(io.calls.index("preflight"),io.calls.index("issue:create"))
        self.assertLess(io.calls.index("stop"),io.calls.index("cleanup"))
        self.assertEqual([s.removeprefix("cleanup:") for s in io.calls if s.startswith("cleanup:")],list(CLEANUP_READBACKS))
    def test_explicit_no_live_entrypoint_in_source(self):
        source=(ROOT/"docs/security/phase2l/probe_a_controller.py").read_text()
        for bad in ("import subprocess","import socket","sudo -n", "subprocess.run(", "os.system("):
            self.assertNotIn(bad,source)

if __name__=="__main__":
    unittest.main()
