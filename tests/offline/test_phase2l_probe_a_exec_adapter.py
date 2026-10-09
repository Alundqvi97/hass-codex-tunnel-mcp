"""Mock argv and deadline gate: no command executes."""
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_contract import compile_plan
from probe_a_exec_adapter import ExactArgvGate,Reply,UnsafeCommand,RUN_LIMIT_SECONDS
PLAN=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")

class ArgvGateTests(unittest.TestCase):
    def setup_gate(self):
        emitted=[]
        def invoke(argv,limit):
            emitted.append((argv,limit))
            return Reply(0,"")
        return ExactArgvGate(PLAN,invoke=invoke),emitted
    def test_no_implicit_executor(self):
        with self.assertRaises(TypeError):
            ExactArgvGate(PLAN)
        with self.assertRaises(UnsafeCommand):
            ExactArgvGate(PLAN,invoke=None)
    def test_exact_setup_once_and_in_order(self):
        gate,emitted=self.setup_gate()
        with self.assertRaises(UnsafeCommand):
            gate.setup(PLAN.setup[1])
        for c in PLAN.setup: self.assertEqual(gate.setup(c).code,0)
        self.assertEqual(len(emitted),len(PLAN.setup))
        with self.assertRaises(UnsafeCommand):gate.setup(PLAN.setup[-1])
    def test_no_unreviewed_command(self):
        gate,_=self.setup_gate()
        from probe_contract import Command
        bad=Command("ipv4",("/usr/sbin/iptables","-F","INPUT"),"attack")
        with self.assertRaises(UnsafeCommand):gate.preflight_read(bad)
        with self.assertRaises(UnsafeCommand):gate.setup(bad)
    def test_teardown_requires_observed_ownership(self):
        gate,_=self.setup_gate()
        with self.assertRaises(UnsafeCommand):
            gate.teardown(PLAN.teardown[0],confirmed_owned=False)
        for c in PLAN.teardown:gate.teardown(c,confirmed_owned=True)
        with self.assertRaises(UnsafeCommand):gate.teardown(PLAN.teardown[-1],confirmed_owned=True)
    def test_timeout_must_be_short(self):
        gate,_=self.setup_gate()
        for value in (0,-1,RUN_LIMIT_SECONDS+1,"8",None):
            with self.assertRaises(UnsafeCommand):gate.setup(PLAN.setup[0],timeout=value)
    def test_backend_exception_sanitized_and_no_retry(self):
        secret="private-test-token"
        gate=ExactArgvGate(PLAN,invoke=lambda argv,seconds: (_ for _ in ()).throw(RuntimeError(secret)))
        with self.assertRaises(UnsafeCommand) as exc:
            gate.setup(PLAN.setup[0])
        self.assertNotIn(secret,str(exc.exception))
        with self.assertRaises(UnsafeCommand):gate.setup(PLAN.setup[0])
    def test_fake_bad_output_denied(self):
        gate=ExactArgvGate(PLAN,invoke=lambda argv,seconds:Reply(0,"x"*150000))
        with self.assertRaises(UnsafeCommand):gate.setup(PLAN.setup[0])
    def test_no_runtime_backend_or_main(self):
        s=(ROOT/"docs/security/phase2l/probe_a_exec_adapter.py").read_text()
        for bad in ("import subprocess","import socket","if __name__","os.system(","subprocess.run(","sudo -n /usr/sbin/iptables"):
            self.assertNotIn(bad,s)

if __name__=="__main__":unittest.main()
