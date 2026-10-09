"""Failure-injection rehearsal does not launch network tools."""
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_contract import compile_plan,CLEANUP_READBACKS
from probe_rehearsal import rehearse

class Fixture:
    def __init__(self,fail_setup=None,fail_cleanup=None,fail_observer=None):
        self.plan=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")
        self.fail_setup=fail_setup
        self.fail_cleanup=fail_cleanup
        self.fail_observer=fail_observer
        self.calls=[]
        self.nsetup=0
        self.ncleanup=0
        self.nwork=0
        self.stops=0
    def issue(self,cmd):
        self.calls.append(("issue",cmd.family,cmd.phase))
        if cmd in self.plan.setup:
            pos=self.nsetup
            self.nsetup+=1
            return pos != self.fail_setup
        pos=self.ncleanup
        self.ncleanup+=1
        return pos != self.fail_cleanup
    def observe(self,key):
        self.calls.append(("readback",key))
        return key!=self.fail_observer
    def workload(self):
        self.nwork+=1
        return True
    def stop(self):
        self.stops+=1
    def readback(self,key):
        return True
    def run(self,preflight=lambda: True):
        return rehearse(self.plan,preflight=preflight,issue=self.issue,observe=self.observe,
                        workload=self.workload,stop=self.stop,cleanup_readback=self.readback)

class RehearsalTests(unittest.TestCase):
    def test_full_mock_always_nonruntime(self):
        f=Fixture();x=f.run()
        self.assertEqual(x.result,"SYNTHETIC_WORKLOAD_COMPLETE_NOT_KERNEL_PROOF")
        self.assertEqual((x.setup_attempts,x.teardown_attempts,x.workload_attempts),(len(f.plan.setup),len(f.plan.teardown),1))
        self.assertEqual(f.stops,1)
    def test_failure_at_each_setup_command_still_cleans_both_families(self):
        base=Fixture()
        for i in range(len(base.plan.setup)):
            with self.subTest(i=i):
                f=Fixture(fail_setup=i)
                x=f.run()
                self.assertEqual(x.setup_attempts,i+1)
                self.assertEqual(x.teardown_attempts,len(f.plan.teardown))
                self.assertEqual(x.workload_attempts,0)
                self.assertEqual(f.stops,1)
                self.assertIn("ipv4",[entry[1] for entry in f.calls if len(entry)==3 and entry[0]=="issue" and entry[2]=="unhook"])
                self.assertIn("ipv6",[entry[1] for entry in f.calls if len(entry)==3 and entry[0]=="issue" and entry[2]=="unhook"])
    def test_failed_dual_hook_readback_blocks_workload(self):
        f=Fixture(fail_observer="dual_stack_deny_hooks")
        x=f.run()
        self.assertEqual(x.workload_attempts,0)
        self.assertEqual(x.teardown_attempts,len(f.plan.teardown))
    def test_bad_effective_order_blocks_workload(self):
        f=Fixture(fail_observer="effective_rule_order")
        self.assertEqual(f.run().workload_attempts,0)
    def test_bad_owner_uid_blocks_workload(self):
        f=Fixture(fail_observer="exact_uid")
        self.assertEqual(f.run().workload_attempts,0)
    def test_preflight_failed_still_attempts_cleanup(self):
        f=Fixture()
        x=f.run(preflight=lambda:False)
        self.assertEqual((x.setup_attempts,x.teardown_attempts,x.workload_attempts),(0,len(f.plan.teardown),0))
    def test_partial_teardown_failure_nonzero_and_no_cleanup_short_circuit(self):
        for i in range(len(Fixture().plan.teardown)):
            with self.subTest(i=i):
                f=Fixture(fail_cleanup=i)
                x=f.run()
                self.assertEqual(x.result,"BLOCKED_TEARDOWN")
                self.assertEqual(x.teardown_attempts,len(f.plan.teardown))
    def test_missing_cleanup_readback_is_blocked(self):
        f=Fixture()
        f.readback=lambda k: False if k=="ipv6_chain_absent" else True
        self.assertEqual(f.run().result,"BLOCKED_CLEANUP_READBACK")
    def test_untrusted_exception_does_not_skip_teardown(self):
        f=Fixture()
        f.issue=lambda cmd: (_ for _ in ()).throw(RuntimeError("synthetic secret string"))
        x=f.run()
        self.assertEqual(x.result,"BLOCKED_TEARDOWN")
        self.assertEqual(x.teardown_attempts,len(f.plan.teardown))
        self.assertNotIn("synthetic secret",x.result)
    def test_no_executable_network_or_host_commands_in_rehearsal(self):
        src=(ROOT/"docs/security/phase2l/probe_rehearsal.py").read_text()
        for value in ("import subprocess","import socket","os.system(","sudo ","subprocess.Popen(","os.exec"):
            self.assertNotIn(value,src)
if __name__=="__main__":unittest.main()
