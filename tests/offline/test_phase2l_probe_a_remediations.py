"""Targeted F2/F3/F5 adversarial mock regressions; NEVER runs firewall commands."""
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))

from test_phase2l_probe_a_runtime import P,BASE,FakeKernel,FakeReader,MockWork,MockResources
from probe_contract import emergency_deny_commands
from probe_a_recovery import inspect_partial,recover_owned,emergency_deny_only
from probe_a_guardian import GuardianCore
from probe_a_kernel import tokens,canonical_owned_rule

class EmergencyKernel(FakeKernel):
    def perform(self,argv,deadline):
        for cmd in emergency_deny_commands(P):
            if argv==cmd.argv:
                self.writes.append(argv)
                if argv==self.fail:
                    return False
                remove=canonical_owned_rule(("-A",P.chain4)+argv[5:],
                                            chain=P.chain4,ipv6=False)
                for i,rule in enumerate(self.rules["ipv4"]):
                    if canonical_owned_rule(tokens(rule),chain=P.chain4,ipv6=False)==remove:
                        del self.rules["ipv4"][i]
                        return True
                return False
        return super().perform(argv,deadline)

class RemediationSafetyTests(unittest.TestCase):
    def test_deny_only_removes_all_allows_but_keeps_both_uid_hooks(self):
        m=EmergencyKernel(9)
        attempted=[]
        outcome,writes=emergency_deny_only(P,(BASE,BASE),snapshot=m.snapshot,
                execute=m.perform,deadline=20,clock=lambda:1,on_attempt=attempted.append)
        self.assertEqual(outcome,"DENY_ONLY_OWNER_HOOKS_RETAINED_NOT_LIVE_ATTESTED")
        self.assertEqual(tuple(attempted),writes)
        v4,v6=inspect_partial(P,(BASE,BASE),m.snapshot(20))
        self.assertEqual(v4.rules,1)
        self.assertTrue(v4.hook)
        self.assertTrue(v6.hook)
        self.assertEqual(m.rules["ipv4"],["-A "+P.chain4+" -j REJECT"])

    def test_emergency_refuses_partial_dual_family_setup(self):
        for n in (0,3,5,6):
            m=EmergencyKernel(n)
            result,writes=emergency_deny_only(P,(BASE,BASE),snapshot=m.snapshot,
                        execute=m.perform,deadline=20,clock=lambda:1)
            self.assertEqual(result,"BLOCKED_EMERGENCY_UNVERIFIED")
            self.assertEqual(writes,())
            self.assertFalse(m.writes)

    def test_deny_only_does_not_retry_uncertain_prior_mutation(self):
        commands=emergency_deny_commands(P)
        m=EmergencyKernel(9,fail=commands[0].argv)
        ledger=set()
        failed,writes=emergency_deny_only(P,(BASE,BASE),snapshot=m.snapshot,
                 execute=m.perform,deadline=20,clock=lambda:1,on_attempt=ledger.add)
        self.assertEqual(failed,"BLOCKED_EMERGENCY_UNVERIFIED")
        self.assertEqual(len(writes),1)
        _,follow=emergency_deny_only(P,(BASE,BASE),snapshot=m.snapshot,
                  execute=m.perform,deadline=20,clock=lambda:1,
                  previous_attempts=ledger,on_attempt=ledger.add)
        self.assertNotIn(commands[0].argv,follow)
        self.assertEqual(m.writes.count(commands[0].argv),1)

    def test_partial_teardown_recovery_resumes_without_retrying_attempted(self):
        m=EmergencyKernel(9)
        ledger=set()
        first=P.teardown[0].argv
        def abort_after_first(argv,deadline):
            m.perform(argv,deadline)
            raise KeyboardInterrupt("after mutation before receipt")
        outcome,_=recover_owned(P,(BASE,BASE),snapshot=m.snapshot,
               execute=abort_after_first,deadline=20,clock=lambda:1,
               on_attempt=ledger.add)
        self.assertEqual(outcome,"BLOCKED_CLEANUP_UNVERIFIED")
        self.assertIn(first,ledger)
        result,writes=recover_owned(P,(BASE,BASE),snapshot=m.snapshot,
                execute=m.perform,deadline=20,clock=lambda:1,
                previous_attempts=ledger,on_attempt=ledger.add)
        # No uncertain command is replayed; fresh snapshots allow the other steps.
        self.assertEqual(result,"SYNTHETIC_RECOVERED_NOT_KERNEL_ATTESTED")
        self.assertNotIn(first,writes)
        self.assertEqual(m.writes.count(first),1)
        self.assertEqual(m.snapshot(20),(BASE,BASE))

    def test_guardian_persistent_uid_preserves_hooks_and_blocks_restoration(self):
        m=EmergencyKernel(9)
        class ProcessReader(FakeReader):
            def __call__(self,argv,deadline):
                if argv==("/usr/bin/pgrep","-u","45123"):
                    from probe_a_exec_adapter import Reply
                    return Reply(0,"4321\n")
                return super().__call__(argv,deadline)
        class StopFails(MockWork):
            def stop(self,deadline):
                self.stops+=1
                return False
        core=GuardianCore(P,command=ProcessReader(m),
                          work=StopFails(),resources=MockResources(),clock=lambda:1)
        # Preflight cannot pass while UID is already running, so the synthetic
        # worker only appears AFTER the original preflight.
        class BeforeAfter:
            def __init__(self):
                self.reader=FakeReader(m);self.running=False
            def __call__(self,argv,d):
                if self.running and argv==("/usr/bin/pgrep","-u","45123"):
                    from probe_a_exec_adapter import Reply
                    return Reply(0,"4321\n")
                return self.reader(argv,d)
        caller=BeforeAfter()
        core=GuardianCore(P,command=caller,work=StopFails(),resources=MockResources(),clock=lambda:1)
        # FakeKernel begins in fully configured state: build the trusted
        # pre-change baseline explicitly; real code only does this via preflight.
        core.started=True
        core.baseline=(BASE,BASE)
        core.observer.baseline=(BASE,BASE)
        caller.running=True
        self.assertFalse(core.cleanup(20))
        self.assertIn(core.cleanup_state,("PARTIAL","BLOCKED"))
        self.assertTrue(m.hooks["ipv4"])
        self.assertTrue(m.hooks["ipv6"])
        self.assertEqual(m.rules["ipv4"],["-A "+P.chain4+" -j REJECT"])
        self.assertNotEqual(core.receipts["watchdog_absent"],True)

if __name__=="__main__":
    unittest.main()
