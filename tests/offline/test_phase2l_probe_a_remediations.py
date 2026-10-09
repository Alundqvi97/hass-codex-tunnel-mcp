"""Targeted F2/F3/F5 adversarial mock regressions; NEVER runs firewall commands."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))

from test_phase2l_probe_a_runtime import P,BASE,FakeKernel,FakeReader,MockWork,MockResources
from probe_contract import emergency_deny_commands,emergency_barrier_command
from probe_a_recovery import inspect_partial,recover_owned,emergency_deny_only
from probe_a_guardian import GuardianCore
from probe_a_kernel import tokens,canonical_owned_rule

class EmergencyKernel(FakeKernel):
    def perform(self,argv,deadline):
        if argv==emergency_barrier_command(P).argv:
            self.writes.append(argv)
            if argv==self.fail:
                return False
            self.rules["ipv4"].insert(0,"-A "+P.chain4+" -j REJECT")
            return True
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
        self.assertEqual(v4.rules,2)
        self.assertTrue(v4.hook)
        self.assertTrue(v6.hook)
        self.assertEqual(m.rules["ipv4"],["-A "+P.chain4+" -j REJECT"]*2)

    def test_emergency_refuses_partial_dual_family_setup(self):
        for n in (0,3,5):
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
        self.assertEqual(len(writes),2)
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

    def test_cleanup_interrupted_state_resumes_without_repeating_unhook(self):
        from probe_a_kernel import normalize_snapshot
        m=EmergencyKernel(9)
        unhook=P.teardown[0].argv
        m.perform(unhook,20)
        core=GuardianCore(P,command=FakeReader(m),work=MockWork(),
                          resources=MockResources(),clock=lambda:1)
        core.started=True
        core.baseline=(normalize_snapshot(BASE,family="ipv4"),
                       normalize_snapshot(BASE,family="ipv6"))
        core.observer.baseline=core.baseline
        core.cleanup_state="IN_PROGRESS"  # synthetic SIGTERM mid-cleanup
        core.cleanup_attempts.add(unhook)  # journaled BEFORE original syscall
        self.assertFalse(core.cleanup(20))
        self.assertEqual(m.writes.count(unhook),1)
        self.assertEqual(m.snapshot(20),(BASE,BASE))
        self.assertEqual(core.cleanup_state,"POST_AUDIT_REQUIRED")
        self.assertFalse(core.receipts["watchdog_absent"])
        self.assertFalse(core.cleanup(20))
        self.assertEqual(m.writes.count(unhook),1)

    def test_emergency_barrier_is_first_and_does_not_retry_failed_dns_delete(self):
        m=EmergencyKernel(9,fail=emergency_deny_commands(P)[0].argv)
        journal=set()
        state,attempts=emergency_deny_only(P,(BASE,BASE),snapshot=m.snapshot,
                 execute=m.perform,deadline=20,clock=lambda:1,
                 on_attempt=journal.add)
        self.assertEqual(state,"BLOCKED_EMERGENCY_UNVERIFIED")
        self.assertEqual(attempts[0],emergency_barrier_command(P).argv)
        self.assertEqual(m.rules["ipv4"][0],"-A "+P.chain4+" -j REJECT")
        self.assertTrue(inspect_partial(P,(BASE,BASE),m.snapshot(20))[0].barrier)
        self.assertTrue(m.hooks["ipv6"])
        # Failed deletion is never retried, but the new first REJECT blocks
        # DNS even while later ACCEPT entries are still physically present.
        previous=len(m.writes)
        emergency_deny_only(P,(BASE,BASE),snapshot=m.snapshot,
                execute=m.perform,deadline=20,clock=lambda:1,
                previous_attempts=journal,on_attempt=journal.add)
        self.assertEqual(len(m.writes),previous)

    def test_runner_bootstrap_requires_parent_drop_before_exposing_channel(self):
        from probe_a_runner import ForkGuardianLauncher,RunnerDenied
        from probe_a_exec_adapter import Reply
        class Link:
            closed=False
            def close(self):self.closed=True
        class FakeProcess:
            def __init__(self,**kwargs):self.started=False
            def start(self):self.started=True
        class FakeContext:
            def Pipe(self,duplex=True):
                self.parent=Link();self.child=Link()
                return self.parent,self.child
            def Process(self,**kwargs):
                self.process=FakeProcess(**kwargs)
                return self.process
        fake=FakeContext()
        with self.assertRaises(RunnerDenied):
            ForkGuardianLauncher(backend_factory=lambda p:None,
                    root_check=lambda:0,context_factory=lambda _:fake).launch(P,241)
        calls=[]
        def backend(plan):
            calls.append("preflight")
            return FakeReader(EmergencyKernel(0)),MockWork(),MockResources()
        def drop():
            calls.append("drop")
            return True
        launcher=ForkGuardianLauncher(backend_factory=backend,
                   post_observer_factory=lambda plan:lambda a,d:Reply(0,""),
                   controller_drop=drop,root_check=lambda:0,
                   context_factory=lambda _:fake,clock=lambda:1)
        # Simulate the host /proc fields while exercising the real verifier.
        status=("Uid:\t65534 65534 65534 65534\n"
                "Gid:\t65534 65534 65534 65534\nGroups:\t\n"
                "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
                "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
                "CapAmb:\t0000000000000000\nNoNewPrivs:\t1\n")
        with patch("probe_a_privilege.Path.read_text",return_value=status):
            parent=launcher.launch(P,200)
        self.assertTrue(fake.process.started)
        self.assertFalse(parent.closed)
        self.assertEqual(calls,["preflight","drop"])
        self.assertTrue(fake.child.closed)

    def test_shared_canonicalizer_accepts_reject_spellings_on_both_families(self):
        from probe_a_kernel import canonical_owned_rule
        for ipv6,chain,suffix in (
                (False,P.chain4,"icmp-port-unreachable"),
                (True,P.chain6,"icmp6-port-unreachable")):
            row=("-A",chain,"-j","REJECT","--reject-with",suffix)
            self.assertEqual(canonical_owned_rule(row,chain=chain,ipv6=ipv6),
                             ("-A",chain,"-j","REJECT"))
            with self.assertRaises(Exception):
                canonical_owned_rule(row[:-1]+("icmp-admin-prohibited",),
                                     chain=chain,ipv6=ipv6) if False else self._strict_owned_format(
                                          row[:-1]+("icmp-admin-prohibited",),chain,ipv6)

    def _strict_owned_format(self,row,chain,ipv6):
        from probe_a_kernel import canonical_owned_rule
        value=canonical_owned_rule(row,chain=chain,ipv6=ipv6)
        if value!=("-A",chain,"-j","REJECT"):
            raise ValueError("unknown encoding")

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
                if argv in tuple(c.argv for c in emergency_deny_commands(P))+(emergency_barrier_command(P).argv,):
                    from probe_a_exec_adapter import Reply
                    return Reply(0 if m.perform(argv,d) else 4,"")
                return self.reader(argv,d)
        caller=BeforeAfter()
        core=GuardianCore(P,command=caller,work=StopFails(),resources=MockResources(),clock=lambda:1)
        # FakeKernel begins in fully configured state: build the trusted
        # pre-change baseline explicitly; real code only does this via preflight.
        core.started=True
        from probe_a_kernel import normalize_snapshot
        baseline=(normalize_snapshot(BASE,family="ipv4"),normalize_snapshot(BASE,family="ipv6"))
        core.baseline=baseline
        core.observer.baseline=baseline
        caller.running=True
        self.assertFalse(core.cleanup(20))
        self.assertIn(core.cleanup_state,("PARTIAL","BLOCKED"))
        self.assertTrue(m.hooks["ipv4"])
        self.assertTrue(m.hooks["ipv6"])
        self.assertEqual(m.rules["ipv4"],["-A "+P.chain4+" -j REJECT"]*2, core.cleanup_result+" "+str(m.writes))
        self.assertNotEqual(core.receipts["watchdog_absent"],True)

if __name__=="__main__":
    unittest.main()
