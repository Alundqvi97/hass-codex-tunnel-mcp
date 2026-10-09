"""Offline-only adversarial tests: no subprocess, sockets, firewall or VM."""
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))

from probe_contract import compile_plan
from probe_a_recovery import inspect_partial, recover_owned, RecoveryDenied
from probe_a_guardian import GuardianCore, GuardianChannel, GuardianDenied
from probe_a_workload import FixedWorkload, exact_argv, peer_argv, CASES_ORDER, WorkloadDenied
from probe_a_runner import OneShotRunner
from probe_a_exec_adapter import Reply
from probe_a_client_process import ClientProcess, ClientProcessDenied
from probe_a_resources import numeric_identity, ResourceDenied

P=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")
BASE="*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
RULES4=(
    "-A "+P.chain4+" -j REJECT",
    "-A "+P.chain4+" -d 9.9.9.9/32 -p udp -m udp --dport 53 -j ACCEPT",
    "-A "+P.chain4+" -d 9.9.9.9/32 -p tcp -m tcp --dport 53 -j ACCEPT",
    "-A "+P.chain4+" -o lo -d 127.0.0.1/32 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT",
)
RULES6=("-A "+P.chain6+" -j REJECT",)

class FakeKernel:
    def __init__(self,setup_count=0, fail=None, alter=False):
        self.state=setup_count
        self.chains={"ipv4":setup_count>=1,"ipv6":setup_count>=3}
        self.rules={"ipv4":list(reversed(RULES4[:max(1,setup_count-5)])) if setup_count>=7 else ([RULES4[0]] if setup_count>=2 else []),
                    "ipv6":[RULES6[0]] if setup_count>=4 else []}
        self.hooks={"ipv4":setup_count>=5,"ipv6":setup_count>=6}
        self.fail=fail;self.alter=alter;self.writes=[]
    def render(self,fam):
        chain=P.chain4 if fam=="ipv4" else P.chain6
        extra=((":"+chain+" - [0:0]\n") if self.chains[fam] else "")
        hook=(("-A OUTPUT -m owner --uid-owner 45123 -j "+chain+"\n") if self.hooks[fam] else "")
        rules="".join(x+"\n" for x in self.rules[fam])
        if fam=="ipv4" and self.alter:rules+="-A "+chain+" -j ACCEPT\n"
        return BASE.replace("COMMIT\n",extra+hook+rules+"COMMIT\n")
    def snapshot(self,deadline):return self.render("ipv4"),self.render("ipv6")
    def perform(self,argv,deadline):
        self.writes.append(argv)
        if argv==self.fail:return False
        cmd=next((x for x in P.teardown if x.argv==argv),None)
        if cmd is None:return False
        fam=cmd.family
        if cmd.phase=="unhook":self.hooks[fam]=False
        elif "-F" in argv:self.rules[fam]=[]
        elif "-X" in argv:self.chains[fam]=False
        return True

class RecoveryTests(unittest.TestCase):
    def test_canonical_tcp_udp_matches_active_and_recovery(self):
        from probe_a_kernel import canonical_owned_rule
        for protocol in ("tcp","udp"):
            chain=P.chain4
            text=("-A",chain,"-d","9.9.9.9/32","-p",protocol,
                  "-m",protocol,"--dport","53","-j","ACCEPT")
            expected=text[:5]+text[7:]
            self.assertEqual(canonical_owned_rule(text,chain=chain,ipv6=False),expected)
            with self.assertRaises(Exception):
                canonical_owned_rule(text[:6]+("-m","icmp")+text[8:],chain=chain,ipv6=False)


    def test_all_setup_prefixes_recover_without_rerun(self):
        for n in range(10):
            with self.subTest(setup_prefix=n):
                m=FakeKernel(n)
                inspect_partial(P,(BASE,BASE),m.snapshot(10))
                result,writes=recover_owned(P,(BASE,BASE),snapshot=m.snapshot,execute=m.perform,
                                            deadline=10,clock=lambda:1)
                self.assertEqual(result,"SYNTHETIC_RECOVERED_NOT_KERNEL_ATTESTED")
                self.assertEqual(m.snapshot(10),(BASE,BASE))
                self.assertEqual(writes,tuple(m.writes))
                self.assertEqual(len(writes),len(set(writes)))
    def test_altered_owned_chain_aborts_all_writes(self):
        m=FakeKernel(9,alter=True)
        with self.assertRaises(RecoveryDenied):inspect_partial(P,(BASE,BASE),m.snapshot(10))
        outcome,writes=recover_owned(P,(BASE,BASE),snapshot=m.snapshot,execute=m.perform,deadline=10,clock=lambda:1)
        self.assertEqual(outcome,"BLOCKED_CLEANUP_UNVERIFIED")
        self.assertFalse(writes)
    def test_altered_unrelated_filter_aborts(self):
        m=FakeKernel(9)
        before=m.snapshot
        m.snapshot=lambda limit:(before(limit)[0].replace(":INPUT ACCEPT",":INPUT DROP"),before(limit)[1])
        outcome,writes=recover_owned(P,(BASE,BASE),snapshot=m.snapshot,execute=m.perform,deadline=10,clock=lambda:1)
        self.assertEqual(outcome,"BLOCKED_CLEANUP_UNVERIFIED")
        self.assertFalse(writes)
    def test_failed_unhook_not_retried_and_no_unsafe_flush(self):
        m=FakeKernel(9,fail=P.teardown[1].argv)
        outcome,writes=recover_owned(P,(BASE,BASE),snapshot=m.snapshot,execute=m.perform,deadline=10,clock=lambda:1)
        self.assertEqual(outcome,"BLOCKED_CLEANUP_UNVERIFIED")
        self.assertEqual(writes.count(P.teardown[1].argv),1)
        self.assertNotIn(P.teardown[3].argv,writes)
        self.assertNotIn(P.teardown[5].argv,writes)
    def test_timing_prevents_write(self):
        m=FakeKernel(9)
        outcome,writes=recover_owned(P,(BASE,BASE),snapshot=m.snapshot,execute=m.perform,deadline=1,clock=lambda:1)
        self.assertEqual(outcome,"BLOCKED_CLEANUP_UNVERIFIED")
        self.assertFalse(writes)

class FakeReader:
    def __init__(self,kernel):
        self.k=kernel;self.commands=[]
    def __call__(self,argv,deadline):
        self.commands.append(argv)
        if argv==("/usr/sbin/iptables","-V"):return Reply(0,"iptables v1.8.10 (nf_tables)")
        if argv==("/usr/sbin/ip6tables","-V"):return Reply(0,"ip6tables v1.8.10 (nf_tables)")
        if argv==("/usr/sbin/iptables-save","-t","filter"):return Reply(0,self.k.render("ipv4"))
        if argv==("/usr/sbin/ip6tables-save","-t","filter"):return Reply(0,self.k.render("ipv6"))
        if argv[0]=="/usr/bin/getent":return Reply(2,"")
        if argv[0]=="/usr/bin/pgrep":return Reply(1,"")
        if "-S" in argv:return Reply(1,"")
        if argv in (c.argv for c in P.setup):
            idx=[c.argv for c in P.setup].index(argv)
            if idx!=self.k.state:return Reply(4,"")
            self.k.state+=1
            self.k.chains["ipv4"]=self.k.state>=1
            self.k.chains["ipv6"]=self.k.state>=3
            self.k.hooks["ipv4"]=self.k.state>=5
            self.k.hooks["ipv6"]=self.k.state>=6
            self.k.rules["ipv6"]=[RULES6[0]] if self.k.state>=4 else []
            self.k.rules["ipv4"]=list(reversed(RULES4[:max(1,self.k.state-5)])) if self.k.state>=2 else []
            return Reply(0,"")
        if argv in (c.argv for c in P.teardown):
            return Reply(0 if self.k.perform(argv,deadline) else 4,"")
        return Reply(4,"")

class MockResources:
    def __init__(self):self.calls=[]
    def preflight(self):self.calls.append("preflight");return True
    def readback(self,key,deadline):self.calls.append(key);return True
class MockWork:
    def __init__(self):self.cases=[];self.stops=0
    def exercise(self,case,plan,deadline):self.cases.append(case);return True
    def stop(self,deadline):self.stops+=1;return True

class GuardianTests(unittest.TestCase):
    def prepare(self):
        model=FakeKernel()
        host=FakeReader(model);work=MockWork();resources=MockResources()
        core=GuardianCore(P,command=host,work=work,resources=resources,clock=lambda:1)
        return core,model,host,work
    def test_preflight_required_before_any_mutation(self):
        c,m,host,work=self.prepare()
        with self.assertRaises(GuardianDenied):c.handle("issue",P.setup[0],10)
        self.assertFalse(m.state)
        c.handle("preflight","START",10)
        with self.assertRaises(Exception):c.handle("preflight","START",10)
        with self.assertRaises(Exception):c.handle("issue",P.setup[1],10)
        self.assertEqual(m.state,0)
    def test_setup_exact_once_and_independent_partial_snapshots(self):
        c,m,host,work=self.prepare()
        self.assertTrue(c.handle("preflight","START",10))
        for command in P.setup:
            self.assertTrue(c.handle("issue",command,10))
        self.assertEqual(m.state,9)
        with self.assertRaises(Exception):c.handle("issue",P.setup[-1],10)
        self.assertFalse(work.cases)
        self.assertFalse(c.cleanup(10))  # cannot self-attest watchdog exit
        self.assertEqual(m.snapshot(10),(BASE,BASE))
        self.assertFalse(c.receipts["watchdog_absent"])
        self.assertGreater(len(host.commands),len(P.setup))
    def test_eof_forces_guardian_cleanup(self):
        c,m,host,work=self.prepare()
        c.handle("preflight","START",10)
        c.handle("issue",P.setup[0],10)
        class Dropped:
            def poll(self,seconds):return True
            def recv_bytes(self,limit):raise EOFError()
            def close(self):pass
        GuardianChannel(c,clock=lambda:1).serve(Dropped(),end=241)
        self.assertEqual(m.snapshot(10),(BASE,BASE))
        self.assertGreaterEqual(work.stops,1)
    def test_unknown_command_fails_before_write(self):
        c,m,host,work=self.prepare()
        c.handle("preflight","START",10)
        with self.assertRaises(GuardianDenied):c.handle("issue",P.teardown[0],10)
        self.assertEqual(m.state,0)

class WorkloadTests(unittest.TestCase):
    def test_fixed_order_and_response_attestation(self):
        def success(argv,d,uid,peer):
            case=argv[-3]
            value=("DNS_UDP_MATCHED_NXDOMAIN" if case=="approved-udp" else
                   "DNS_TCP_MATCHED_NXDOMAIN" if case=="approved-tcp" else
                   "ROOT_PEER_ROUNDTRIP_COMPLETE" if case=="loopback-established" else
                   "SOCKET_FAILED_REQUIRES_KERNEL_COUNTER")
            return 0,value+"\n",True,peer is not None
        w=FixedWorkload(P,invoke=success,stop=lambda d: True)
        for case in CASES_ORDER:
            self.assertTrue(w.exercise(case,P,10))
        with self.assertRaises(WorkloadDenied):w.exercise(CASES_ORDER[-1],P,10)
        self.assertTrue(w.stop(10))
    def test_wrong_uid_and_fake_network_reply_fail(self):
        for result in ((0,"DNS_UDP_MATCHED_NXDOMAIN\n",False,False),
                       (0,"SOCKET_FAILED_REQUIRES_KERNEL_COUNTER\n",True,False),
                       (0,"DNS_UDP_MATCHED_NXDOMAIN\nsecret",True,False)):
            with self.subTest(result=result):
                w=FixedWorkload(P,invoke=lambda *a:result,stop=lambda d:True)
                with self.assertRaises(WorkloadDenied):w.exercise("approved-udp",P,10)
                with self.assertRaises(WorkloadDenied):w.exercise("approved-udp",P,10)
    def test_client_process_checks_actual_identity_callback(self):
        from probe_a_workload import exact_argv
        def stream(argv,timeout,**kwargs):
            kwargs["on_spawn"](4321)
            return Reply(0,"DNS_UDP_MATCHED_NXDOMAIN\n")
        p=ClientProcess(P,stream=stream,check_uid=lambda pid,uid:False,clock=lambda:1,sleep=lambda _:None)
        with self.assertRaises(ClientProcessDenied):
            p(exact_argv(P,"approved-udp"),10,P.uid,None)
    def test_uid_procfs_evidence_not_self_report(self):
        good=("Uid:\t45123 45123 45123 45123\n"
              "Gid:\t45123 45123 45123 45123\nGroups:\t\n"
              "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
              "CapAmb:\t0000000000000000\n")
        self.assertTrue(numeric_identity(4321,P.uid,read_text=lambda _:good))
        for bad in (good.replace("45123 45123 45123 45123","0 0 0 0",1),
                    good.replace("CapBnd:\t0000000000000000","CapBnd:\t0000000000000001")):
            with self.assertRaises(ResourceDenied):
                numeric_identity(4321,P.uid,read_text=lambda _:bad)
    def test_runner_default_is_disabled_and_never_launches(self):
        class Bomb:
            def launch(self,*args):raise AssertionError("must not spawn")
        r=OneShotRunner(P,launcher=Bomb(),verify_activation=lambda *x:True)
        self.assertEqual(r.run(),"BLOCKED_DISABLED_OR_UNAPPROVED")
        self.assertEqual(r.run(activated=True,approval="mock"),"BLOCKED_REPLAY")
if __name__=="__main__":
    unittest.main()
