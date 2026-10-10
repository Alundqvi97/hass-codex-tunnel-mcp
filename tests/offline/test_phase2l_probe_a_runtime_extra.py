"""No live subprocess or network: test new process and JSON boundary failures."""
import hashlib
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_contract import compile_plan
from probe_a_client_process import ClientProcess
from probe_a_workload import exact_argv,peer_argv
from probe_a_exec_adapter import Reply
from probe_a_attestation import DigestGate,AttestationDenied,PINNED
from probe_a_guardian import GuardianChannel,RemoteIO,GuardianDenied
from probe_a_stream import capture,StreamFailure,MAX_BYTES

PLAN=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")

class AdditionalSecurityTests(unittest.TestCase):
    def test_split_ready_line_and_root_peer_are_bounded(self):
        calls=[]
        def stream(argv,timeout,**kwargs):
            calls.append(argv)
            if argv==peer_argv():
                return Reply(0,"ROOT_PEER_ACK_MATCHED\n")
            kwargs["on_spawn"](12345)
            kwargs["on_chunk"](b"REA")
            kwargs["on_chunk"](b"READY\n")
            return Reply(0,"READY\nROOT_PEER_ROUNDTRIP_COMPLETE\n")
        invoker=ClientProcess(PLAN,stream=stream,check_uid=lambda p,u:True,
                              check_listener=lambda p:True,clock=lambda:1,sleep=lambda _:None)
        result=invoker(exact_argv(PLAN,"loopback-established"),10,PLAN.uid,peer_argv())
        self.assertEqual(result,(0,"ROOT_PEER_ROUNDTRIP_COMPLETE\n",True,True))
        self.assertEqual(calls,[exact_argv(PLAN,"loopback-established"),peer_argv()])
        with self.assertRaises(Exception):
            invoker(exact_argv(PLAN,"loopback-established"),10,PLAN.uid,peer_argv())

    def test_misleading_root_peer_ack_rejected(self):
        def stream(argv,timeout,**kw):
            if argv==peer_argv():return Reply(0,"NOT_A_PEER\n")
            kw["on_spawn"](12345)
            kw["on_chunk"](b"READY\n")
            return Reply(0,"READY\nROOT_PEER_ROUNDTRIP_COMPLETE\n")
        c=ClientProcess(PLAN,stream=stream,check_uid=lambda p,u:True,
                        check_listener=lambda p:True,clock=lambda:1,sleep=lambda _:None)
        with self.assertRaises(Exception):
            c(exact_argv(PLAN,"loopback-established"),10,PLAN.uid,peer_argv())

    def test_manifest_requires_every_source_and_verified_runner_version(self):
        digest=hashlib.sha256(b"mock pinned bytes").hexdigest()
        all_files={p:digest for p in PINNED}
        with self.assertRaises(AttestationDenied):
            DigestGate({p:digest for p in PINNED[:-1]},image_version="20261009.1")
        # The manifest cannot be accepted without a separately reviewed
        # complete dependency closure, even if primary binaries match.
        with self.assertRaises(AttestationDenied):
            DigestGate(all_files,image_version="20261009.1",
                       read_bytes=lambda p:b"mock pinned bytes",
                       environ={"ImageOS":"ubuntu24","ImageVersion":"20261009.1"})
        dependency="/usr/lib/p2a-fixture/ld-approved.so"
        full={**all_files,dependency:digest}
        good=DigestGate(full,dependency_paths=(dependency,),verified_dependency_inventory=True,image_version="20261009.1",
                       read_bytes=lambda p:b"mock pinned bytes",
                       environ={"ImageOS":"ubuntu24","ImageVersion":"20261009.1"})
        self.assertTrue(good.verify())
        altered=DigestGate(full,dependency_paths=(dependency,),verified_dependency_inventory=True,image_version="20261009.1",
                          read_bytes=lambda p:b"modified",
                          environ={"ImageOS":"ubuntu24","ImageVersion":"20261009.1"})
        with self.assertRaises(AttestationDenied):altered.verify()
        wrong=DigestGate(full,dependency_paths=(dependency,),verified_dependency_inventory=True,image_version="20261009.1",
                         read_bytes=lambda p:b"mock pinned bytes",
                         environ={"ImageOS":"ubuntu22","ImageVersion":"20261009.1"})
        with self.assertRaises(AttestationDenied):wrong.verify()

    def test_manifest_omitted_security_tools_fail_closed(self):
        self.assertIn("/usr/bin/pgrep", PINNED)
        self.assertIn("/usr/bin/getent", PINNED)
        digest=hashlib.sha256(b"source").hexdigest()
        manifest={path:digest for path in PINNED if path!="/usr/bin/pgrep"}
        manifest["/lib/ld-audited.so"]=digest
        with self.assertRaises(AttestationDenied):
            DigestGate(manifest,image_version="20261009.1",
                       dependency_paths=("/lib/ld-audited.so",),
                       verified_dependency_inventory=True)

    def test_os_privilege_drop_contract_never_accepts_root_or_caps(self):
        from probe_a_privilege import verify_unprivileged, drop_controller, PrivilegeDenied
        status=("Uid:\t65534 65534 65534 65534\n"
                "Gid:\t65534 65534 65534 65534\nGroups:\t\n"
                "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
                "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
                "CapAmb:\t0000000000000000\nNoNewPrivs:\t1\n")
        self.assertTrue(verify_unprivileged(read_text=lambda p: status))
        for wrong in (status.replace("65534 65534 65534 65534","0 0 0 0",1),
                      status.replace("CapBnd:\t0000000000000000","CapBnd:\t0000000000000001"),
                      status.replace("NoNewPrivs:\t1","NoNewPrivs:\t0")):
            with self.assertRaises(PrivilegeDenied):
                verify_unprivileged(read_text=lambda p, s=wrong:s)
        calls=[]
        class Caps:
            def thread_count(self):calls.append("threads");return 1
            def last_capability(self):calls.append("last");return 1
            def no_new_privs(self):calls.append("nnp");return True
            def clear_ambient(self):calls.append("ambient");return True
            def bounding_member(self,c):calls.append(("bound",c));return c==0
            def drop_bounding(self,c):calls.append(("drop",c));return True
            def clear_process_sets(self):calls.append("capset");return True
        self.assertTrue(drop_controller(getuid=lambda:0,capability_ops=Caps(),
                 setgroups=lambda v:calls.append(("groups",v)),
                 setgid=lambda *v:calls.append(("gid",v)),
                 setuid=lambda *v:calls.append(("uid",v)),
                 verify=lambda *a:calls.append("verify") or True))
        self.assertEqual(calls,["threads","last","nnp","ambient",
                                ("bound",0),("drop",0),("bound",1),
                                ("groups",[]),("gid",(65534,)*3),
                                ("uid",(65534,)*3),"capset","verify"])
        with self.assertRaises(PrivilegeDenied):
            drop_controller(getuid=lambda:65534,capability_ops=Caps())

    def test_readonly_observer_does_not_expose_guardian_write(self):
        from probe_a_privilege import ReadOnlyPostObserver, PrivilegeDenied
        observed=[]
        reader=ReadOnlyPostObserver(PLAN,read=lambda a,d:observed.append(a),
                                    check=lambda:True)
        reader(("/usr/sbin/iptables-save","-t","filter"),10)
        self.assertEqual(len(observed),1)
        for cmd in PLAN.setup+PLAN.teardown:
            with self.assertRaises(PrivilegeDenied):
                reader(cmd.argv,10)
        with self.assertRaises(PrivilegeDenied):
            ReadOnlyPostObserver(PLAN,read=lambda *a:True,
                                check=lambda:False)(("/usr/sbin/iptables-save","-t","filter"),10)

    def test_root_command_adapter_refuses_unprivileged_sudo_fallback(self):
        from probe_a_os_boundary import bounded_process, HostBlocked
        with patch("probe_a_os_boundary.os.geteuid",return_value=65534), \
             patch("probe_a_os_boundary.capture",side_effect=AssertionError("unreviewed spawn")):
            with self.assertRaises(HostBlocked):
                bounded_process(PLAN.setup[0].argv,2,reviewed_plan=PLAN)

    def test_cgroup_contract_catches_detached_descendant_and_peer_survival(self):
        from probe_a_containment import CgroupV2Containment,ContainmentDenied
        class Fake:
            def __init__(self):
                self.populated="1";self.procs="112\n113\n";self.killed=False
            def preflight_atomic_spawn(self,path):return path.endswith("A1B2C3D4")
            def capture_atomic(self,path,argv,timeout,**callbacks):return Reply(0,"ok")
            def kill_all(self,path,deadline):
                self.killed=True
                return True
            def readback(self,path,deadline):
                return "populated "+self.populated+"\n",self.procs
            def check_uid_absent(self,uid,deadline):return True
        fake=Fake()
        fence=CgroupV2Containment(PLAN,agent=fake)
        with self.assertRaises(ContainmentDenied):
            fence.capture(peer_argv(),3)
        self.assertTrue(fence.arm())
        fence.capture(peer_argv(),3)
        fence.capture(exact_argv(PLAN,"approved-udp"),3)
        # A detached root peer remains despite kill() claiming success.
        self.assertFalse(fence.stop(10))
        self.assertTrue(fake.killed)
        fake.populated="0";fake.procs=""
        self.assertTrue(fence.stop(10))
        with self.assertRaises(ContainmentDenied):
            fence.capture(peer_argv(),3)

    def test_live_factory_rejects_non_atomic_process_boundary(self):
        from probe_a_runner import reviewed_boundary_factory,RunnerDenied
        class Attestor:
            def verify(self):return True
        with self.assertRaises(RunnerDenied):
            reviewed_boundary_factory(PLAN,attestor=Attestor())

    def test_bounded_json_not_pickle_and_wrong_index_rejected(self):
        class Model:
            cleaned=False
            cleanup_state="NOT_STARTED"
            plan=PLAN
            calls=[]
            def handle(self,*a):self.calls.append(a);return True
            def cleanup(self,deadline):
                self.cleaned=True
                self.cleanup_state="POST_AUDIT_REQUIRED"
        for wire in (b"cos\nsystem\n", b'{"method":"issue","value":999,"deadline":9}',
                     b'{"method":"issue","value":["-F","OUTPUT"],"deadline":9}'):
            model=Model(); model.calls=[]
            class Link:
                def poll(self,timeout):return True
                def recv_bytes(self,maxlen,*,deadline=None):
                    self.assert_limit=maxlen
                    return wire
                def close(self):pass
                def send_bytes(self,p,*,deadline=None):raise AssertionError("never reply")
            GuardianChannel(model,clock=lambda:1).serve(Link(),end=241)
            self.assertTrue(model.cleaned)
            self.assertEqual(model.calls,[])
        source=(ROOT/"docs/security/phase2l/probe_a_guardian.py").read_text()
        self.assertNotIn("channel.recv()",source)
        self.assertNotIn("channel.send((",source)

    def test_json_snapshot_rehydrates_as_tuple(self):
        class Link:
            def __init__(self):self.sent=[]
            def send_bytes(self,data,*,deadline=None):self.sent.append(json.loads(data))
            def poll(self,t):return True
            def recv_bytes(self,maxsize,*,deadline=None):return b'{"ok":true,"value":["first","second"]}'
        channel=Link()
        remote=RemoteIO(channel,PLAN,clock=lambda:1)
        self.assertEqual(remote.snapshot(),("first","second"))
        self.assertEqual(channel.sent[0]["method"],"snapshot")
        self.assertEqual(channel.sent[0]["value"],None)

    def test_stream_overflow_kills_fake_child_group_without_real_process(self):
        class File:
            def fileno(self):return 44
            def close(self):pass
        class Child:
            stdout=File()
            pid=81712
            returncode=0
            def poll(self):return None
            def wait(self,timeout):return 0
        class Selector:
            def register(self,*a):pass
            def get_map(self):return {44:True}
            def select(self,timeout):return [(SimpleNamespace(fileobj=File()),1)]
            def close(self):pass
        with patch("probe_a_stream.os.set_blocking"), \
             patch("probe_a_stream.os.read",return_value=b"x"*8192), \
             patch("probe_a_stream.os.killpg") as kill:
            with self.assertRaises(StreamFailure):
                capture(("/usr/bin/true",),2,spawn=lambda *a,**kw:Child(),
                        selector_factory=Selector,clock=lambda:1,
                        group_owner=lambda pid:True,group_kill=kill)
            kill.assert_called_once_with(81712,__import__("signal").SIGKILL)
        self.assertEqual(MAX_BYTES,131072)

    def test_ipv6_default_reject_encoding_is_narrowly_accepted(self):
        from probe_a_recovery import inspect_partial,RecoveryDenied
        nl=chr(10)
        base=nl.join(["*filter",":INPUT ACCEPT [0:0]",":FORWARD ACCEPT [0:0]",":OUTPUT ACCEPT [0:0]","COMMIT",""])
        chain=PLAN.chain6
        active=base.replace("COMMIT"+nl,
            nl.join([f":{chain} - [0:0]",f"-A {chain} -j REJECT --reject-with icmp6-port-unreachable","COMMIT",""]))
        self.assertTrue(inspect_partial(PLAN,(base,base),(base,active))[1].chain)
        with self.assertRaises(RecoveryDenied):
            inspect_partial(PLAN,(base,base),(base,active.replace("icmp6-port-unreachable","icmp6-adm-prohibited")))

    def test_sigterm_handler_is_deterministic_and_offline(self):
        from probe_a_guardian import installed_signal_abort,GuardianDenied
        import signal
        signals=[]
        with patch("probe_a_guardian.signal.signal",side_effect=lambda a,b:signals.append((a,b))):
            installed_signal_abort(lambda:signals.append(("cleanup",True)))
            handler=signals[0][1]
            with self.assertRaises(GuardianDenied):handler(signal.SIGTERM,None)
        self.assertIn(("cleanup",True),signals)
        self.assertIn((signal.SIGTERM,signal.SIG_IGN),signals)

if __name__=="__main__":
    unittest.main()
