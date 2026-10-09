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
        good=DigestGate(all_files,image_version="20261009.1",
                       read_bytes=lambda p:b"mock pinned bytes",
                       environ={"ImageOS":"ubuntu24","ImageVersion":"20261009.1"})
        self.assertTrue(good.verify())
        altered=DigestGate(all_files,image_version="20261009.1",
                          read_bytes=lambda p:b"modified",
                          environ={"ImageOS":"ubuntu24","ImageVersion":"20261009.1"})
        with self.assertRaises(AttestationDenied):altered.verify()
        wrong=DigestGate(all_files,image_version="20261009.1",
                         read_bytes=lambda p:b"mock pinned bytes",
                         environ={"ImageOS":"ubuntu22","ImageVersion":"20261009.1"})
        with self.assertRaises(AttestationDenied):wrong.verify()

    def test_bounded_json_not_pickle_and_wrong_index_rejected(self):
        class Model:
            cleaned=False
            plan=PLAN
            calls=[]
            def handle(self,*a):self.calls.append(a);return True
            def cleanup(self,deadline):self.cleaned=True
        for wire in (b"cos\nsystem\n", b'{"method":"issue","value":999,"deadline":9}',
                     b'{"method":"issue","value":["-F","OUTPUT"],"deadline":9}'):
            model=Model(); model.calls=[]
            class Link:
                def poll(self,timeout):return True
                def recv_bytes(self,maxlen):
                    self.assert_limit=maxlen
                    return wire
                def close(self):pass
                def send_bytes(self,p):raise AssertionError("never reply")
            GuardianChannel(model,clock=lambda:1).serve(Link(),end=241)
            self.assertTrue(model.cleaned)
            self.assertEqual(model.calls,[])
        source=(ROOT/"docs/security/phase2l/probe_a_guardian.py").read_text()
        self.assertNotIn("channel.recv()",source)
        self.assertNotIn("channel.send((",source)

    def test_json_snapshot_rehydrates_as_tuple(self):
        class Link:
            def __init__(self):self.sent=[]
            def send_bytes(self,data):self.sent.append(json.loads(data))
            def poll(self,t):return True
            def recv_bytes(self,maxsize):return b'{"ok":true,"value":["first","second"]}'
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
                        selector_factory=Selector,clock=lambda:1)
            kill.assert_called_once_with(81712,__import__("signal").SIGKILL)
        self.assertEqual(MAX_BYTES,131072)

if __name__=="__main__":
    unittest.main()
