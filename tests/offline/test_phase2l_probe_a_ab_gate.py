"""Adversarial Probe A A/B gate tests. No OS sockets or process termination.

Every stream, selector, root fork, and process exit is replaced with a fake.
Only these test-specific injected observations can succeed: no kernel evidence.
"""
import json
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_contract import compile_plan
from probe_a_ipc import BoundedSocketIPC,IpcDenied,IpcDeadline,IpcFraming,MAX_FRAME
from probe_a_guardian import GuardianChannel,RemoteIO,LIFECYCLE_FAULT
from probe_a_runner import ForkGuardianLauncher,RunnerDenied
from probe_a_exec_adapter import Reply
from test_phase2l_probe_a_runtime import FakeReader,FakeKernel,MockWork,MockResources
from test_phase2l_probe_a_final_supervision import ScriptedCleanup, Clock, SAFE_STATUS

PLAN=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")


class FakeSocket:
    counter=77
    def __init__(self):
        FakeSocket.counter+=1
        self.number=FakeSocket.counter
        self.inbox=bytearray()
        self.peer=None
        self.eof=False
        self.writable=True
        self.blocking=None
        self.closed=False
        self.send_limit=None
        self.writes=0
        self.stop_after=None
    def fileno(self):return self.number
    def setblocking(self,value):self.blocking=value
    def recv(self,size):
        if self.inbox:
            n=min(size,len(self.inbox))
            payload=bytes(self.inbox[:n])
            del self.inbox[:n]
            return payload
        if self.eof or (self.peer is not None and self.peer.closed):
            return b""
        raise BlockingIOError()
    def send(self,buffer):
        if not self.writable or (self.stop_after is not None and self.writes>=self.stop_after):
            raise BlockingIOError()
        if self.peer is not None and self.peer.closed:
            raise BrokenPipeError()
        payload=bytes(buffer)
        count=min(len(payload),self.send_limit or len(payload))
        if self.peer is not None:
            self.peer.inbox.extend(payload[:count])
        self.writes+=1
        return count
    def close(self):self.closed=True


def clocked_select(clock):
    def choose(readers,writers,errors,seconds):
        ready_r=[s for s in readers if s.inbox or s.eof or (s.peer is not None and s.peer.closed)]
        ready_w=[s for s in writers if s.writable and
                 (s.stop_after is None or s.writes < s.stop_after) and
                 (s.peer is None or not s.peer.closed)]
        if ready_r or ready_w:
            return ready_r,ready_w,[]
        clock.advance(seconds)
        return [],[],[]
    return choose


def pair(clock):
    a,b=FakeSocket(),FakeSocket()
    a.peer=b;b.peer=a
    return (BoundedSocketIPC(a,clock=clock,select_fn=clocked_select(clock)),
            BoundedSocketIPC(b,clock=clock,select_fn=clocked_select(clock)))


class FramingTests(unittest.TestCase):
    def test_same_exact_four_byte_framing_on_both_sides(self):
        clock=Clock(0)
        a,b=pair(clock)
        self.assertFalse(a.stream.blocking)
        self.assertFalse(b.stream.blocking)
        a.send_bytes(b'{"method":"snapshot"}',deadline=4)
        self.assertTrue(b.poll(1))
        self.assertEqual(b.recv_bytes(256,deadline=4),b'{"method":"snapshot"}')
        b.send_bytes(b'{"ok":true,"value":null}',deadline=4)
        self.assertEqual(a.recv_bytes(300000,deadline=4),b'{"ok":true,"value":null}')
        self.assertFalse(a.stream.inbox)
        self.assertFalse(b.stream.inbox)

    def test_incomplete_header_times_out_at_absolute_deadline(self):
        clock=Clock(179.5)
        a,b=pair(clock)
        a.stream.inbox.extend(b"\x00\x00")
        with self.assertRaises(IpcDeadline):
            a.recv_bytes(256,deadline=180)
        self.assertGreaterEqual(clock(),180)
        self.assertLess(clock(),180.01)

    def test_truncated_payload_cannot_extend_cleanup_reserve(self):
        clock=Clock(179.5)
        a,b=pair(clock)
        a.stream.inbox.extend(struct.pack("!I",12)+b'{"x":')
        with self.assertRaises(IpcDeadline):
            a.recv_bytes(256,deadline=180)
        self.assertGreaterEqual(clock(),180)
        self.assertLess(clock(),180.01)

    def test_invalid_frame_length_fails_before_payload_allocation(self):
        for length in (0,257,MAX_FRAME+1,0xFFFFFFFF):
            clock=Clock(0)
            a,b=pair(clock)
            a.stream.inbox.extend(struct.pack("!I",length))
            with self.subTest(length=length),self.assertRaises(IpcFraming):
                a.recv_bytes(256,deadline=1)

    def test_complete_header_with_eof_mid_payload_fails_closed(self):
        clock=Clock(0)
        a,b=pair(clock)
        a.stream.inbox.extend(struct.pack("!I",8)+b"abc")
        a.stream.eof=True
        with self.assertRaises(EOFError):
            a.recv_bytes(256,deadline=3)

    def test_partial_header_then_eof_never_dispatches_json(self):
        clock=Clock(0)
        a,b=pair(clock)
        a.stream.inbox.extend(b"\x00\x00")
        a.stream.eof=True
        with self.assertRaises(EOFError):
            a.recv_bytes(256,deadline=2)

    def test_stalled_partial_write_expires_without_entering_reserve(self):
        clock=Clock(179.5)
        a,b=pair(clock)
        a.stream.send_limit=2
        a.stream.stop_after=1
        with self.assertRaises(IpcDeadline):
            a.send_bytes(b'{"ok":true}',deadline=180)
        self.assertGreaterEqual(clock(),180)
        self.assertLess(clock(),180.01)
        self.assertEqual(len(b.stream.inbox),2)

    def test_unread_large_reply_times_out_on_nonblocking_send(self):
        clock=Clock(10)
        a,b=pair(clock)
        a.stream.stop_after=0
        a.stream.writable=False
        with self.assertRaises(IpcDeadline):
            a.send_bytes(b"x"*MAX_FRAME,deadline=11)
        self.assertLessEqual(clock(),11.01)
        with self.assertRaises(IpcFraming):
            a.send_bytes(b"x"*(MAX_FRAME+1),deadline=13)

    def test_nonblocking_send_failure_does_not_echo_details(self):
        clock=Clock(0)
        a,b=pair(clock)
        b.close()
        with self.assertRaises(IpcDenied) as err:
            a.send_bytes(b"secret",deadline=2)
        self.assertNotIn("secret",str(err.exception))

    def test_remote_controller_applies_shared_rpc_deadline(self):
        clock=Clock(1)
        a,b=pair(clock)
        b.send_bytes(b'{"ok":true,"value":["before4","before6"]}',deadline=3)
        remote=RemoteIO(a,PLAN,clock=clock)
        self.assertEqual(remote.snapshot(),("before4","before6"))
        request=b.recv_bytes(256,deadline=3)
        self.assertEqual(json.loads(request),{"method":"snapshot","value":None,"deadline":9})
        self.assertLessEqual(clock(),9)

    def test_remote_truncated_response_is_not_success(self):
        clock=Clock(1)
        a,b=pair(clock)
        a.stream.inbox.extend(struct.pack("!I",25)+b'{"ok":')
        with self.assertRaises(Exception):
            RemoteIO(a,PLAN,clock=clock).snapshot()
        self.assertGreaterEqual(clock(),9)

    def test_guardian_partial_payload_runs_its_own_cleanup_after_cutoff(self):
        clock=Clock(179.7)
        guardian_end,controller_end=pair(clock)
        guardian_end.stream.inbox.extend(struct.pack("!I",100)+b'{"method":')
        core=ScriptedCleanup(clock,["POST_AUDIT_REQUIRED"])
        result=GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            guardian_end,end=240,cleanup_cutoff=180)
        self.assertEqual(result,LIFECYCLE_FAULT)
        self.assertEqual(len(core.calls),1)
        self.assertGreaterEqual(core.calls[0],180)
        self.assertTrue(guardian_end.closed)
        self.assertFalse(core.writes)

    def test_guardian_stalled_response_abandons_ipc_to_clean_up(self):
        clock=Clock(179.4)
        guardian_end,controller_end=pair(clock)
        request=json.dumps({"method":"snapshot","value":None,"deadline":200}).encode()
        controller_end.send_bytes(request,deadline=179.7)
        guardian_end.stream.writable=False
        class Model(ScriptedCleanup):
            def handle(self,method,arg,deadline):
                if method=="snapshot":
                    return ["fixture4","fixture6"]
                return super().handle(method,arg,deadline)
        core=Model(clock,["POST_AUDIT_REQUIRED"])
        result=GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            guardian_end,end=240,cleanup_cutoff=180)
        self.assertEqual(result,LIFECYCLE_FAULT)
        self.assertEqual(len(core.calls),1)
        self.assertTrue(guardian_end.closed)

    def test_guardian_rejects_complete_oversized_header_before_cleanup(self):
        clock=Clock(179.4)
        guardian_end,controller_end=pair(clock)
        guardian_end.stream.inbox.extend(struct.pack("!I",99999))
        core=ScriptedCleanup(clock,["POST_AUDIT_REQUIRED"])
        result=GuardianChannel(core,clock=clock,sleep=clock.advance).serve(
            guardian_end,end=240,cleanup_cutoff=180)
        self.assertEqual(result,LIFECYCLE_FAULT)
        self.assertEqual(len(core.calls),1)


class HardStopped(BaseException):
    pass


class FakeContext:
    def __init__(self):
        self.started=False
        self.fail_start=False
    def Process(self,**kw):
        ctx=self
        class Proc:
            def start(self):
                ctx.started=True
                if ctx.fail_start:
                    raise RuntimeError("synthetic uncertain fork")
        return Proc()


class HardStopTests(unittest.TestCase):
    def build(self,drop,*,fail_start=False):
        clock=Clock(1)
        ctx=FakeContext()
        ctx.fail_start=fail_start
        endpoints=[]
        class End:
            def __init__(self):self.closed=False
            def close(self):self.closed=True
        def factory(*,clock):
            pair=(End(),End())
            endpoints.extend(pair)
            return pair
        launch=ForkGuardianLauncher(
            backend_factory=lambda p:(FakeReader(FakeKernel(0)),MockWork(),MockResources()),
            controller_drop=drop,
            post_observer_factory=lambda p:lambda argv,d:Reply(0,""),
            root_check=lambda:0,context_factory=lambda _:ctx,
            transport_pair_factory=factory,clock=clock)
        return launch,ctx,endpoints

    def test_failed_privilege_drop_before_uid_change_hard_stops(self):
        launch,ctx,pipes=self.build(lambda:(_ for _ in ()).throw(PermissionError("pre UID")))
        with patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
            with self.assertRaises(HardStopped):
                launch.launch(PLAN,200,140)
        hard_exit.assert_called_once_with(77)
        self.assertTrue(ctx.started)
        self.assertTrue(all(p.closed for p in pipes))

    def test_partial_capability_drop_hard_stops_no_controller_return(self):
        events=[]
        def drop():
            events.append("caps-partial")
            raise RuntimeError("synthetic CAP_SETPCAP failure")
        launch,ctx,pipes=self.build(drop)
        with patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
            with self.assertRaises(HardStopped):
                launch.launch(PLAN,200,140)
        self.assertEqual(events,["caps-partial"])
        hard_exit.assert_called_once_with(77)
        self.assertTrue(all(p.closed for p in pipes))

    def test_false_success_after_guardian_fork_still_hard_stops(self):
        launch,ctx,pipes=self.build(lambda:True)
        with patch("probe_a_runner.verify_unprivileged",
                   side_effect=PermissionError("fake UID still root")), \
             patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
            with self.assertRaises(HardStopped):
                launch.launch(PLAN,200,140)
        hard_exit.assert_called_once_with(77)
        self.assertTrue(ctx.started)
        self.assertTrue(all(p.closed for p in pipes))

    def test_process_start_failure_also_hard_stops(self):
        launch,ctx,pipes=self.build(lambda:True,fail_start=True)
        with patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
            with self.assertRaises(HardStopped):
                launch.launch(PLAN,200,140)
        hard_exit.assert_called_once_with(77)
        self.assertTrue(ctx.started)
        self.assertTrue(all(p.closed for p in pipes))

    def test_untrusted_python_exception_cannot_replace_hard_exit(self):
        launch,ctx,pipes=self.build(lambda:(_ for _ in ()).throw(SystemExit(0)))
        with patch("probe_a_runner.os._exit",side_effect=HardStopped) as hard_exit:
            with self.assertRaises(HardStopped):
                launch.launch(PLAN,200,140)
        hard_exit.assert_called_once_with(77)
        # Mock raised only to avoid exiting the test runner; real os._exit
        # cannot be caught by Python BaseException or converted to PASS.
        self.assertTrue(all(p.closed for p in pipes))

    def test_no_untrusted_post_audit_is_claimed_after_hard_stop(self):
        launch,ctx,pipes=self.build(lambda:False)
        observer_called=[]
        launch.verify_after=lambda *a:observer_called.append(a)
        with patch("probe_a_runner.os._exit",side_effect=HardStopped):
            with self.assertRaises(HardStopped):
                launch.launch(PLAN,200,140)
        self.assertEqual(observer_called,[])


if __name__=="__main__":
    unittest.main()
