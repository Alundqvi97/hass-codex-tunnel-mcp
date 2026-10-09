"""Fixed streamed subprocess invoker with independent /proc UID and listener checks.

No commands are executed at import. Called only through explicitly injected
guardian-owned FixedWorkload. A separate actor must supervise this boundary.
"""
from __future__ import annotations
import time

from probe_a_stream import capture
from probe_a_resources import numeric_identity, attest_listener
from probe_a_workload import exact_argv, peer_argv, CASES_ORDER

class ClientProcessDenied(RuntimeError):
    pass


class ClientProcess:
    def __init__(self, plan, *, stream=capture, check_uid=numeric_identity,
                 check_listener=attest_listener, clock=time.monotonic, sleep=time.sleep):
        self.plan=plan
        self.stream=stream
        self.check_uid=check_uid
        self.check_listener=check_listener
        self.clock=clock
        self.sleep=sleep
        self.seen=set()
        self.running_pids=set()

    def __call__(self, argv, deadline, uid, root_peer_command):
        if (type(uid) is not int or uid != self.plan.uid or
                root_peer_command not in (None, peer_argv()) or
                argv not in tuple(exact_argv(self.plan, case) for case in CASES_ORDER) or
                argv in self.seen or not self.clock()<deadline):
            raise ClientProcessDenied("UNREVIEWED_CLIENT_INVOCATION")
        case=CASES_ORDER[tuple(exact_argv(self.plan,x) for x in CASES_ORDER).index(argv)]
        if (case=="loopback-established") != (root_peer_command is not None):
            raise ClientProcessDenied("PEER_SCOPE_MISMATCH")
        self.seen.add(argv)  # consume before launch, no retries
        verified=[False,False]
        pid=[None]
        def on_spawn(actual_pid):
            pid[0]=actual_pid
            self.running_pids.add(actual_pid)
            # setpriv initially exists as a root-owned launcher; inspect
            # /proc until it becomes the reviewed numeric UID, with a bounded
            # observation window. Never relaunch a failing process.
            for _ in range(25):
                try:
                    if self.check_uid(actual_pid,uid) is True:
                        verified[0]=True
                        break
                except BaseException:
                    pass
                if self.clock()>=deadline:
                    break
                self.sleep(0.02)
            if not verified[0]:
                raise ClientProcessDenied("UID_NOT_ATTESTED")
        def on_chunk(data):
            if root_peer_command is None or verified[1]:
                return
            if len(data)>4096 or not data.startswith(b"READY\n"[:len(data)]):
                raise ClientProcessDenied("BAD_LOOPBACK_READINESS")
            if len(data)<6:
                return  # streaming reader may split READY across chunks
            if self.check_listener(pid[0]) is not True:
                raise ClientProcessDenied("LISTENER_NOT_ATTESTED")
            reply=self.stream(root_peer_command, min(5,deadline-self.clock()))
            if reply.code!=0 or reply.stdout!="ROOT_PEER_ACK_MATCHED\n":
                raise ClientProcessDenied("PEER_ATTESTATION_FAILED")
            verified[1]=True
        try:
            result=self.stream(argv, min(8,deadline-self.clock()),
                               on_spawn=on_spawn,on_chunk=on_chunk)
            return (result.code,result.stdout.removeprefix("READY\n"),verified[0],verified[1])
        except BaseException:
            raise ClientProcessDenied("CLIENT_PROCESS_FAILED") from None
        finally:
            if pid[0] is not None:
                self.running_pids.discard(pid[0])

    def stop(self, deadline):
        # The actual capture helper kills remaining process groups on errors.
        # An independent guardian must STILL verify pgrep -u UID == absent.
        return not self.running_pids and self.clock()<deadline
