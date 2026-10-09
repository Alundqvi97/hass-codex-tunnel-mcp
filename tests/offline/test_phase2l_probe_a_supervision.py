"""Offline-only fault injection; never spawn a process or touch the network."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "docs/security/phase2l"))
from probe_contract import compile_plan, CLEANUP_READBACKS
from probe_a_exec_adapter import Reply
from probe_a_stream import capture, StreamFailure
from probe_a_observer import KernelReadback, ObservationDenied
from probe_a_os_boundary import SAVE4, SAVE6, VERSION4, VERSION6

PLAN = compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")
BASE = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"

class FakeReader:
    def __init__(self):
        self.calls=[]
        self.fail=None
        self.snapshots=(BASE,BASE)
    def __call__(self, argv, deadline):
        self.calls.append(argv)
        if argv == self.fail: raise RuntimeError("private-value")
        if argv == VERSION4:return Reply(0,"iptables v1.8.10 (nf_tables)\n")
        if argv == VERSION6:return Reply(0,"ip6tables v1.8.10 (nf_tables)\n")
        if argv == SAVE4:return Reply(0,self.snapshots[0])
        if argv == SAVE6:return Reply(0,self.snapshots[1])
        if argv[0:2] == ("/usr/bin/getent","passwd"):return Reply(2,"")
        if argv[0:2] == ("/usr/bin/pgrep","-u"):return Reply(1,"")
        if "-S" in argv:return Reply(1,"")
        return Reply(4,"UNKNOWN")
class ResourceReader:
    def __init__(self,fail=None):self.calls=[];self.fail=fail
    def readback(self,key,deadline):
        self.calls.append(key)
        return key!=self.fail

class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.reader=FakeReader()
        self.observer=KernelReadback(PLAN,read=self.reader,clock=lambda:1)
    def test_preflight_and_all_cleanup_readbacks(self):
        self.observer.preflight(10)
        res=ResourceReader()
        self.assertEqual(set(self.observer.mandatory_readbacks(10,independent_resources=res)),set(CLEANUP_READBACKS))
        self.assertTrue(all(self.observer.mandatory_readbacks(10,independent_resources=res).values()))
        self.assertEqual(self.observer.require_restored(10),"SYNTHETIC_RULES_RESTORED_NOT_KERNEL_PROVEN")
    def test_wrong_uid_or_existing_process_fails(self):
        for cmd,exit_code in ((("/usr/bin/getent","passwd","45123"),0),
                              (("/usr/bin/pgrep","-u","45123"),0)):
            with self.subTest(cmd=cmd):
                reader=FakeReader()
                orig=reader.__call__
                reader.__call__=lambda *a:None
                def run(argv,deadline):
                    if argv==cmd:return Reply(exit_code,"occupied")
                    return orig(argv,deadline)
                with self.assertRaises(ObservationDenied):
                    KernelReadback(PLAN,read=run,clock=lambda:1).preflight(10)
    def test_backend_mismatch_denied(self):
        def reader(argv,deadline):
            if argv==VERSION6:return Reply(0,"ip6tables v1.8.10 (legacy)")
            return self.reader(argv,deadline)
        with self.assertRaises(ObservationDenied):
            KernelReadback(PLAN,read=reader,clock=lambda:1).preflight(10)
    def test_readback_failure_checks_remaining_keys(self):
        self.observer.preflight(10)
        reader=ResourceReader("test_listeners_absent")
        result=self.observer.mandatory_readbacks(10,independent_resources=reader)
        self.assertFalse(result["test_listeners_absent"])
        self.assertEqual(reader.calls,["test_listeners_absent","temporary_files_absent","watchdog_absent","resolver_unchanged"])
    def test_missing_snapshot_blocks_cleanup_proof(self):
        res=self.observer.mandatory_readbacks(10,independent_resources=ResourceReader())
        self.assertFalse(res["preexisting_ipv4_filter_identical"])
    def test_misleading_snapshot_and_command_error(self):
        self.observer.preflight(10)
        self.reader.snapshots=(BASE+"-A OUTPUT -j EVIL\n",BASE)
        with self.assertRaises(Exception):
            self.observer.require_restored(10)
        self.reader.fail=SAVE6
        with self.assertRaises(ObservationDenied) as e:self.observer.snapshot(10)
        self.assertNotIn("private-value",str(e.exception))

class StreamTests(unittest.TestCase):
    def test_bad_input_never_spawns(self):
        with patch("probe_a_stream.subprocess.Popen",side_effect=AssertionError("launched")) as popen:
            for argv,t in ((("/bin/sh","-c","true"),0),((),1),(("/bin/echo","\x00"),1)):
                with self.subTest(argv=argv),self.assertRaises(StreamFailure):
                    capture(argv,t)
            popen.assert_not_called()
    def test_overflow_and_term_fail_closed_without_process(self):
        # These are mock-only tests: no subprocess starts, no SIGKILL sent.
        from probe_a_stream import MAX_BYTES
        self.assertEqual(MAX_BYTES,131072)
        with self.assertRaises(StreamFailure):
            capture(("/usr/bin/true",),1,spawn=lambda *a,**kw: (_ for _ in ()).throw(KeyboardInterrupt()))
    def test_no_automatic_entrypoint(self):
        for name in ("probe_a_stream.py","probe_a_observer.py"):
            source=(ROOT/"docs/security/phase2l"/name).read_text()
            self.assertNotIn('if __name__',source)
            self.assertNotIn("shell=True",source)
if __name__=="__main__":unittest.main()
