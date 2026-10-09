"""Mock-only tests of exact argv and timeout gate; no subprocess."""
import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_contract import compile_plan
from probe_a_exec_adapter import Reply
from probe_a_os_boundary import RestrictedHost,HostBlocked,RUN_LIMIT_SECONDS
PLAN=compile_plan(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")
class HostGateTests(unittest.TestCase):
    def test_only_approved_arguments(self):
        got=[]
        h=RestrictedHost(PLAN,call=lambda argv,t:(got.append((argv,t)) or Reply(0,"")),clock=lambda:1)
        h.execute(PLAN.setup[0].argv,deadline=5)
        h.execute(("/usr/sbin/iptables-save","-t","filter"),deadline=5)
        self.assertEqual(len(got),2)
        self.assertTrue(all(0<x[1]<=RUN_LIMIT_SECONDS for x in got))
        for bad in (("/usr/sbin/iptables","-F","INPUT"),
                    ("/usr/sbin/iptables-restore","--noflush"),
                    ("/usr/bin/bash","-c","true"),
                    ("/usr/bin/curl","https://example.com")):
            with self.subTest(cmd=bad),self.assertRaises(HostBlocked):
                h.execute(bad,deadline=5)
    def test_timeout_and_sanitization(self):
        h=RestrictedHost(PLAN,call=lambda argv,t:Reply(0,""),clock=lambda:10)
        with self.assertRaises(HostBlocked):h.execute(PLAN.setup[0].argv,deadline=10)
        marker="private-secret"
        h=RestrictedHost(PLAN,call=lambda argv,t:(_ for _ in ()).throw(ValueError(marker)),clock=lambda:0)
        with self.assertRaises(HostBlocked) as e:h.execute(PLAN.setup[0].argv,deadline=10)
        self.assertNotIn(marker,str(e.exception))
    def test_absent_automatic_entry(self):
        src=(ROOT/"docs/security/phase2l/probe_a_os_boundary.py").read_text()
        self.assertNotIn('if __name__',src)
        self.assertNotIn('shell=True',src)
        self.assertNotIn('qemu-system',src)
if __name__=="__main__":unittest.main()
