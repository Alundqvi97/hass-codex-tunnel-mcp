"""Review-only process-owner probe tests; no root, QEMU, sockets or subprocess."""
import dataclasses
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
from probe_contract import (
    Command, Plan, Refused, compile_plan, validate_plan,
    CLEANUP_READBACKS, verdict,
)

def proposal():
    # 9.9.9.9 used ONLY as a public-address syntax fixture; no traffic.
    return dict(scope="A1B2C3D4",uid=45123,dns="9.9.9.9")

class ProbeContractTests(unittest.TestCase):
    def p(self,**kwargs):
        x=proposal();x.update(kwargs)
        return compile_plan(**x)
    def test_scoped_unique_chains(self):
        p=self.p()
        self.assertEqual((p.chain4,p.chain6),("P2A4_A1B2C3D4","P2A6_A1B2C3D4"))
        self.assertNotEqual(p.chain4,p.chain6)
        self.assertEqual(validate_plan(p),"OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED")
        self.assertEqual(p.receipt(),"PROBE=OFFLINE_PLAN_ONLY")
    def test_owner_rules_and_exact_dns_protocols(self):
        p=self.p()
        args=[x.argv for x in p.setup]
        for protocol in ("udp","tcp"):
            matches=[x for x in args if protocol in x and "--dport" in x and x[x.index("--dport")+1]=="53"]
            self.assertEqual(len(matches),1)
            self.assertIn("9.9.9.9/32",matches[0])
        self.assertTrue(all("-m" in x.argv and "owner" in x.argv and "45123" in x.argv for x in p.setup if x.phase=="hook"))
    def test_restrict_then_hooks_then_allowed(self):
        p=self.p()
        phases=[x.phase for x in p.setup]
        self.assertLess(phases.index("restrict"),phases.index("hook"))
        self.assertTrue(all(x.phase not in ("allow-dns-udp","allow-dns-tcp") for x in p.setup[:6]))
        self.assertEqual([x.family for x in p.setup if x.phase=="hook"],["ipv4","ipv6"])
    def test_unrelated_rules_never_flushed(self):
        p=self.p()
        for cmd in (*p.setup,*p.teardown):
            a=cmd.argv
            self.assertNotIn("INPUT",a)
            self.assertNotIn("FORWARD",a)
            self.assertNotIn("-P",a)
            self.assertNotIn("--noflush",a)
            self.assertFalse(any("restore" in z for z in a))
            if "-F" in a or "-X" in a:
                self.assertIn(a[-1],(p.chain4,p.chain6))
        self.assertEqual(len([x for x in p.setup if x.phase=="hook"]),2)
    def test_loopback_only_established_reply(self):
        p=self.p()
        rules=[x.argv for x in p.setup if x.phase=="allow-loopback-reply"]
        self.assertEqual(len(rules),1)
        self.assertIn("ESTABLISHED",rules[0])
        self.assertIn("127.0.0.1/32",rules[0])
        self.assertNotIn("NEW",rules[0])
        self.assertNotIn("-A OUTPUT",str(rules))
    def test_no_public_web_port_allow(self):
        p=self.p()
        self.assertFalse(any("443" in x.argv or "80" in x.argv for x in p.setup))
        self.assertFalse(any("ipv6"==x.family and "ACCEPT" in x.argv for x in p.setup))
    def test_reject_private_loopback_ipv6_and_reserved_dns(self):
        for dns in ("127.0.0.1","127.0.0.53","10.2.3.4","192.168.1.1","172.16.0.4","169.254.169.254","100.65.1.1","192.0.2.1","::1","2606:4700:4700::1111"):
            with self.subTest(dns=dns):
                with self.assertRaises(Refused): self.p(dns=dns)
    def test_bad_identity_scope_or_auto_retry(self):
        for kwargs in (
            dict(uid=0),dict(uid=45000.1),dict(uid=59999+1),
            dict(scope="AAAA"),dict(scope="A1B2C3D4;rm"),dict(scope="aaaaaaaa"),
            dict(qemu=True),dict(auto_retry=True)
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(Refused):self.p(**kwargs)
    def test_unique_scope_changes_only_scope_chain(self):
        first=self.p()
        second=self.p(scope="01020304")
        self.assertNotEqual(first.chain4,second.chain4)
        self.assertEqual(first.dns,second.dns)
    def test_rollback_all_prefixes_has_both_families_and_no_external_flushing(self):
        p=self.p()
        for cut in range(len(p.setup)+1):
            with self.subTest(cut=cut):
                # Even if any single step fails/partly modifies the kernel,
                # the independent teardown recipe contains both exact hooks.
                t=p.teardown
                self.assertEqual({x.family for x in t if x.phase=="unhook"},{"ipv4","ipv6"})
                self.assertEqual({x.family for x in t if x.phase=="own-chain-only"},{"ipv4","ipv6"})
                self.assertEqual(sum("-F" in x.argv for x in t),2)
                self.assertEqual(sum("-X" in x.argv for x in t),2)
                self.assertTrue(all(x.argv[-1] in (p.chain4,p.chain6) for x in t if x.phase=="own-chain-only"))
    def test_tampered_command_blocked(self):
        p=self.p()
        bad=dataclasses.replace(p,setup=p.setup+(Command("ipv4",("/usr/sbin/iptables","-w","5","-F","INPUT"),"hack"),))
        self.assertEqual(validate_plan(bad),"BLOCKED")
        bad2=dataclasses.replace(p,setup=p.setup+(Command("ipv4",("/usr/sbin/iptables-restore","--noflush"),"hack"),))
        self.assertEqual(validate_plan(bad2),"BLOCKED")
    def test_teardown_requires_independent_snapshot_comparison(self):
        self.assertIn("preexisting_ipv4_filter_identical",CLEANUP_READBACKS)
        self.assertIn("preexisting_ipv6_filter_identical",CLEANUP_READBACKS)
        self.assertIn("numeric_uid_process_absent",CLEANUP_READBACKS)
        self.assertIn("resolver_unchanged",CLEANUP_READBACKS)
    def test_cleanup_missing_failure_and_unknown_blocks(self):
        allgood={k:True for k in CLEANUP_READBACKS}
        for key in CLEANUP_READBACKS:
            for val in (False,None,"PASS"):
                x=dict(allgood);x[key]=val
                self.assertEqual(verdict(x,provenance="REAL_INDEPENDENT_HOST_READBACK"),"BLOCKED_CLEANUP_UNVERIFIED")
            x=dict(allgood);x.pop(key)
            self.assertEqual(verdict(x,provenance="REAL_INDEPENDENT_HOST_READBACK"),"BLOCKED_CLEANUP_INCOMPLETE")
    def test_fake_provenance_cannot_claim_kernel_pass(self):
        good={k:True for k in CLEANUP_READBACKS}
        self.assertEqual(verdict(good,provenance="fixture"),"SYNTHETIC_COMPLETE_NOT_ENFORCEMENT_PROOF")
        self.assertEqual(verdict(good,provenance="REAL_INDEPENDENT_HOST_READBACK"),"BLOCKED_NO_TRUSTED_OBSERVER")
    def test_no_executable_tool_or_network_call(self):
        src=(ROOT/"docs/security/phase2l/probe_contract.py").read_text()
        for fragment in ("import subprocess","from subprocess","import socket","os.system(","subprocess.run(","subprocess.Popen(","import requests","urllib.request","sudo "):
            self.assertNotIn(fragment,src)
    def test_existing_vm_workflow_is_unchanged_and_only_own_path_trigger(self):
        src=(ROOT/".github/workflows/phase2h-haos-vm-once.yml").read_text()
        self.assertIn("paths: [.github/workflows/phase2h-haos-vm-once.yml]",src)
        self.assertNotIn("workflow_dispatch",src)
    def test_future_guest_runner_still_blocked(self):
        s=(ROOT/"docs/security/phase2h/runner_once.sh").read_text()
        self.assertLess(s.index("runner_preflight.py"),s.index("sudo apt-get"))
        self.assertIn("PHASE2L_PRE_GUEST=BLOCKED_UNIMPLEMENTED_EGRESS_PROOF",s)

if __name__=="__main__":
    unittest.main()
