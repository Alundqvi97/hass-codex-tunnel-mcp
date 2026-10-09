"""Consolidated pre-VM negative tests, no network, host mutation, or Docker."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"docs/security/phase2l"))
import egress_compiler as egress
import runtime_evidence as evidence

NOW=2_000_000_000

def approved_proposal():
    # Addresses and hostnames are fictional QA fixtures, not approval of
    # any actual DNS server, CDN, registry endpoint or bootstrap service.
    return {
        "schema":1, "origin":"PROPOSED_ONLY", "owner_uid":43210,
        "dns":{"public_ipv4":"9.9.9.9","tcp":True,"udp":True,
               "resolver_control":"PROCESS_PRIVATE_RESOLV_CONF_PROPOSED"},
        "ntp":{"mode":"REVIEWED_NTP_DESTINATION","public_ipv4":"1.1.1.1"},
        "ipv6":{"guest":"off","host":"deny"},
        "web":[{"hostname":"ghcr.io","addresses":["8.8.8.8"],
                "observed_epoch":NOW-1,"ttl_seconds":120,
                "https_only":True}],
        "redirects":[["ghcr.io","ghcr.io"]],
        "hostforwards":[list(x) for x in egress.HOSTPORTS],
        "cleanup":list(evidence.REQUIRED),
    }

class ProposedEgressTests(unittest.TestCase):
    def good(self,plan=None):
        return egress.compile_proposal(approved_proposal() if plan is None else plan,now_epoch=NOW)
    def blocked(self,plan,code=None):
        with self.assertRaises(egress.PolicyBlocked) as e:
            self.good(plan)
        if code:
            self.assertEqual(e.exception.code,code)
    def test_proposal_never_claims_observed_or_enforced(self):
        p=self.good()
        self.assertEqual(p.status,"OFFLINE_PROPOSED_NOT_OBSERVED_NOT_ENFORCED")
        self.assertNotIn("9.9.9.9",p.receipt())
        self.assertNotIn("ghcr.io",p.receipt())
    def test_single_reviewed_dns_exact_transport_rules(self):
        p=self.good()
        for proto in ("udp","tcp"):
            rule=f"-d 9.9.9.9/32 -p {proto} --dport 53 -j ACCEPT"
            self.assertEqual(p.ipv4_restore.count(rule),1)
        self.assertNotIn("-A PHASE2H_GUEST -p udp --dport 53 -j ACCEPT",p.ipv4_restore)
        self.assertEqual(p.ipv4_restore.count(" --dport 53 -j ACCEPT"),2)
    def test_limited_web_and_time(self):
        p=self.good()
        self.assertIn("-d 8.8.8.8/32 -p tcp --dport 443 -j ACCEPT",p.ipv4_restore)
        self.assertIn("-d 1.1.1.1/32 -p udp --dport 123 -j ACCEPT",p.ipv4_restore)
        self.assertNotIn("--dport 80 -j ACCEPT",p.ipv4_restore)
        self.assertNotIn("-p tcp --dport 22 -j ACCEPT",p.ipv4_restore)
        self.assertTrue(p.ipv4_restore.endswith("-A PHASE2H_GUEST -j REJECT\nCOMMIT\n"))
    def test_guest_ipv6_and_host_ipv6_denied(self):
        p=self.good()
        self.assertIn("ipv6=off",p.qemu_netdev)
        self.assertIn("-A PHASE2H_GUEST6 -j REJECT",p.ipv6_restore)
        self.assertEqual(p.ipv6_restore.count(" ACCEPT"),0)
        for change in ({"guest":"on","host":"deny"},{"guest":"off","host":"permit"}):
            v=approved_proposal();v["ipv6"]=change
            self.blocked(v,"IPV6_GUARD_MISSING")
    def test_forward_list_exact_and_loopback_only(self):
        p=self.good()
        self.assertEqual(p.qemu_netdev.count("hostfwd="),4)
        self.assertEqual(p.qemu_netdev.count("hostfwd=tcp:127.0.0.1:"),4)
        for bad in (
            [[18123,8123]],[[18123,8123],[18124,80],[14357,4357],[19583,22]],
            [[18123,8123],[18124,80],[14357,4357],[19583,9583],[2222,22]],
        ):
            v=approved_proposal();v["hostforwards"]=bad
            self.blocked(v,"UNEXPECTED_FORWARD")
    def test_loopback_reply_exception_not_broad(self):
        p=self.good()
        self.assertIn("-o lo -d 127.0.0.1/32 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT",p.ipv4_restore)
        self.assertIn("-d 127.0.0.0/8 -j REJECT",p.ipv4_restore)
        self.assertEqual(p.ipv4_restore.count("-o lo"),1)
    def test_dns_private_loopback_ipv6_and_reserved_rejected(self):
        for dns in ("127.0.0.53","127.0.0.1","10.0.0.1","192.168.1.1","172.20.1.1","169.254.1.2","100.64.1.1","::1","2001:4860:4860::8888","203.0.113.1"):
            with self.subTest(dns=dns):
                v=approved_proposal();v["dns"]["public_ipv4"]=dns
                self.blocked(v)
    def test_udp_or_tcp_only_rejected(self):
        for proto in ("udp","tcp"):
            v=approved_proposal();v["dns"][proto]=False
            self.blocked(v,"DNS_TRANSPORT_INCOMPLETE")
    def test_uncontrolled_resolver(self):
        v=approved_proposal();v["dns"]["resolver_control"]="from_env"
        self.blocked(v,"RESOLVER_ROUTE_NOT_CONTROLLED")
    def test_malformed_and_extra_schema_rejected(self):
        for change in ({"origin":"OBSERVED"},{"schema":2},{"owner_uid":-1},{"new_permission":"yes"}):
            v=approved_proposal();v.update(change)
            self.blocked(v)
    def test_wrong_or_unverified_ntp(self):
        for change in ({"mode":"UNKNOWN","public_ipv4":"1.1.1.1"},{"mode":"REVIEWED_NTP_DESTINATION","public_ipv4":"169.254.169.254"}):
            v=approved_proposal();v["ntp"]=change
            self.blocked(v)
    def test_web_private_and_unreviewed_rejected(self):
        for bad in ("10.0.0.2","192.168.1.2","127.0.0.1","::1","169.254.169.254"):
            v=approved_proposal();v["web"][0]["addresses"]=[bad]
            self.blocked(v)
        v=approved_proposal();v["web"][0]["https_only"]=False
        self.blocked(v,"UNREVIEWED_WEB_HOST_OR_HTTP")
    def test_redirect_must_be_bounded_to_approved_names(self):
        for edges in ([[ "ghcr.io","evil.invalid" ]], [["evil.invalid","ghcr.io"]]):
            v=approved_proposal();v["redirects"]=edges
            self.blocked(v,"UNREVIEWED_REDIRECT")
    def test_duplicate_and_too_many_web_destinations(self):
        v=approved_proposal();v["web"][0]["addresses"]=["8.8.8.8","8.8.8.8"]
        self.blocked(v,"INVALID_WEB_ADDRESS_SET")
        v=approved_proposal();v["web"]*=17
        self.blocked(v,"WEB_BOUND_INVALID")
    def test_dns_ttl_expiry_and_future_observation_rejected(self):
        for ttl,stamp in ((0,NOW-1),(1,NOW-2),(3601,NOW-1),(60,NOW+1)):
            v=approved_proposal();v["web"][0]["ttl_seconds"]=ttl;v["web"][0]["observed_epoch"]=stamp
            self.blocked(v,"DNS_BINDING_EXPIRED_OR_UNOBSERVED")
    def test_new_dns_addresses_or_expiry_stop_no_auto_widen(self):
        p=self.good()
        self.assertEqual(egress.handle_answer_change(p,current_epoch=NOW+1,new_addresses_equal=False),"BLOCKED_STOP_AND_REVIEW_REPLACEMENT")
        self.assertEqual(egress.handle_answer_change(p,current_epoch=p.expiry_epoch,new_addresses_equal=True),"BLOCKED_STOP_AND_REVIEW_REPLACEMENT")
        self.assertEqual(egress.handle_answer_change(p,current_epoch=NOW,new_addresses_equal=True),"OFFLINE_UNEXPIRED_SNAPSHOT_NOT_OBSERVED")
    def test_explicit_cleanup_contract_required(self):
        v=approved_proposal();v["cleanup"].remove("nbd_detached")
        self.blocked(v,"CLEANUP_CONTRACT_INCOMPLETE")
    def test_no_host_permission_to_applying_rules(self):
        text=(ROOT/"docs/security/phase2l/egress_compiler.py").read_text()
        for forbidden in ("import subprocess", "from subprocess", "import socket", "os.system(", "subprocess.run(", "subprocess.Popen("):
            self.assertNotIn(forbidden,text)

class AcceptanceEvidenceTests(unittest.TestCase):
    def test_16_known_gates_and_zero_actual_observers(self):
        self.assertEqual(len(evidence.GATES),16)
        self.assertEqual(evidence.RUNTIME_OBSERVERS,{})
        self.assertEqual(set(evidence.GATES),set(evidence.mod.REQUIRED))
        for gate in evidence.GATES:
            self.assertEqual(evidence.status_for_gate(gate,instrumented=False,live_verified=False),"NOT_TESTED_RUNTIME_PROOF_MISSING")
    def test_fake_runtime_flags_not_accepted(self):
        for gate in evidence.GATES:
            self.assertEqual(evidence.status_for_gate(gate,instrumented=True,live_verified=True),"BLOCKED_EXTERNAL_ATTESTATION_REQUIRED")
    def test_cleanup_all_mock_success_is_only_synthetic(self):
        self.assertEqual(len(evidence.REQUIRED),13)
        self.assertEqual(evidence.review_cleanup({k:True for k in evidence.REQUIRED}),"SYNTHETIC_CLEANUP_COMPLETE_NOT_RUNTIME_VERIFIED")
    def test_cleanup_missing_false_unknown_or_duplicate(self):
        allgood={k:True for k in evidence.REQUIRED}
        for k in evidence.REQUIRED:
            for val in (False,None,"PASS"):
                changed=allgood.copy();changed[k]=val
                self.assertEqual(evidence.review_cleanup(changed),"BLOCKED_CLEANUP_FAILED_OR_UNKNOWN")
            changed=allgood.copy();changed.pop(k)
            self.assertEqual(evidence.review_cleanup(changed),"BLOCKED_CLEANUP_INCOMPLETE")
        changed=allgood.copy();changed["unexpected"]=True
        self.assertEqual(evidence.review_cleanup(changed),"BLOCKED_CLEANUP_INCOMPLETE")
    def test_readback_recipe_covers_every_required_cleanup(self):
        self.assertEqual(set(evidence.future_readback_requirements()),set(evidence.REQUIRED))
    def test_no_synthetic_overall_pass(self):
        self.assertEqual(evidence.release_exit_code(["PASS"]*16,{k:True for k in evidence.REQUIRED}),6)
    def test_future_runner_still_aborts_before_privileged_path(self):
        text=(ROOT/"docs/security/phase2h/runner_once.sh").read_text()
        self.assertLess(text.index("docs/security/phase2l/runner_preflight.py"),text.index("sudo apt-get update"))
        self.assertIn('echo "PHASE2L_PRE_GUEST=BLOCKED_UNIMPLEMENTED_EGRESS_PROOF"',text)
        self.assertIn("exit 3",text)

    def test_qemu_source_matches_exact_compiled_netdev(self):
        # Python AST inspection does not execute QEMU or import the launcher.
        import ast
        file=ROOT/"docs/security/phase2h/single_haos_guest.py"
        code=ast.parse(file.read_text())
        fn=next(x for x in code.body if isinstance(x,ast.FunctionDef) and x.name=="launch_guest")
        cmd=next(x.value for x in fn.body if isinstance(x,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=="cmd" for t in x.targets))
        args=cmd.elts
        netarg=next(i for i,x in enumerate(args) if isinstance(x,ast.Constant) and x.value=="-netdev")
        self.assertIsInstance(args[netarg+1],ast.Constant)
        expected=self.good().qemu_netdev
        self.assertEqual(args[netarg+1].value,expected)
        self.assertEqual(sum(1 for x in args if isinstance(x,ast.Constant) and x.value=="-netdev"),1)
    def test_cleanup_exit_requires_runtime_readback(self):
        sh=(ROOT/"docs/security/phase2h/runner_once.sh").read_text()
        self.assertIn("PHASE2L_CLEANUP=BLOCKED_INCOMPLETE_RUNTIME_READBACK",sh)
        self.assertIn('if [[ "$exit_code" -eq 0 ]]; then',sh)
        self.assertIn("exit_code=6",sh)

    def test_immutable_guest_workflow_trigger(self):
        text=(ROOT/".github/workflows/phase2h-haos-vm-once.yml").read_text()
        self.assertIn("paths: [.github/workflows/phase2h-haos-vm-once.yml]",text)
        self.assertNotIn("workflow_dispatch",text)

if __name__=="__main__":
    unittest.main()
