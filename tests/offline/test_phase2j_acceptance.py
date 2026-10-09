"""Deterministic Phase 2J acceptance checks; no guest, network or privilege."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location("phase2j_acceptance", ROOT/"docs/security/phase2j/acceptance.py")
mod=importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name]=mod
SPEC.loader.exec_module(mod)

class AcceptanceTests(unittest.TestCase):
    def test_sixteen_stable_gates(self):
        self.assertEqual(len(mod.GATES), 16)
        self.assertEqual(len(set(mod.REQUIRED)),16)
        self.assertEqual([g.name for g in mod.GATES], mod.REQUIRED)
    def test_default_fails_closed(self):
        a=mod.Acceptance()
        self.assertEqual(a.verdict(),"BLOCKED")
        self.assertEqual(a.exit_code(),6)
        self.assertEqual(len(a.sanitized()),16)
    def test_unknown_gate_and_status(self):
        a=mod.Acceptance()
        for name, status in (("IMAGINARY","PASS"),("HAOS_BOOT","UNKNOWN"),("HAOS_BOOT","NOT_TESTED")):
            with self.assertRaises(ValueError): a.record(name,status)
    def test_unverified_and_fake_origin_cannot_pass(self):
        a=mod.Acceptance()
        for origin,proof,verified in (("HAOS","HAOS_KERNEL_BOOT",False),("SYNTHETIC","HAOS_KERNEL_BOOT",True),("HAOS","random",True)):
            with self.assertRaises(ValueError):
                a.record("HAOS_BOOT","PASS",origin=origin,proof=proof,runtime_verified=verified)
        self.assertEqual(a.exit_code(),6)
    def test_prerequisites_strict(self):
        a=mod.Acceptance()
        g=mod.GATE_BY_NAME["SUPERVISOR_READY"]
        with self.assertRaises(ValueError):
            a.record(g.name,"PASS",proof=g.proof,origin=g.origin,runtime_verified=True)
    def test_terminal_failure_cannot_upgrade(self):
        a=mod.Acceptance()
        a.record("HAOS_BOOT","FAIL")
        with self.assertRaises(ValueError):
            a.record("HAOS_BOOT","PASS",proof="HAOS_KERNEL_BOOT",origin="HAOS",runtime_verified=True)
        self.assertEqual(a.verdict(),"FAIL")
    def test_blocked_and_not_tested_never_pass(self):
        a=mod.Acceptance()
        a.record("HAOS_BOOT","BLOCKED")
        self.assertEqual(a.exit_code(),6)
        self.assertEqual(a.verdict(),"BLOCKED")
    def test_exception_strings_not_accepted_as_receipts(self):
        a=mod.Acceptance()
        for extra in ({"proof":"/_secret_token"}, {"origin":"https://private"}, {"runtime_verified":True}):
            with self.assertRaises(ValueError): a.record("HAOS_BOOT","FAIL",**extra)
    def test_all_synthetic_success_only_when_explicit_mocked(self):
        # Simulates every runtime observer; DOES NOT verify a real Supervisor.
        a=mod.Acceptance()
        for g in mod.GATES:
            a.record(g.name,"PASS",proof=g.proof,origin=g.origin,runtime_verified=True)
        self.assertTrue(a.passed())
        self.assertEqual(a.verdict(),"PASS")
        self.assertEqual(a.exit_code(),6) # cleanup is independent
        for key in mod.CLEANUP:a.record_cleanup(key,True)
        self.assertEqual(a.exit_code(),0) # purely in-memory simulation
    def test_cleanup_partial_fails_closed(self):
        a=mod.Acceptance()
        for x in mod.CLEANUP[:-1]:a.record_cleanup(x,True)
        self.assertFalse(a.cleanup_complete())
        a.record_cleanup(mod.CLEANUP[-1],False)
        self.assertFalse(a.cleanup_complete())
    def test_cleanup_cannot_be_overwritten(self):
        a=mod.Acceptance()
        a.record_cleanup("guest_absent",False)
        with self.assertRaises(ValueError):a.record_cleanup("guest_absent",True)
    def test_cleanup_cannot_use_non_boolean(self):
        with self.assertRaises(ValueError):mod.Acceptance().record_cleanup("guest_absent","PASS")
    def test_sanitized_output_has_fixed_shape(self):
        a=mod.Acceptance()
        a.record("HAOS_BOOT","FAIL")
        msg="\n".join(a.sanitized())
        self.assertNotIn("secret",msg)
        self.assertNotIn("https://",msg)
        self.assertIn("CASE_01=FAIL",msg)
    def test_dns_loopback_refused(self):
        result=mod.check_bootstrap_policy(["127.0.0.53"],udp53_destinations=["127.0.0.53"],tcp53_destinations=["127.0.0.53"],public_tcp_ports=[80,443],ipv6_enabled=False,forwards_local=True)
        self.assertEqual(result,"BLOCKED")
    def test_dns_private_and_ipv6_refused(self):
        for addr in ("10.0.2.3","192.168.1.1","::1","169.254.169.254"):
            with self.subTest(addr=addr):
                self.assertEqual(mod.check_bootstrap_policy([addr],udp53_destinations=[addr],tcp53_destinations=[addr],public_tcp_ports=[80,443],ipv6_enabled=False,forwards_local=True),"BLOCKED")
    def test_dns_tcp_fallback_required(self):
        self.assertEqual(mod.check_bootstrap_policy(["1.1.1.1"],udp53_destinations=["1.1.1.1"],tcp53_destinations=[],public_tcp_ports=[80,443],ipv6_enabled=False,forwards_local=True),"BLOCKED")
    def test_public_dns_only_model_not_proof(self):
        self.assertEqual(mod.check_bootstrap_policy(["1.1.1.1"],udp53_destinations=["1.1.1.1"],tcp53_destinations=["1.1.1.1"],public_tcp_ports=[80,443],ipv6_enabled=False,forwards_local=True),"OFFLINE_CONSISTENT_NOT_NETWORK_VERIFIED")
    def test_reject_bad_forwarding(self):
        self.assertEqual(mod.check_bootstrap_policy(["1.1.1.1"],udp53_destinations=["1.1.1.1"],tcp53_destinations=["1.1.1.1"],public_tcp_ports=[80,443],ipv6_enabled=False,forwards_local=False),"BLOCKED")
    def test_synthetic_local_layout(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)/"supervisor"/"apps"/"local"/"ha_mcp_phase2j"
            folder.mkdir(parents=True)
            (folder/"config.yaml").write_text("synthetic")
            (folder/"Dockerfile").write_text("synthetic")
            good=mod.validate_local_app_fixture(d,slug="ha_mcp_phase2j",expected_files=["config.yaml","Dockerfile"])
            self.assertEqual(good,"SOURCE_LAYOUT_ONLY_NOT_INSTALLED")
            self.assertEqual(mod.validate_local_app_fixture(d,slug="../../etc",expected_files=["config.yaml"]),"BLOCKED")
            self.assertEqual(mod.validate_local_app_fixture(d,slug="ha_mcp_phase2j",expected_files=["missing.py"]),"BLOCKED")
    def test_legacy_layout_cannot_prove_install(self):
        with tempfile.TemporaryDirectory() as d:
            x=Path(d)/"supervisor"/"addons"/"local"/"ha_mcp_phase2j"
            x.mkdir(parents=True)
            (x/"config.yaml").write_text("synthetic")
            self.assertEqual(mod.validate_local_app_fixture(d,slug="ha_mcp_phase2j",expected_files=["config.yaml"]),"BLOCKED")
    def test_existing_guest_script_stays_fail_closed(self):
        source=(ROOT/"docs/security/phase2h/single_haos_guest.py").read_text()
        self.assertIn('BLOCKED_INCOMPLETE_16_CASES',source)
        self.assertIn('return 6',source)
    def test_workflow_never_launches_vm(self):
        source=(ROOT/".github/workflows/phase2j-offline-only.yml").read_text()
        for forbidden in ("qemu-system", "sudo ", "workflow_dispatch", "runner_once.sh", "single_haos_guest.py", "iptables", "docker run"):
            self.assertNotIn(forbidden,source)
        vm=(ROOT/".github/workflows/phase2h-haos-vm-once.yml").read_text()
        self.assertIn("paths: [.github/workflows/phase2h-haos-vm-once.yml]",vm)
        self.assertNotIn("workflow_dispatch:",vm)

if __name__=="__main__":unittest.main()
