import importlib.util
import sys
import unittest
from pathlib import Path
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("phase2k_check",root/"docs/security/phase2k/installation_checks.py")
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)
class EvidenceTests(unittest.TestCase):
    def sample(self):
        return dict(
            source_sha=m.EXPECTED_SOURCE_SHA,slug=m.EXPECTED_SLUG,version=m.EXPECTED_VERSION,
            store_discovered=True,install_api_accepted=True,installed=True,
            strict_schema=True,strict_options_saved=True,strict_options_readback=True,
            bootstrap_flag_saved=True,bootstrap_first_start_observed=True,
            policy_read_only_verified=True,running=True,harmless_tool_read=True,
            negative_privileged_dispatch_denied=True,restore_documented=True,
            cleanup_complete=True,image_digest="sha256:"+"a"*64,
            reviewed_image_digest="sha256:"+"a"*64,
            candidate_patch_sha="b"*40)
    def test_all_synthetic_still_not_runtime(self):
        self.assertEqual(m.check_synthetic_install(self.sample()),"SYNTHETIC_COMPLETE_NOT_REAL_SUPERVISOR")
    def test_missing_and_incorrect_source(self):
        for update in ({"source_sha":"bad"},{"source_sha":""},{"source_sha":None}):
            with self.subTest(update=update):
                e=self.sample();e.update(update)
                self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_absent_in_store_and_install_error(self):
        for name in ("store_discovered","install_api_accepted","installed"):
            e=self.sample();e[name]=False
            self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_successful_api_without_image_is_not_install(self):
        e=self.sample();e["installed"]=False
        self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
        e=self.sample();e.pop("image_digest")
        self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_wrong_image_digest_and_source(self):
        for k,v in (("image_digest","sha256:"+"c"*64),("image_digest","not-a-digest"),("candidate_patch_sha","other")):
            e=self.sample();e[k]=v
            self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_schema_options_and_bootstrap_denials(self):
        for k in ("strict_schema","strict_options_saved","strict_options_readback",
                  "bootstrap_flag_saved","bootstrap_first_start_observed"):
            e=self.sample();e[k]=False
            self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_policy_missing_or_unsafe(self):
        for k in ("policy_read_only_verified","negative_privileged_dispatch_denied","harmless_tool_read"):
            e=self.sample();e[k]=False
            self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_failed_start_and_recovery_and_cleanup(self):
        for k in ("running","restore_documented","cleanup_complete"):
            e=self.sample();e[k]=False
            self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_invalid_boolean_type_not_accepted(self):
        e=self.sample();e["installed"]=1
        self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_bad_slug_and_version(self):
        for k,val in (("slug","local_other"),("version","8.5.0")):
            e=self.sample();e[k]=val
            self.assertEqual(m.check_synthetic_install(e),"BLOCKED")
    def test_16_gate_skips_cannot_pass(self):
        assert m.phase2j_16_gates_still_required(tuple("PASS" for _ in range(16)))!="VERIFIED_SUPERVISOR"
        self.assertEqual(m.phase2j_16_gates_still_required(tuple("PASS" for _ in range(15))),"BLOCKED")
        self.assertEqual(m.phase2j_16_gates_still_required(tuple(["PASS"]*15+["NOT_TESTED"])),"BLOCKED")

if __name__=="__main__":
    unittest.main()
