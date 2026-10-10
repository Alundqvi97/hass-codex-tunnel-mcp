"""Phase 2K — only synthetic files and source; no HA, QEMU or networking."""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def load(name, filename):
    spec=importlib.util.spec_from_file_location(name, ROOT/"docs/security/phase2k"/filename)
    obj=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=obj
    spec.loader.exec_module(obj)
    return obj
m=load("phase2k_bootstrap", "bootstrap_policy.py")
candidate=load("phase2k_candidate", "source_candidate.py")

class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.data=self.root/"data"
        self.data.mkdir()
        self.opts=self.data/"options.json"
        self.package=self.root/"phase2k_policy.json"
        self.package.write_bytes(m._POLICY_BYTES)
        self.options={"bootstrap_reviewed_policy":True,
                      "require_strict_tool_policy":True,
                      "enable_tool_security_policies":True,
                      "enable_security_policy_tool":False}
        self.save_options()
    def save_options(self):
        self.opts.write_text(json.dumps(self.options))
    def run_init(self):
        return m.bootstrap_reviewed_policy(self.data,self.opts,self.package)
    def test_first_install_policy_exact_and_mode(self):
        self.assertEqual(self.run_init(),"INITIALIZED")
        p=self.data/"tool_policy.json"
        self.assertEqual(p.read_bytes(),m._POLICY_BYTES)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
        obj=json.loads(p.read_bytes())
        self.assertEqual(obj["rule_effect"],"allow")
        self.assertEqual([x["tool_name"] for x in obj["rules"]],["ha_get_overview"])
    def test_missing_arm_never_installs(self):
        self.options["bootstrap_reviewed_policy"]=False;self.save_options()
        self.assertEqual(self.run_init(),"NOT_ARMED")
        self.assertFalse((self.data/"tool_policy.json").exists())
    def test_unsafe_options_block(self):
        baseline=self.options.copy()
        for key,value in (("require_strict_tool_policy",False),
                          ("enable_tool_security_policies",False),
                          ("enable_security_policy_tool",True),
                          ("bootstrap_reviewed_policy","true"),
                          ("require_strict_tool_policy",None)):
            with self.subTest(key=key,value=value):
                self.options=baseline.copy()
                self.options[key]=value
                self.save_options()
                with self.assertRaises(ValueError):self.run_init()
                self.assertFalse((self.data/"tool_policy.json").exists())
        self.options=baseline.copy()
        self.save_options()
    def test_broken_template_never_installs(self):
        self.package.write_text('{"rule_effect":"require_approval","rules":[]}')
        with self.assertRaises(ValueError):self.run_init()
        self.assertFalse((self.data/"tool_policy.json").exists())
    def test_symlink_template_refused(self):
        other=self.root/"other";other.write_bytes(m._POLICY_BYTES)
        self.package.unlink();self.package.symlink_to(other)
        with self.assertRaises(ValueError):self.run_init()
    def test_marker_requires_manual_recovery(self):
        (self.data/"strict_policy_required.v1.json").write_text('{"required":true}')
        with self.assertRaises(ValueError):self.run_init()
        self.assertFalse((self.data/"tool_policy.json").exists())
    def test_existing_corrupt_never_reset(self):
        p=self.data/"tool_policy.json";p.write_text("malformed")
        self.assertEqual(self.run_init(),"EXISTING_UNTOUCHED")
        self.assertEqual(p.read_text(),"malformed")
    def test_existing_valid_never_overwritten(self):
        p=self.data/"tool_policy.json";p.write_bytes(m._POLICY_BYTES)
        self.assertEqual(self.run_init(),"EXISTING_UNTOUCHED")
        self.assertEqual(p.read_bytes(),m._POLICY_BYTES)
    def test_policy_symlink_refused(self):
        target=self.root/"target";target.write_bytes(m._POLICY_BYTES)
        (self.data/"tool_policy.json").symlink_to(target)
        with self.assertRaises(ValueError):self.run_init()
        self.assertEqual(target.read_bytes(),m._POLICY_BYTES)
    def test_options_not_json_or_missing(self):
        self.opts.write_text("{invalid")
        with self.assertRaises(ValueError):self.run_init()
        self.opts.unlink()
        with self.assertRaises(ValueError):self.run_init()
    def test_data_symlink_refused(self):
        alternate=self.root/"alias";alternate.symlink_to(self.data,target_is_directory=True)
        with self.assertRaises(ValueError):
            m.bootstrap_reviewed_policy(alternate,self.opts,self.package)
    def test_interrupted_fsync_leaves_file_and_never_retries(self):
        with patch.object(m.os, "fsync", side_effect=OSError("simulated failure")):
            with self.assertRaises(OSError):self.run_init()
        # Deliberately no implicit repair of a partial policy.
        self.assertTrue((self.data/"tool_policy.json").exists())
        self.assertEqual(self.run_init(),"EXISTING_UNTOUCHED")
    def test_synthetic_restore_from_known_good_bytes(self):
        self.assertEqual(self.run_init(),"INITIALIZED")
        p=self.data/"tool_policy.json"
        p.write_text("corrupt")
        self.assertEqual(self.run_init(),"EXISTING_UNTOUCHED")
        # Merely simulates an external restore, NOT real Supervisor backup.
        p.write_bytes(m._POLICY_BYTES)
        self.assertEqual(self.run_init(),"EXISTING_UNTOUCHED")
        self.assertEqual(p.read_bytes(),m._POLICY_BYTES)
    def test_no_network_or_shell_in_bootstrap(self):
        txt=(ROOT/"docs/security/phase2k/bootstrap_policy.py").read_text()
        for forbidden in ("subprocess", "urllib", "requests.", "socket.", "http://supervisor"):
            self.assertNotIn(forbidden,txt)

class PatchTests(unittest.TestCase):
    def test_patch_anchor_replaces_once_and_wires_before_strict(self):
        conf="  require_strict_tool_policy: false\n  require_strict_tool_policy: bool?\n"
        start="    try:\n        strict_required = configure_supported_strict_policy(data_dir, config_file)\n"
        docker="COPY homeassistant-addon/start.py /\n"
        conf2,start2,docker2=candidate.candidate_changes(conf,start,docker)
        self.assertIn("bootstrap_reviewed_policy: bool?",conf2)
        self.assertIn('from phase2k_bootstrap import bootstrap_reviewed_policy',start2)
        self.assertLess(start2.index("bootstrap_reviewed_policy("),start2.index("configure_supported_strict_policy("))
        self.assertIn("COPY phase2k_bootstrap.py /phase2k_bootstrap.py",docker2)
        self.assertIn("COPY phase2k_policy.json /phase2k_policy.json",docker2)
        with self.assertRaises(ValueError):candidate.candidate_changes(conf2,start2,docker2)
    def test_bad_anchors_refuse_changes(self):
        with self.assertRaises(ValueError):
            candidate.candidate_changes("irrelevant","nothing","COPY homeassistant-addon/start.py /")
    def test_future_runner_stages_only_app_source(self):
        sh=(ROOT/"docs/security/phase2h/runner_once.sh").read_text()
        self.assertIn("supervisor/apps/local/ha_mcp_phase2h",sh)
        self.assertIn("source_candidate.py --root ha_mcp_pinned --apply",sh)
        self.assertNotIn('supervisor/addons/data/local_ha_mcp_phase2h',sh)
        self.assertNotIn('tee "$WORK/mount/supervisor',sh)
    def test_future_guest_configures_bootstrap_via_supervisor(self):
        source=(ROOT/"docs/security/phase2h/single_haos_guest.py").read_text()
        self.assertIn('"bootstrap_reviewed_policy":True',source)
        self.assertIn('"require_strict_tool_policy":True',source)
        self.assertIn('"enable_security_policy_tool":False',source)
        self.assertIn("BLOCKED_INCOMPLETE_16_CASES",source)
        self.assertIn("return 6",source)
    def test_vm_workflow_immutable_trigger(self):
        source=(ROOT/".github/workflows/phase2h-haos-vm-once.yml").read_text()
        self.assertIn("paths: [.github/workflows/phase2h-haos-vm-once.yml]",source)
        self.assertNotIn("workflow_dispatch",source)
if __name__=="__main__":
    unittest.main()
