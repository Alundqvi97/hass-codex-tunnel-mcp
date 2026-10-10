import importlib.util
import sys
import unittest
from pathlib import Path

root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("phase2j_install",root/"docs/security/phase2j/installation_plan.py")
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)

class InstallPlanTests(unittest.TestCase):
    def test_version_bound_routes(self):
        s=m.v2_api_steps("2026.10.1","local_ha_mcp_phase2h")
        self.assertEqual(s[0].path,"/store/reload")
        self.assertEqual(s[2].path,"/store/apps/local_ha_mcp_phase2h/install")
        self.assertEqual(s[-1].path,"/apps/local_ha_mcp_phase2h/info")
    def test_unknown_version_fails_closed(self):
        for v in ("unknown","2026.10.0","2026.09.3",""):
            with self.assertRaises(ValueError):m.v2_api_steps(v,"local_ha_mcp_phase2h")
    def test_invalid_slug_blocked(self):
        for s in ("other_app","local_../x","local_x/a","local_x?y=1"):
            with self.assertRaises(ValueError):m.v2_api_steps("2026.10.1",s)
    def test_discovery_is_not_installation(self):
        p=m.SyntheticSequence(m.v2_api_steps("2026.10.1","local_ha_mcp_phase2h"))
        for s in p.steps[:2]:p.record(s.name,observed=True)
        self.assertEqual(p.verdict(),"BLOCKED")
    def test_full_mock_is_not_real_proof(self):
        p=m.SyntheticSequence(m.v2_api_steps("2026.10.1","local_ha_mcp_phase2h"))
        for s in p.steps:p.record(s.name,observed=True)
        self.assertEqual(p.verdict(),"SYNTHETIC_ONLY_NOT_INSTALLED")
    def test_failure_permanently_blocks(self):
        p=m.SyntheticSequence(m.v2_api_steps("2026.10.1","local_ha_mcp_phase2h"))
        with self.assertRaises(ValueError):p.record("INSTALL_REQUEST",observed=True)
        with self.assertRaises(ValueError):p.record("STORE_RELOAD",observed=True)
        self.assertEqual(p.verdict(),"BLOCKED")
    def test_meta_lint(self):
        files=("config.yaml","Dockerfile","start.py","pyproject.toml","uv.lock","src/")
        meta={"slug":"ha_mcp_phase2h","require_strict_tool_policy_schema":"bool?"}
        self.assertEqual(m.check_build_metadata(meta,"COPY start.py /",files),"BUILD_METADATA_LINT_ONLY")
        self.assertEqual(m.check_build_metadata(dict(meta,image="unmodified"),"COPY start.py /",files),"BLOCKED")
        self.assertEqual(m.check_build_metadata(meta,"COPY elsewhere /",files),"BLOCKED")
        self.assertEqual(m.check_build_metadata(meta,"COPY start.py /",files[:-1]),"BLOCKED")
if __name__=="__main__":unittest.main()
