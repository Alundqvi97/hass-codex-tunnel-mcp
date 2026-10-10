"""Archive install + schema upgrade + unsafe downgrade refusal + recovery."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import io
import test_admin_product as product

spec = importlib.util.spec_from_file_location("admin_release_builder", product.REPO/"scripts/development/package.py")
package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)


class ReleaseArchive(unittest.TestCase):
    def test_actual_archives_install_upgrade_reject_unsafe_downgrade_and_recover(self):
        with tempfile.TemporaryDirectory(prefix="native-admin-packages-") as owned:
            root = Path(owned)
            current = root / "current.zip"
            supplied = os.environ.get("ADMIN_RELEASE_ARCHIVE")
            if supplied: shutil.copyfile(supplied, current)
            else: package.build(current)
            manifest = package.verify(current)
            self.assertNotIn("tests/", " ".join(manifest["files"]))
            self.assertNotIn("probe_a", " ".join(manifest["files"]))
            # Exact reviewed original, not a moving remote or a fabricated older
            # release. This archive is a disposable compatibility fixture only.
            revision = "a7ad7a6a3362262e0a5f3b8d8a04998106d42acc"
            subprocess.run(["git", "merge-base", "--is-ancestor", revision, "HEAD"], cwd=product.REPO, check=True)
            data = subprocess.run(["git", "archive", revision, "custom_components/hass_codex_admin", "custom_components/hass_codex_tunnel_mcp"], cwd=product.REPO, check=True, stdout=subprocess.PIPE).stdout
            previous = root / "previous-source"; previous.mkdir()
            with tarfile.open(fileobj=io.BytesIO(data)) as archive: archive.extractall(previous, filter="data")
            legacy = root / "legacy.zip"; package.build(legacy, previous)
            config = root / "ha"; config.mkdir()
            active = None
            for stage, archive in (("legacy", legacy), ("upgraded", current), ("unsafe-downgrade", legacy), ("recovered", current)):
                if active:
                    # Verify that replacement touches only owned installed code;
                    # auth, DB, configurations and backups remain untouched.
                    for name, record in package.verify(active)["files"].items():
                        self.assertEqual(hashlib.sha256((config/name).read_bytes()).hexdigest(), record["sha256"])
                    shutil.rmtree(config/"custom_components")
                package.install_fresh(archive, config)
                environment = {**os.environ, "ADMIN_RELEASE_ARCHIVE": str(archive), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPYCACHEPREFIX": str(root/"pycache")}
                process = subprocess.run([sys.executable, "-B", str(product.REPO/"tests/staging/admin_package_process.py"), stage, str(config)], cwd=product.REPO, env=environment, capture_output=True, text=True, timeout=25)
                self.assertEqual(process.returncode, 0, process.stderr[-8000:])
                self.assertIn("PACKAGE_TRANSITION="+stage+":PASS", process.stdout)
                active = archive
            # Both reviewed manifests and current schema passed through real
            # processes; unsafe historical downgrade remains deliberately blocked.
