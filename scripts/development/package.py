#!/usr/bin/env python3
"""Deterministic production-only component archive; no dependencies or fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ("hass_codex_admin", "hass_codex_tunnel_mcp")


def build(destination, root=ROOT):
    files = {}
    for component in COMPONENTS:
        for path in sorted((root / "custom_components" / component).rglob("*")):
            if path.is_symlink():
                raise ValueError("Symlinks are not release assets")
            if path.is_file() and "__pycache__" not in path.parts:
                if path.suffix not in {".py", ".js", ".json", ".yaml"}:
                    raise ValueError("Unexpected component asset: "+path.name)
                files[path.relative_to(root).as_posix()] = path.read_bytes()
    manifest = {"format": 1, "components": {name: json.loads(files[f"custom_components/{name}/manifest.json"])["version"] for name in COMPONENTS}, "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in files.items()}, "supported_core": "2026.10.x; acceptance tested on 2026.10.0", "enablement": "Optional component requires explicit owner policy; production/staging authorization is separate"}
    files["release_manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True)+"\n").encode()
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (2026, 10, 10, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, data)
    verify(destination)
    return hashlib.sha256(Path(destination).read_bytes()).hexdigest()


def verify(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 250:
            raise ValueError("Duplicate/oversized release archive")
        manifest = json.loads(archive.read("release_manifest.json"))
        if set(names) != {"release_manifest.json"} | set(manifest["files"]):
            raise ValueError("Unmanifested release asset")
        if set(manifest["components"]) != set(COMPONENTS):
            raise ValueError("Unexpected component set")
        for name, record in manifest["files"].items():
            parts = PurePosixPath(name).parts
            if len(parts) < 3 or parts[0] != "custom_components" or parts[1] not in COMPONENTS or ".." in parts or PurePosixPath(name).is_absolute() or "\\" in name or "__pycache__" in parts:
                raise ValueError("Unsafe release path")
            info = archive.getinfo(name)
            if not stat.S_ISREG(info.external_attr >> 16) or info.file_size > 500000 or info.file_size != record["bytes"]:
                raise ValueError("Invalid release asset")
            if hashlib.sha256(archive.read(name)).hexdigest() != record["sha256"]:
                raise ValueError("Release asset digest mismatch")
        return manifest


def install_fresh(path, directory):
    """Fixture installer: refuses replacement, symlinks or unrelated files."""
    verify(path)
    directory = Path(directory)
    target = directory / "custom_components"
    if target.exists() or target.is_symlink():
        raise ValueError("Fresh install requires an absent custom_components directory")
    directory.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name == "release_manifest.json":
                continue
            destination = directory / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(name) as source, destination.open("xb") as output:
                shutil.copyfileobj(source, output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify(args.archive), sort_keys=True))
    else:
        print(build(args.archive)+"  "+args.archive.name)
