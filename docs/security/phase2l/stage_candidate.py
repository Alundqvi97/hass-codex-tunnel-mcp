"""Phase 2L reproducible offline source staging; NOT an image build or install.

Used by future-only guest runner after SHA-guarded patches; CI also stages an
actual pinned and patched checkout into a temporary path without Docker/VM.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil

from packaging_preflight import inspect_context

SOURCE_FILES = ("config.yaml","Dockerfile","start.py")
ROOT_FILES = ("pyproject.toml","uv.lock")
BOOT_FILES = {"bootstrap_policy.py":"phase2k_bootstrap.py", "phase2k_policy.json":"phase2k_policy.json"}

def once(s: str, old: str, new: str) -> str:
    if s.count(old) != 1:
        raise ValueError("SOURCE_STAGING_ANCHOR_MISSING")
    return s.replace(old,new,1)

def stage(source: Path, destination: Path, reference: Path) -> str:
    source,destination,reference=Path(source),Path(destination),Path(reference)
    if not source.is_dir() or source.is_symlink() or destination.exists():
        raise ValueError("INVALID_SOURCE_OR_NONEMPTY_DESTINATION")
    if not reference.is_dir() or reference.is_symlink():
        raise ValueError("INVALID_REFERENCE")
    entries=[source/"homeassistant-addon"/f for f in SOURCE_FILES]+[source/f for f in ROOT_FILES]+[reference/f for f in BOOT_FILES]
    if any(x.is_symlink() or not x.is_file() for x in entries):
        raise ValueError("MISSING_OR_SYMLINK_SOURCE")
    src=source/"src"
    if not src.is_dir() or src.is_symlink():
        raise ValueError("MISSING_SRC")
    # Deny symlinks anywhere in the staged tree.
    if any(x.is_symlink() for x in src.rglob("*")):
        raise ValueError("SRC_SYMLINK_NOT_ALLOWED")
    destination.mkdir(parents=True,exist_ok=False)
    try:
        for f in SOURCE_FILES:
            shutil.copy2(source/"homeassistant-addon"/f,destination/f)
        for f in ROOT_FILES:
            shutil.copy2(source/f,destination/f)
        for source_name, destination_name in BOOT_FILES.items():
            shutil.copy2(reference/source_name,destination/destination_name)
        shutil.copytree(src,destination/"src",symlinks=False)
        cfg=destination/"config.yaml"
        s=cfg.read_text(encoding="utf-8")
        s=once(s,'slug: "ha_mcp"','slug: "ha_mcp_phase2h"')
        s=once(s,'version: "8.5.0"','version: "8.6.0"')
        s=once(s,'name: "Home Assistant MCP Server"','name: "Phase2H Synthetic MCP"')
        s=once(s,'image: "ghcr.io/homeassistant-ai/ha-mcp-addon-{arch}"\n',"")
        cfg.write_text(s,encoding="utf-8")
        docker=destination/"Dockerfile"
        d=docker.read_text(encoding="utf-8")
        d=once(d,"COPY homeassistant-addon/start.py /\n","COPY start.py /\n")
        docker.write_text(d,encoding="utf-8")
        status=inspect_context(destination,reference)
        if status!="OFFLINE_BUILD_CONTEXT_CONSISTENT_NO_DOCKER_BUILD":
            raise ValueError("BUILD_CONTEXT_BLOCKED")
        return status
    except Exception:
        # These are synthetic source files in a temporary directory, not
        # guest/Supervisor state. A failed stage cannot be reused accidentally.
        shutil.rmtree(destination,ignore_errors=True)
        raise

def main(argv=None) -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",type=Path,required=True)
    ap.add_argument("--destination",type=Path,required=True)
    ap.add_argument("--reference",type=Path,required=True)
    args=ap.parse_args(argv)
    try:
        status=stage(args.source,args.destination,args.reference)
    except (ValueError,OSError):
        print("PHASE2L_BUILD_CONTEXT=BLOCKED")
        return 3
    print("PHASE2L_BUILD_CONTEXT="+status)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
