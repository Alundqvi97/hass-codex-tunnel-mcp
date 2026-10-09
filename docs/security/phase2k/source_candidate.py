"""Phase 2K: anchored source-only patch for disposable pinned HA-MCP add-on.

Apply after Phase 2D + 2F patches to a *disposable* checked-out upstream
revision. Does not access production, Supervisor, HTTP, or an OS image.
"""
from pathlib import Path
import argparse
import subprocess

PINNED_COMMIT = "fc54437a804858732e4bc927add98e202d879a09"

def once(data: str, needle: str, replacement: str) -> str:
    count = data.count(needle)
    if count != 1:
        raise ValueError("PHASE2K_PATCH_ANCHOR_MISMATCH")
    return data.replace(needle, replacement, 1)

def candidate_changes(config: str, start: str, docker: str):
    if "strict_required = configure_supported_strict_policy(data_dir, config_file)" not in start:
        raise ValueError("PHASE2F_STRICT_PREREQUISITE_MISSING")
    if "bootstrap_reviewed_policy" in start or "bootstrap_reviewed_policy:" in config:
        raise ValueError("PHASE2K_DUPLICATE")
    config = once(
        config, "  require_strict_tool_policy: false\n",
        "  require_strict_tool_policy: false\n  bootstrap_reviewed_policy: false\n")
    config = once(
        config, "  require_strict_tool_policy: bool?\n",
        "  require_strict_tool_policy: bool?\n  bootstrap_reviewed_policy: bool?\n")
    start = once(
        start,
        "        strict_required = configure_supported_strict_policy(data_dir, config_file)\n",
        '        from phase2k_bootstrap import bootstrap_reviewed_policy\n'
        '        bootstrap_status = bootstrap_reviewed_policy(\n'
        '            data_dir, config_file, Path("/phase2k_policy.json")\n'
        '        )\n'
        '        if bootstrap_status == "INITIALIZED":\n'
        '            log_info("PHASE2K_BOOTSTRAP_INITIALIZED")\n'
        '        strict_required = configure_supported_strict_policy(data_dir, config_file)\n')
    docker = once(
        docker, "COPY homeassistant-addon/start.py /\n",
        "COPY homeassistant-addon/start.py /\n"
        "COPY phase2k_bootstrap.py /phase2k_bootstrap.py\n"
        "COPY phase2k_policy.json /phase2k_policy.json\n")
    return config, start, docker

def apply_to_root(root: Path):
    """No edits until every anchor validates. Verify upstream Git revision."""
    root = Path(root).resolve()
    git_sha = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if git_sha != PINNED_COMMIT:
        raise ValueError("UPSTREAM_COMMIT_NOT_PINNED")
    rels = (
        "homeassistant-addon/config.yaml",
        "homeassistant-addon/start.py",
        "homeassistant-addon/Dockerfile",
    )
    sources = [(root / rel).read_text(encoding="utf-8") for rel in rels]
    changed = candidate_changes(*sources)
    for rel, text in zip(rels, changed):
        (root / rel).write_text(text, encoding="utf-8")
    return rels

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path("ha_mcp_pinned"))
    p.add_argument("--apply", action="store_true")
    args=p.parse_args()
    if not args.apply:
        raise ValueError("REQUIRES_EXPLICIT_DISPOSABLE_CHECKOUT_APPLY_FLAG")
    apply_to_root(args.root)
    print("PHASE2K_SOURCE_CANDIDATE_APPLIED_TO_PINNED_CHECKOUT")

if __name__=="__main__":
    main()
