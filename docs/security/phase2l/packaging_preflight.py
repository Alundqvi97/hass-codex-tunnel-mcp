"""Phase 2L: deterministic checks against the *staged* local add-on context.

Reads only paths supplied by the offline caller, runs no Docker, shells or
network. Validating COPY sources does not mean a Docker image was built.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

EXPECTED_POLICY = {
    "schema_version":2,"rule_effect":"allow",
    "rules":[{"tool_name":"ha_get_overview","when":[],"remember_minutes":0}],
    "version":0,
}
FILES = ("config.yaml","Dockerfile","start.py","pyproject.toml","uv.lock",
         "phase2k_bootstrap.py","phase2k_policy.json",
         "src/ha_mcp/__init__.py","src/ha_mcp/server.py",
         "src/ha_mcp/policy/middleware.py")

def hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def inspect_context(staged: Path, reference: Path) -> str:
    staged,reference=Path(staged),Path(reference)
    if not staged.is_dir() or staged.is_symlink() or not reference.is_dir():
        return "BLOCKED_CONTEXT_ROOT"
    for name in FILES:
        file=staged/name
        if file.is_symlink() or not file.is_file() or file.stat().st_size==0:
            return "BLOCKED_CONTEXT_FILE"
    for name in ("phase2k_bootstrap.py","phase2k_policy.json"):
        expected=reference/name
        if expected.is_symlink() or not expected.is_file() or hash_file(staged/name)!=hash_file(expected):
            return "BLOCKED_PINNED_PACKAGED_FILE"
    try:
        policy=json.loads((staged/"phase2k_policy.json").read_text(encoding="utf-8"))
        cfg=(staged/"config.yaml").read_text(encoding="utf-8")
        docker=(staged/"Dockerfile").read_text(encoding="utf-8")
        start=(staged/"start.py").read_text(encoding="utf-8")
        server=(staged/"src/ha_mcp/server.py").read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return "BLOCKED_CONTENT_UNREADABLE"
    if type(policy) is not dict or policy!=EXPECTED_POLICY:
        return "BLOCKED_POLICY_TEMPLATE"
    required_cfg=(
        'slug: "ha_mcp_phase2h"',
        '  require_strict_tool_policy: bool?',
        '  bootstrap_reviewed_policy: bool?',
        '  require_strict_tool_policy: false',
        '  bootstrap_reviewed_policy: false',
    )
    if any(cfg.count(key)!=1 for key in required_cfg) or re.search(r"(?m)^image:",cfg):
        return "BLOCKED_ADDON_SCHEMA"
    if "HA_MCP_REQUIRE_STRICT_POLICY" not in server:
        return "BLOCKED_STRICT_SERVER_PATCH"
    expected_copy=(
        "COPY pyproject.toml uv.lock ./",
        "COPY src/ ./src/",
        "COPY start.py /",
        "COPY phase2k_bootstrap.py /phase2k_bootstrap.py",
        "COPY phase2k_policy.json /phase2k_policy.json",
    )
    if any(docker.count(line)!=1 for line in expected_copy):
        return "BLOCKED_DOCKER_COPY"
    if "COPY homeassistant-addon/start.py /" in docker:
        return "BLOCKED_DOCKER_COPY"
    # No unexpected local COPY input. Multi-stage image COPY --from=builder
    # intentionally does not consume host build-context paths.
    for raw in docker.splitlines():
        line=raw.strip()
        if not line.startswith("COPY "):
            continue
        if line.startswith("COPY --from=builder "):
            continue
        if line not in expected_copy:
            return "BLOCKED_UNREVIEWED_DOCKER_COPY"
    try:
        bootstrap_at=start.index("bootstrap_reviewed_policy(")
        strict_at=start.index("strict_required = configure_supported_strict_policy(")
    except ValueError:
        return "BLOCKED_STARTUP_WIRING"
    if bootstrap_at>=strict_at:
        return "BLOCKED_STARTUP_ORDER"
    if "phase2k_policy.json" not in start or "phase2k_bootstrap" not in start:
        return "BLOCKED_STARTUP_WIRING"
    return "OFFLINE_BUILD_CONTEXT_CONSISTENT_NO_DOCKER_BUILD"
