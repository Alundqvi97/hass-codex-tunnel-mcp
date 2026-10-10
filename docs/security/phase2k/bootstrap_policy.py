"""Phase 2K candidate: first-install-only packaged policy bootstrap.

This module is copied into the disposable test add-on image. It does not
talk to HA, Supervisor, the MCP endpoint, or the network. No production use.
Only an explicitly armed Supervisor option can create a missing policy.
Never overwrite an existing or corrupted policy, or bypass the strict marker.
"""
from __future__ import annotations
import json
import os
from pathlib import Path

_POLICY_BYTES = (
    b'{"schema_version":2,"rule_effect":"allow","rules":'
    b'[{"tool_name":"ha_get_overview","when":[],"remember_minutes":0}],'
    b'"version":0}\n'
)
_POLICY_NAME = "tool_policy.json"
_MARKER_NAME = "strict_policy_required.v1.json"
_MAX_OPTIONS = 65536
_MAX_TEMPLATE = 512

def bootstrap_reviewed_policy(data_dir: Path, options_file: Path, package_template: Path) -> str:
    """Provision only an absent strict positive allow-list on first start.

    Returns a fixed label. Raises ValueError or OSError; upstream strict
    preflight catches these and aborts before the MCP listener is opened.
    """
    data_dir = Path(data_dir)
    options_file = Path(options_file)
    package_template = Path(package_template)
    if not data_dir.is_dir() or data_dir.is_symlink():
        raise ValueError("INVALID_ADDON_DATA_VOLUME")
    if options_file.is_symlink() or not options_file.is_file():
        raise ValueError("SUPERVISOR_OPTIONS_UNAVAILABLE")
    if options_file.stat().st_size > _MAX_OPTIONS:
        raise ValueError("SUPERVISOR_OPTIONS_OVERSIZED")
    try:
        opts = json.loads(options_file.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("SUPERVISOR_OPTIONS_UNREADABLE") from exc
    if not isinstance(opts, dict):
        raise ValueError("SUPERVISOR_OPTIONS_INVALID")
    arm = opts.get("bootstrap_reviewed_policy", False)
    if type(arm) is not bool:
        raise ValueError("POLICY_BOOTSTRAP_OPTION_INVALID")

    policy = data_dir / _POLICY_NAME
    marker = data_dir / _MARKER_NAME
    if policy.is_symlink():
        raise ValueError("POLICY_SYMLINK_REJECTED")
    if policy.exists():
        # Strict preflight subsequently validates contents even if corrupt.
        return "EXISTING_UNTOUCHED"
    if marker.exists() or marker.is_symlink():
        raise ValueError("POLICY_MISSING_WITH_MANDATORY_MARKER")
    if not arm:
        return "NOT_ARMED"

    if opts.get("require_strict_tool_policy") is not True:
        raise ValueError("STRICT_OPTION_NOT_ENABLED")
    if opts.get("enable_tool_security_policies") is not True:
        raise ValueError("POLICY_ENGINE_NOT_ENABLED")
    if opts.get("enable_security_policy_tool") is not False:
        raise ValueError("REMOTE_POLICY_EDIT_TOOL_NOT_DISABLED")
    if package_template.is_symlink() or not package_template.is_file():
        raise ValueError("PACKAGED_TEMPLATE_UNAVAILABLE")
    if package_template.stat().st_size > _MAX_TEMPLATE:
        raise ValueError("PACKAGED_TEMPLATE_OVERSIZED")
    # Exact pinned bytes, not merely schema-valid alternative content.
    if package_template.read_bytes() != _POLICY_BYTES:
        raise ValueError("PACKAGED_TEMPLATE_NOT_PINNED")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(policy, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(_POLICY_BYTES)
            stream.flush()
            os.fsync(stream.fileno())
        dir_fd = os.open(data_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        # Deliberately preserve partial/corrupt state: future restart must
        # refuse rather than silently reinitialize or overwrite it.
        raise
    return "INITIALIZED"
