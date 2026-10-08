"""Opt-in supported add-on strict policy candidate for pinned HA-MCP 8.6.0.

Apply only after Phase 2D policy/logging candidates to disposable upstream
checkout. Protects the original official source Git blobs, exact revision
and exact patch context. No production files, configuration or tokens.
"""
from __future__ import annotations
import argparse
import subprocess
from pathlib import Path

COMMIT = "fc54437a804858732e4bc927add98e202d879a09"
BLOBS = {
 "homeassistant-addon/config.yaml": "0079f23fd040651892a2dc2b2652b64af0e0a3d4",
 "homeassistant-addon/start.py": "88e926a59f568dc9a9bf7bcd719b518b42f52baa",
}
MARKER = "strict_policy_required.v1.json"
SAFE_READ_TOOLS = ("ha_get_overview",)

def once(src: str, before: str, after: str) -> str:
    n = src.count(before)
    if n != 1:
        raise RuntimeError(f"PHASE2F_CONTEXT_INVALID count={n}")
    return src.replace(before, after, 1)

def config_patch(s: str) -> str:
    s=once(s, "  enable_tool_security_policies: false\n",
        "  enable_tool_security_policies: false\n  require_strict_tool_policy: false\n")
    s=once(s, "  enable_tool_security_policies: bool?\n",
        "  enable_tool_security_policies: bool?\n  require_strict_tool_policy: bool?\n")
    return s

def addon_patch(s: str) -> str:
    helper = '''# Phase 2F: stable Supervisor-only strict option (not deployed).
_STRICT_MARKER_NAME = "strict_policy_required.v1.json"
# Start with the smallest proven positive allow-list. All control/write
# operations stay approval-required until their entire operation schema is
# audited independently. No blanket generic service/tool-proxy allow.
_STRICT_AUTO_ALLOWED_NAMES = frozenset({"ha_get_overview"})


def _validate_strict_policy_for_boot(data_dir: Path) -> None:
    from ha_mcp.policy.persistence import load_policy
    policy_file = data_dir / "tool_policy.json"
    if not policy_file.is_file() or policy_file.is_symlink():
        raise ValueError("mandatory policy file unavailable")
    policy = load_policy(data_dir)
    if policy.rule_effect != "allow" or not policy.rules:
        raise ValueError("mandatory policy is not a nonempty allow-list")
    # The installed policy engine has only allow/approval-required, no
    # irreversible deny. During initial opt-in, reject all write/control
    # auto-allows rather than attempting unsafe argument recognition.
    for rule in policy.rules:
        if rule.tool_name not in _STRICT_AUTO_ALLOWED_NAMES or rule.when:
            raise ValueError("mandatory policy contains unreviewed automatic access")


def _strict_marker_state(data_dir: Path) -> bool:
    path = data_dir / _STRICT_MARKER_NAME
    if path.is_symlink():
        raise ValueError("mandatory policy marker type invalid")
    if not path.exists():
        return False
    if not path.is_file():
        raise ValueError("mandatory policy marker type invalid")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data != {"schema_version": 1, "required": True}:
        raise ValueError("mandatory policy marker invalid")
    return True


def _commit_strict_marker(data_dir: Path) -> None:
    marker = data_dir / _STRICT_MARKER_NAME
    raw = b'{"required":true,"schema_version":1}\\n'
    # O_EXCL prevents silent overwrite/race. Partial writes are intentionally
    # treated as invalid on next startup, never mistaken for a disabled flag.
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        dirfd = os.open(data_dir, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except Exception:
        # Retain corrupt/partial marker to fail closed after interruption.
        raise


def configure_supported_strict_policy(
    data_dir: Path, config_file: Path,
) -> bool:
    """Security-decision preflight before opening MCP listener.

    Marker enforces mandatory status across options corruption, deletion or
    downgrade. Legitimate recovery is via local Supervisor data restore with
    explicit administrator involvement, never via the remote MCP connection.
    """
    active = _strict_marker_state(data_dir)
    if not config_file.exists():
        if active:
            raise ValueError("mandatory add-on configuration unavailable")
        return False
    parsed = json.loads(config_file.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("add-on options must be an object")
    value = parsed.get("require_strict_tool_policy", False)
    if type(value) is not bool:
        raise ValueError("require_strict_tool_policy must be boolean")
    if active and not value:
        raise ValueError("mandatory policy cannot be downgraded via options")
    if not value:
        return False
    if parsed.get("enable_tool_security_policies") is not True:
        raise ValueError("mandatory policy engine must be enabled")
    _validate_strict_policy_for_boot(data_dir)
    if not active:
        _commit_strict_marker(data_dir)
    return True


'''
    s=once(s, "def main() -> int:\n",helper+"def main() -> int:\n")
    old='''    # Validate Supervisor token (needed for both ha-mcp auth below and the
    # options-persist call right after secret path resolution)
'''
    new='''    # Do not trust fallbacks from the old broad config parsing block:
    # strict status must be recovered separately from durable /data storage.
    try:
        strict_required = configure_supported_strict_policy(data_dir, config_file)
    except (ValueError, OSError, json.JSONDecodeError, UnicodeDecodeError):
        log_error("Mandatory policy startup preflight rejected configuration")
        return 1
    os.environ["HA_MCP_REQUIRE_STRICT_POLICY"] = str(strict_required).lower()

'''+old
    s=once(s,old,new)
    return s

def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("ha_mcp_pinned"))
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args()
    root=args.root.resolve()
    sha=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    if sha!=COMMIT:raise RuntimeError("UPSTREAM_REVISION_CHANGED")
    for path,original in BLOBS.items():
        blob=subprocess.check_output(["git","-C",str(root),"rev-parse",f"HEAD:{path}"],text=True).strip()
        if blob!=original: raise RuntimeError("PINNED_UPSTREAM_BLOB_CHANGED")
    source=(root/"homeassistant-addon/start.py").read_text()
    # Require earlier narrow hardening already applied, and refuse changes
    # made to the staged code by another operation.
    if 'install_secret_path_log_filter(secret_path)' not in source or 'HA_MCP_REQUIRE_STRICT_POLICY' in source:
        raise RuntimeError("PHASE2D_PREREQUISITE_MISSING_OR_DUPLICATE")
    paths=[("homeassistant-addon/config.yaml",config_patch),
           ("homeassistant-addon/start.py",addon_patch)]
    outputs=[]
    for path,fn in paths:
        old=(root/path).read_text()
        new=fn(old)
        outputs.append((path,new))
    if args.apply:
        for path,new in outputs:
            (root/path).write_text(new)
    print("PHASE2F exact upstream checked; supported strict option candidate applied="+str(args.apply))

if __name__=="__main__":
    main()
