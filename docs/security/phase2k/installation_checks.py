"""Offline acceptance guard for proposed Supervisor-managed local install.

All inputs are synthetic dictionary fixtures; no actual APIs, Docker,
filesystem or network. Return BLOCKED unless *each* independent observation
is present. Never return VERIFIED_SUPERVISOR for a mock.
"""
from __future__ import annotations
import re

EXPECTED_SOURCE_SHA = "fc54437a804858732e4bc927add98e202d879a09"
EXPECTED_SLUG = "local_ha_mcp_phase2h"
EXPECTED_VERSION = "8.6.0"

def check_synthetic_install(evidence: dict) -> str:
    if not isinstance(evidence, dict):
        return "BLOCKED"
    expected = {
        "source_sha": EXPECTED_SOURCE_SHA,
        "slug": EXPECTED_SLUG,
        "version": EXPECTED_VERSION,
        "store_discovered": True,
        "install_api_accepted": True,
        "installed": True,
        "strict_schema": True,
        "strict_options_saved": True,
        "strict_options_readback": True,
        "bootstrap_flag_saved": True,
        "bootstrap_first_start_observed": True,
        "policy_read_only_verified": True,
        "running": True,
        "harmless_tool_read": True,
        "negative_privileged_dispatch_denied": True,
        "restore_documented": True,
        "cleanup_complete": True,
    }
    for field, wanted in expected.items():
        if type(evidence.get(field)) is not type(wanted) or evidence.get(field) != wanted:
            return "BLOCKED"
    image_digest = evidence.get("image_digest")
    if not isinstance(image_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        return "BLOCKED"
    reviewed_digest = evidence.get("reviewed_image_digest")
    if reviewed_digest != image_digest:
        return "BLOCKED"
    patch_sha = evidence.get("candidate_patch_sha")
    if not isinstance(patch_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", patch_sha):
        return "BLOCKED"
    # No mocked evidence is enough to prove that Supervisor performed the
    # steps. It must be connected to independently reviewed live observers.
    return "SYNTHETIC_COMPLETE_NOT_REAL_SUPERVISOR"

def phase2j_16_gates_still_required(complete_receipts: tuple[str, ...]) -> str:
    if len(complete_receipts) != 16 or any(x != "PASS" for x in complete_receipts):
        return "BLOCKED"
    return "SYNTHETIC_RECEIPTS_ONLY_NOT_VERIFIED"
