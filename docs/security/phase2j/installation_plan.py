"""Static mock of version-scoped Supervisor install sequencing; NO I/O."""
from dataclasses import dataclass
import re

@dataclass(frozen=True)
class ApiStep:
    name: str
    method: str
    path: str

def v2_api_steps(version, slug):
    if version != "2026.10.1":
        raise ValueError("UNKNOWN_GUEST_SUPERVISOR_VERSION")
    if not re.fullmatch(r"local_[a-z0-9_]+", slug):
        raise ValueError("INVALID_APP_SLUG")
    return (
        ApiStep("STORE_RELOAD","POST","/store/reload"),
        ApiStep("STORE_DISCOVER","GET",f"/store/apps/{slug}"),
        ApiStep("INSTALL_REQUEST","POST",f"/store/apps/{slug}/install"),
        ApiStep("INSTALLED_IMAGE_READBACK","GET",f"/apps/{slug}/info"),
        ApiStep("STRICT_SCHEMA_READBACK","GET",f"/apps/{slug}/info"),
        ApiStep("OPTIONS_WRITE","POST",f"/apps/{slug}/options"),
        ApiStep("OPTIONS_READBACK","GET",f"/apps/{slug}/info"),
        ApiStep("START","POST",f"/apps/{slug}/start"),
        ApiStep("RUNTIME_READBACK","GET",f"/apps/{slug}/info"),
    )

class SyntheticSequence:
    def __init__(self, steps):
        self.steps=steps
        self.completed=0
        self.poisoned=False
    def record(self, name, *, observed):
        if self.poisoned or self.completed>=len(self.steps) or self.steps[self.completed].name != name or observed is not True:
            self.poisoned=True
            raise ValueError("INVALID_OR_MISSING_EVIDENCE")
        self.completed+=1
    def verdict(self):
        if self.poisoned or self.completed!=len(self.steps):
            return "BLOCKED"
        return "SYNTHETIC_ONLY_NOT_INSTALLED"

def check_build_metadata(meta, docker_text, names):
    """Minimal metadata lint only; not a full YAML parser or Supervisor approval."""
    required={"config.yaml","Dockerfile","start.py","pyproject.toml","uv.lock","src/"}
    if not required.issubset(set(names)):
        return "BLOCKED"
    if meta.get("slug")!="ha_mcp_phase2h" or "image" in meta:
        return "BLOCKED"
    if meta.get("require_strict_tool_policy_schema")!="bool?":
        return "BLOCKED"
    if "COPY start.py /" not in docker_text:
        return "BLOCKED"
    return "BUILD_METADATA_LINT_ONLY"
