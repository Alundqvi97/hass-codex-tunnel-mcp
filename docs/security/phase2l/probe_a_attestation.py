"""Explicit review-time runner/image/binary drift gate for future Probe A.

No embedded approval manifest exists. Production command access cannot be
wired through reviewed_boundary_factory without externally supplied exact
hashes and an expected Ubuntu runner image marker. The marker itself is
platform-provided metadata, not cryptographic host attestation.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from probe_a_workload import WORKER

class AttestationDenied(RuntimeError):
    pass

BINARY_PATHS=(
    "/usr/sbin/iptables", "/usr/sbin/ip6tables",
    "/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save",
    "/usr/bin/setpriv", "/usr/bin/python3", "/usr/bin/sudo",
    "/usr/bin/getent", "/usr/bin/pgrep",
)
CONFIG_PATHS=("/etc/nsswitch.conf", "/etc/passwd")
SOURCE_NAMES=(
    "probe_contract.py", "probe_a_attestation.py", "probe_a_client.py",
    "probe_a_dns.py", "probe_a_controller.py", "probe_a_exec_adapter.py",
    "probe_a_kernel.py", "probe_a_observer.py", "probe_a_os_boundary.py",
    "probe_a_stream.py", "probe_a_recovery.py", "probe_a_guardian.py",
    "probe_a_runner.py", "probe_a_worker.py", "probe_a_workload.py",
    "probe_a_client_process.py", "probe_a_resources.py",
    "probe_a_privilege.py", "probe_a_containment.py", "probe_a_ipc.py",
    "probe_a_linux_identity.py", "probe_a_linux_launcher.py",
    "probe_a_readonly_broker.py", "probe_a_os_inventory.py",
    "probe_a_linux_containment.py",
    "probe_a_session.py", "probe_a_coordinator.py", "probe_a_execution_contract.py",
    "probe_a_inventory_integration.py", "probe_a_role_entrypoints.py",
    "probe_a_evidence.py", "probe_a_integrated_bootstrap.py",
)
PINNED=BINARY_PATHS+CONFIG_PATHS+tuple(str(Path(__file__).resolve().parent / f) for f in SOURCE_NAMES)

MAX_FILE=20*1024*1024


class DigestGate:
    def __init__(self, expected, *, image_version, read_bytes=None, environ=None,
                 dependency_paths=(), verified_dependency_inventory=False):
        # A file hash is not an OS image signature. A reviewed external
        # launcher must provide the *complete* dynamic loader, linked-library
        # and Python-runtime dependency inventory, or activation stays blocked.
        if (verified_dependency_inventory is not True or not isinstance(dependency_paths, tuple)
                or not dependency_paths or len(set(dependency_paths)) != len(dependency_paths)
                or any(type(p) is not str or not p.startswith("/") or
                       ".." in p.split("/") or p in PINNED for p in dependency_paths)):
            raise AttestationDenied("DEPENDENCY_INVENTORY_NOT_APPROVED")
        self.dependency_paths = dependency_paths
        if (not isinstance(expected, dict) or set(expected)!=set(PINNED) | set(self.dependency_paths) or
                any(not isinstance(v,str) or not re.fullmatch("[0-9a-f]{64}",v) for v in expected.values()) or
                not isinstance(image_version,str) or
                not re.fullmatch(r"[0-9]{8}\.[0-9]+(?:\.[0-9]+)?",image_version)):
            raise AttestationDenied("INCOMPLETE_IMMUTABLE_REVIEW_MANIFEST")
        self.expected=dict(expected)
        self.image_version=image_version
        self.read_bytes=read_bytes or (lambda p: Path(p).read_bytes())
        self.environ=environ if environ is not None else os.environ

    def verify(self):
        if self.environ.get("ImageOS")!="ubuntu24" or self.environ.get("ImageVersion")!=self.image_version:
            raise AttestationDenied("RUNNER_IMAGE_DRIFT")
        for path in PINNED + self.dependency_paths:
            try:
                data=self.read_bytes(path)
            except (OSError, ValueError):
                raise AttestationDenied("BINARY_UNREADABLE") from None
            if not isinstance(data,bytes) or len(data)>MAX_FILE:
                raise AttestationDenied("BINARY_UNBOUNDED")
            if hashlib.sha256(data).hexdigest()!=self.expected[path]:
                raise AttestationDenied("BINARY_OR_SOURCE_DRIFT")
        return True
