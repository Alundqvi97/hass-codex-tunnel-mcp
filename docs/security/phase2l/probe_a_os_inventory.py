"""Externally signed dependency/OS inventory for the disabled Linux foundation.

No approved inventory, key, signature verifier or runtime authorization is
bundled. ImageOS/ImageVersion are deliberately not accepted as host evidence.
Dependency closure must be independently reviewed, not inferred from a worker
report or a boolean 'verified inventory' flag. No writes or execution on import.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import PurePosixPath
import re

from probe_a_attestation import PINNED, BINARY_PATHS, CONFIG_PATHS
from probe_a_linux_identity import read_fd, check_root_file

CATEGORIES = frozenset(("source", "executables", "dynamic_loader", "libcap",
                       "libc_nss", "nss_configuration", "python_runtime",
                       "transitive_dependencies", "kernel_configuration", "cgroup_configuration"))
FACTS = frozenset(("kernel.release", "kernel.machine", "cgroup.version",
                  "cgroup.controllers", "cgroup.mount", "nss.passwd_backend"))
MAX_ASSET = 32 * 1024 * 1024
ROLES = frozenset(("guardian", "observer", "controller", "read-command",
                   "guardian-command", "worker", "peer"))


class InventoryDenied(RuntimeError):
    pass


def absolute(path):
    if (type(path) is not str or not path.startswith("/") or "\x00" in path
            or str(PurePosixPath(path)) != path or ".." in path.split("/")):
        raise InventoryDenied("AMBIGUOUS_INVENTORY_PATH")
    return path


def root_asset(path):
    """Open each directory without following a link; verify root-only control."""
    absolute(path)
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = path.split("/")[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
            st = os.fstat(directory)
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise InventoryDenied("DEPENDENCY_DIRECTORY_NOT_ROOT_CONTROLLED")
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            check_root_file(fd)
            return read_fd(fd, MAX_ASSET)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


class RuntimeInventory:
    """Complete attributed inventory + externally reviewed signature checker.

    A bootstrap's trusted verifier must validate an independently supplied
    signature against its pinned reviewer trust root. No callback, trust root,
    signature or document may come from controller IPC. The caller cannot
    widen roles/argv/cgroup identities after the document is authenticated.
    """
    def __init__(self, document, signature, *, verify_signature=None,
                 read_asset=root_asset, read_facts=None):
        if type(document) is not dict or set(document) != {
                "v", "source_commit", "reviewer", "categories", "files", "facts", "exec", "groups"}:
            raise InventoryDenied("INCOMPLETE_REVIEWED_INVENTORY")
        # Canonical copy prevents mutation of the caller's original mappings.
        try:
            self.canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                                        allow_nan=False).encode()
            self.document = json.loads(self.canonical)
        except (ValueError, TypeError):
            raise InventoryDenied("INVALID_INVENTORY_ENCODING") from None
        if len(self.canonical) > 300000:
            raise InventoryDenied("INVENTORY_UNBOUNDED")
        self.signature, self.verify_signature = signature, verify_signature
        self.read_asset, self.read_facts = read_asset, read_facts
        self.identifier = hashlib.sha256(self.canonical).hexdigest()
        d = self.document
        if (type(d["v"]) is not int or d["v"] != 1
                or type(d["source_commit"]) is not str or not re.fullmatch("[0-9a-f]{40}", d["source_commit"])
                or type(d["reviewer"]) is not str or not 1 <= len(d["reviewer"]) <= 128
                or type(d["categories"]) is not dict or set(d["categories"]) != CATEGORIES
                or type(d["files"]) is not dict or not set(PINNED) <= set(d["files"])
                or type(d["facts"]) is not dict or set(d["facts"]) != FACTS
                or any(type(v) is not str or not v or len(v) > 4096 for v in d["facts"].values())
                or d["facts"]["cgroup.version"] != "2" or d["facts"]["nss.passwd_backend"] != "files"
                or type(d["exec"]) is not dict or set(d["exec"]) != ROLES
                or type(d["groups"]) is not dict or set(d["groups"]) != ROLES):
            raise InventoryDenied("MISSING_DEPENDENCY_OR_OS_IDENTITY")
        coverage = set()
        for paths in d["categories"].values():
            if (type(paths) is not list or not paths
                    or any(type(p) is not str or p not in d["files"] for p in paths)
                    or len(set(paths)) != len(paths) or coverage.intersection(paths)):
                raise InventoryDenied("DEPENDENCY_CATEGORY_INCOMPLETE")
            coverage.update(paths)
        if coverage != set(d["files"]):
            raise InventoryDenied("UNCATEGORIZED_DEPENDENCY")
        if (not set(BINARY_PATHS) <= set(d["categories"]["executables"])
                or not set(CONFIG_PATHS) <= set(d["categories"]["nss_configuration"])
                or not (set(PINNED) - set(BINARY_PATHS) - set(CONFIG_PATHS))
                <= set(d["categories"]["source"])):
            raise InventoryDenied("SOURCE_BINARY_OR_NSS_CATEGORY_MISMATCH")
        for path, digest in d["files"].items():
            absolute(path)
            if type(digest) is not str or not re.fullmatch("[0-9a-f]{64}", digest):
                raise InventoryDenied("INVALID_DEPENDENCY_DIGEST")
        group_ids = set()
        for role in ROLES:
            group, vectors = d["groups"][role], d["exec"][role]
            if (type(group) is not dict or set(group) != {"device", "inode"}
                    or any(type(group[k]) is not int or group[k] <= 0 for k in group)
                    or (group["device"], group["inode"]) in group_ids
                    or type(vectors) is not list or not vectors or len(vectors) > 256):
                raise InventoryDenied("MISSING_OR_OVERLAPPING_ROLE_GROUPS")
            group_ids.add((group["device"], group["inode"]))
            for vector in vectors:
                if (type(vector) is not list or not 1 <= len(vector) <= 32
                        or any(type(s) is not str or not s or "\x00" in s for s in vector)
                        or sum(map(len, vector)) > 4096 or vector[0] not in d["files"]
                        or vector[0] not in d["categories"]["executables"]):
                    raise InventoryDenied("UNREVIEWED_EXEC_VECTOR")
        # Symlinked Python/executable paths intentionally fail closed here.
        # A future reviewed alias-to-open-inode inventory must cover every link
        # and resolved target. Do not silently resolve host-specific aliases.

    def verify(self):
        # Signature validation must authenticate the exact data used below.
        # In particular, mutation of exposed mappings cannot widen an allowlist.
        if json.dumps(self.document, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode() != self.canonical:
            raise InventoryDenied("AUTHENTICATED_INVENTORY_MUTATED")
        if (type(self.signature) is not bytes or not self.signature or len(self.signature) > 8192
                or not callable(self.verify_signature) or not callable(self.read_facts)
                or self.verify_signature(self.canonical, self.signature) is not True):
            raise InventoryDenied("INDEPENDENT_REVIEW_SIGNATURE_REQUIRED")
        if self.read_facts() != self.document["facts"]:
            raise InventoryDenied("KERNEL_CGROUP_OR_NSS_IDENTITY_DRIFT")
        for path, digest in self.document["files"].items():
            data = self.read_asset(path)
            if (type(data) is not bytes or len(data) > MAX_ASSET
                    or hashlib.sha256(data).hexdigest() != digest):
                raise InventoryDenied("SOURCE_OR_RUNTIME_DEPENDENCY_DRIFT")
        return True

    def authorize_exec(self, spec, approval):
        self.verify()
        # A separate signed runtime approval is STILL needed; an inventory
        # signature approves content, never runtime activation by itself.
        if (type(approval) is not bytes or not approval or len(approval) > 8192
                or self.verify_signature(b"ProbeA activation\x00" + self.canonical, approval) is not True):
            raise InventoryDenied("SEPARATE_RUNTIME_AUTHORIZATION_REQUIRED")
        vectors = self.document["exec"].get(spec.role)
        group = self.document["groups"].get(spec.role)
        if (type(vectors) is not list or list(spec.argv) not in vectors
                or type(group) is not dict or set(group) != {"device", "inode"}
                or (group["device"], group["inode"]) != spec.group.identity
                or spec.argv[0] not in self.document["files"]):
            raise InventoryDenied("EXEC_ROLE_ARGV_OR_CGROUP_NOT_REVIEWED")
        check_root_file(spec.executable_fd, executable=True)
        # Read the exact retained descriptor that execve will use, not a path.
        data = bytearray()
        offset = 0
        while len(data) <= MAX_ASSET:
            block = os.pread(spec.executable_fd, min(8192, MAX_ASSET + 1 - len(data)), offset)
            if not block:
                break
            data.extend(block)
            offset += len(block)
        if len(data) > MAX_ASSET or hashlib.sha256(data).hexdigest() != self.document["files"][spec.argv[0]]:
            raise InventoryDenied("PINNED_EXEC_DESCRIPTOR_DRIFT")
        return True
