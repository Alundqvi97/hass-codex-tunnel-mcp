"""Version 2 signed inventory integration; no signing key or runtime approval.

Generation is a separately reviewed read-only collector operation. Dependency
edges must come from trusted ELF/Python/NSS inspection, never ldd execution of
an untrusted image. Completeness is externally reviewed, not proved by hashes.
"""
from __future__ import annotations

import hashlib
import os
import stat
from probe_a_os_inventory import RuntimeInventory, InventoryDenied, absolute
from probe_a_session import canonical, decode
from probe_a_execution_contract import local_nss

REQUIREMENTS = {"clone3": True, "clone_into_cgroup": True, "pidfd": True,
                "cgroup_v2": True, "cgroup_kill": True, "no_delegation": True,
                "sealed_memfd": True, "scm_credentials": True, "nss_network_denied": True}


def validate_parents(path, records):
    paths = ["/"]+["/"+"/".join(path.split("/")[1:n]) for n in range(2,len(path.split("/")))]
    if (type(records) is not list or len(records) != len(paths)
            or any(type(r) is not dict or set(r) != {"path","device","inode","uid","gid","mode"}
                or r["path"] != p or any(type(r[k]) is not int or r[k] < 0 for k in ("device","inode","uid","gid","mode"))
                or r["uid"] != 0 or not stat.S_ISDIR(r["mode"]) or r["mode"] & 0o022
                for r,p in zip(records,paths))):
        raise InventoryDenied("ORDINARY_ASSET_OR_TARGET_ANCESTRY_UNCONTROLLED")


class IntegratedInventory:
    """External verifier authenticates the entire closure, aliases and metadata.

    read_asset, inspect_asset, read_alias, read_requirements and verify_source
    are bootstrap-owned trusted observations. No controller-supplied callback
    is accepted by the role startup interfaces. Files are checked both before
    and after reading. Any drift poisons this inventory permanently.
    """
    def __init__(self, document, signature, *, verify_signature=None,
                 read_asset=None, inspect_asset=None, read_alias=None,
                 read_facts=None, read_requirements=None, verify_source=None):
        self.canonical = canonical(document)
        self.document = decode(self.canonical, 300000)
        self.identifier = hashlib.sha256(self.canonical).hexdigest()
        self.signature, self.verify_signature = signature, verify_signature
        self.read_asset, self.inspect_asset, self.read_alias = read_asset, inspect_asset, read_alias
        self.read_requirements, self.verify_source = read_requirements, verify_source
        self.poisoned = False
        d = self.document
        if (type(d) is not dict or set(d) != {"v", "inventory", "metadata", "aliases", "dependencies", "requirements"}
                or type(d["v"]) is not int or d["v"] != 2 or canonical(d["requirements"]) != canonical(REQUIREMENTS)
                or any(type(d[k]) is not dict for k in ("inventory", "metadata", "aliases", "dependencies"))):
            raise InventoryDenied("INCOMPLETE_V2_INTEGRATION_INVENTORY")
        self.base = RuntimeInventory(d["inventory"], signature,
            verify_signature=lambda _message, sig: self._signature(sig),
            read_asset=self._asset, read_facts=read_facts)
        files = set(self.base.document["files"])
        if set(d["metadata"]) != files or set(d["dependencies"]) != files:
            raise InventoryDenied("METADATA_OR_DEPENDENCY_CLOSURE_INCOMPLETE")
        for path, metadata in d["metadata"].items():
            if (type(metadata) is not dict or set(metadata) not in ({"device", "inode", "uid", "gid", "mode", "size"}, {"device", "inode", "uid", "gid", "mode", "size", "parents"})
                    or any(type(metadata[k]) is not int or metadata[k] < 0 for k in ("device", "inode", "uid", "gid", "mode", "size"))
                    or metadata["uid"] != 0 or metadata["mode"] & 0o022
                    or not stat.S_ISREG(metadata["mode"])):
                raise InventoryDenied("UNCONTROLLED_RUNTIME_ASSET")
            if "parents" in metadata:
                validate_parents(path, metadata["parents"])
        for alias, record in d["aliases"].items():
            if (type(record) is not dict or set(record) != {"target", "device", "inode", "uid", "gid", "mode", "parents"}
                    or any(type(record[k]) is not int or record[k] < 0 for k in ("device", "inode", "uid", "gid", "mode"))
                    or record["uid"] != 0 or not stat.S_ISLNK(record["mode"])
                    or type(record["parents"]) is not list):
                raise InventoryDenied("UNREVIEWED_SYMLINK_IDENTITY")
            target = record["target"]
            absolute(alias); absolute(target)
            parent_paths = ["/"] + ["/"+"/".join(alias.split("/")[1:n]) for n in range(2,len(alias.split("/")))]
            if (len(record["parents"]) != len(parent_paths)
                    or any(type(p) is not dict or set(p) != {"path","device","inode","uid","gid","mode"}
                        or p["path"] != path or any(type(p[k]) is not int or p[k] < 0 for k in ("device","inode","uid","gid","mode"))
                        or p["uid"] != 0 or not stat.S_ISDIR(p["mode"]) or p["mode"] & 0o022
                        for p,path in zip(record["parents"],parent_paths))):
                raise InventoryDenied("ALIAS_ANCESTRY_NOT_ROOT_CONTROLLED")
            if alias not in files or target not in files or alias == target or target in d["aliases"]:
                raise InventoryDenied("ALIAS_CHAIN_OR_UNINVENTORIED_TARGET")
            if self.base.document["files"][alias] != self.base.document["files"][target]:
                raise InventoryDenied("EXECUTABLE_ALIAS_HASH_MISMATCH")
        for path, edges in d["dependencies"].items():
            if (type(edges) is not list or len(set(edges)) != len(edges)
                    or any(type(e) is not str or e not in files or e == path for e in edges)):
                raise InventoryDenied("UNEXPECTED_TRANSITIVE_DEPENDENCY")
        # Every binary/interpreter links to the reviewed loader, libc and its
        # full declared closure. A disconnected extra category is insufficient.
        categories = self.base.document["categories"]
        required = set(categories["dynamic_loader"] + categories["libc_nss"] + categories["libcap"])
        for root in categories["executables"]:
            reached, pending = set(), list(d["dependencies"][root])
            while pending:
                item = pending.pop()
                if item not in reached:
                    reached.add(item); pending.extend(d["dependencies"][item])
            if not required <= reached:
                raise InventoryDenied("LOADER_LIBCAP_LIBC_NSS_CLOSURE_MISSING")

    def _signature(self, signature):
        return (callable(self.verify_signature) and type(signature) is bytes and bool(signature)
                and self.verify_signature(b"ProbeA inventory v2\x00" + self.canonical, signature) is True)

    def _asset(self, path):
        if not callable(self.read_asset) or not callable(self.inspect_asset):
            raise InventoryDenied("TRUSTED_ASSET_READER_MISSING")
        alias = self.document["aliases"].get(path)
        target = alias["target"] if alias is not None else path
        # The trusted no-follow alias reader returns the complete lstat and
        # parent-directory record, not merely a resolved pathname. Symlink
        # permission bits are ignored by Linux; parent ownership is essential.
        if alias is not None and (not callable(self.read_alias) or self.read_alias(path) != alias):
            raise InventoryDenied("SYMLINK_OR_EXECUTABLE_ALIAS_DRIFT")
        expected = self.document["metadata"][target]
        if self.inspect_asset(target) != expected:
            raise InventoryDenied("RUNTIME_METADATA_DRIFT")
        result = self.read_asset(target)
        if (self.inspect_asset(target) != expected or type(result) is not bytes or len(result) != expected["size"]
                or alias is not None and self.read_alias(path) != alias):
            raise InventoryDenied("RUNTIME_ASSET_CHANGED_DURING_VERIFICATION")
        return result

    def verify(self):
        try:
            if (self.poisoned or canonical(self.document) != self.canonical
                    or self.base.canonical != canonical(self.document["inventory"])
                    or not self._signature(self.signature)
                    or not callable(self.read_requirements) or canonical(self.read_requirements()) != canonical(REQUIREMENTS)
                    or not callable(self.verify_source)
                    or self.verify_source(self.base.document["source_commit"], self.base.document["categories"]["source"],
                                          self.base.document["files"]) is not True
                    or self.base.verify() is not True):
                raise InventoryDenied("SIGNATURE_SOURCE_OR_KERNEL_REQUIREMENTS_UNVERIFIED")
            local_nss(self._asset("/etc/nsswitch.conf"))
            return True
        except BaseException:
            self.poisoned = True
            raise

    def verify_integration(self, context):
        self.verify()
        if (context.inventory != self.identifier
                or context.source_commit != self.base.document["source_commit"]):
            self.poisoned = True
            raise InventoryDenied("SOURCE_COMMIT_OR_SESSION_INVENTORY_MISMATCH")
        return True

    def authorize_exec(self, spec, approval):
        self.verify()
        alias = self.document["aliases"].get(spec.argv[0])
        target = alias["target"] if alias is not None else spec.argv[0]
        st = os.fstat(spec.executable_fd)
        expected = self.document["metadata"].get(target)
        if expected is None or {"device":st.st_dev,"inode":st.st_ino,"uid":st.st_uid,"gid":st.st_gid,
            "mode":st.st_mode,"size":st.st_size} != {k:v for k,v in expected.items() if k != "parents"}:
            raise InventoryDenied("EXECUTABLE_DESCRIPTOR_INODE_OR_METADATA_MISMATCH")
        # Reuse exact retained-FD/role/argv/group checks, but authenticate a
        # separate authorization domain. The external issuer must additionally
        # bind the session in the execution contract; inventory alone is inert.
        verifier = self.base.verify_signature
        try:
            self.base.verify_signature = lambda message, sig: (self._signature(sig) if message == self.base.canonical
                else callable(self.verify_signature) and self.verify_signature(
                    b"ProbeA activation v2\x00" + self.canonical, sig) is True)
            return self.base.authorize_exec(spec, approval)
        finally:
            self.base.verify_signature = verifier


def inventory_candidate(inventory, metadata, aliases, dependencies):
    """Format externally collected observations; DOES NOT approve or sign them."""
    result = {"v": 2, "inventory": inventory, "metadata": metadata, "aliases": aliases,
              "dependencies": dependencies, "requirements": dict(REQUIREMENTS)}
    return decode(canonical(result), 300000)
