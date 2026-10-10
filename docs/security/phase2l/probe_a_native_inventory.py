"""No-follow native asset/ELF collection, inert until explicitly constructed.

Only regular local files with protected ancestry. No ldd, target execution,
package installation, key generation or discovery of a 'successful' runner.
Declared ELF closure is not proof of dynamic Python/NSS loading behavior.
"""
from __future__ import annotations

import hashlib
import os
import stat
import struct
import time
from probe_a_os_inventory import absolute, InventoryDenied, MAX_ASSET
from probe_a_session import canonical


def metadata(st):
    return {"device": st.st_dev, "inode": st.st_ino, "uid": st.st_uid,
            "gid": st.st_gid, "mode": st.st_mode, "size": st.st_size}


class NativeAssetReader:
    """Retain every directory and file FD and authenticate path around reads.

    Signed parent identities apply to ordinary files and alias targets, too.
    No parent replacement or same-bytes/different-inode substitution is valid.
    Native use requires root ownership. Fixture ownership is explicit and
    rejected by native assembly. All operations share an absolute deadline.
    """
    def __init__(self, expected, *, aliases=None, deadline, clock=time.monotonic, fixture_uid=None):
        self.expected, self.aliases = expected, aliases or {}
        self.deadline, self.clock = deadline, clock
        self.uid = 0 if fixture_uid is None else fixture_uid
        self.synthetic = fixture_uid is not None

    def _time(self):
        if self.clock() >= self.deadline:
            raise InventoryDenied("NATIVE_ASSET_DEADLINE")

    def _walk(self, path):
        absolute(path); self._time()
        descriptors, records = [], []
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            descriptors.append(fd)
            components, parent = path.split("/")[1:], "/"
            for index in range(len(components)):
                st = os.fstat(fd)
                # Fixture walks through /tmp but pin its exact identity; native
                # mode has no writable-parent exception.
                writable_fixture_parent = self.synthetic and parent == "/tmp"
                if not stat.S_ISDIR(st.st_mode) or (not self.synthetic and st.st_uid != 0) or st.st_mode & 0o022 and not writable_fixture_parent:
                    raise InventoryDenied("NATIVE_ASSET_PARENT_UNCONTROLLED")
                records.append(dict(path=parent, **{k:v for k,v in metadata(st).items() if k != "size"}))
                if index == len(components)-1: break
                fd = os.open(components[index], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                descriptors.append(fd)
                parent = "/"+"/".join(components[:index+1])
            return descriptors, records, components[-1]
        except BaseException:
            for fd in reversed(descriptors): os.close(fd)
            raise

    def collect(self, path):
        descriptors, parents, name = self._walk(path)
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=descriptors[-1])
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self.uid or before.st_mode & 0o022
                    or before.st_nlink != 1 or not 0 <= before.st_size <= MAX_ASSET):
                raise InventoryDenied("NATIVE_ASSET_NOT_IMMUTABLE_REGULAR_FILE")
            chunks, count = [], 0
            while True:
                self._time(); block = os.read(fd, min(65536, MAX_ASSET+1-count))
                if not block: break
                chunks.append(block); count += len(block)
                if count > MAX_ASSET: raise InventoryDenied("NATIVE_ASSET_OVERSIZE")
            after = os.fstat(fd)
            if (metadata(before) != metadata(after) or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns
                    or metadata(os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)) != metadata(before)):
                raise InventoryDenied("NATIVE_ASSET_CHANGED_DURING_READ")
            # Re-open the complete pathname so a replaced ancestor is detected;
            # checking only the retained old directory would miss replacement.
            current, current_parents, _ = self._walk(path)
            try:
                if parents != current_parents: raise InventoryDenied("NATIVE_ASSET_PARENT_REPLACED")
            finally:
                for item in reversed(current): os.close(item)
            info = dict(metadata(after), parents=parents)
            data = b"".join(chunks)
            if len(data) != before.st_size: raise InventoryDenied("NATIVE_ASSET_PARTIAL_READ")
            self._time()
            return data, info
        finally:
            if fd is not None: os.close(fd)
            for item in reversed(descriptors): os.close(item)

    def read_asset(self, path):
        data, info = self.collect(path)
        if info != self.expected.get(path): raise InventoryDenied("NATIVE_ASSET_METADATA_OR_ANCESTRY_DRIFT")
        return data

    def inspect_asset(self, path):
        _, info = self.collect(path)
        if info != self.expected.get(path): raise InventoryDenied("NATIVE_ASSET_METADATA_OR_ANCESTRY_DRIFT")
        return info

    def read_alias(self, path):
        descriptors, parents, name = self._walk(path)
        try:
            before = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
            if not stat.S_ISLNK(before.st_mode) or before.st_uid != self.uid:
                raise InventoryDenied("NATIVE_ALIAS_NOT_REVIEWED_LINK")
            target = os.readlink(name, dir_fd=descriptors[-1])
            # Native collection rejects chains; caller supplies canonical target.
            if not target.startswith("/"):
                target = os.path.normpath(os.path.dirname(path)+"/"+target)
            absolute(target)
            record = {"target":target, **{k:v for k,v in metadata(before).items() if k != "size"}, "parents":parents}
            if metadata(before) != metadata(os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)):
                raise InventoryDenied("NATIVE_ALIAS_REPLACED")
            expected = self.aliases.get(path)
            if record != expected: raise InventoryDenied("NATIVE_ALIAS_OR_TARGET_DRIFT")
            self.inspect_asset(target)
            current, checked, _ = self._walk(path)
            try:
                if checked != parents: raise InventoryDenied("NATIVE_ALIAS_PARENT_REPLACED")
            finally:
                for fd in reversed(current): os.close(fd)
            return record
        finally:
            for fd in reversed(descriptors): os.close(fd)


def elf_loading(raw):
    """Bounded ELF64 little-endian metadata parser; never executes an image."""
    if type(raw) is not bytes or not 64 <= len(raw) <= MAX_ASSET or raw[:6] != b"\x7fELF\x02\x01":
        raise InventoryDenied("UNSUPPORTED_OR_TRUNCATED_ELF")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    if header[1] not in (62, 183) or header[8] != 56 or not 0 < header[9] <= 128:
        raise InventoryDenied("UNSUPPORTED_ELF_MACHINE_OR_HEADERS")
    offset, count = header[4], header[9]
    if offset+count*56 > len(raw): raise InventoryDenied("TRUNCATED_ELF_PROGRAM_HEADERS")
    loads, dynamic, interpreter = [], None, None
    for n in range(count):
        kind, flags, fileoff, vaddr, _paddr, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", raw, offset+n*56)
        if fileoff+filesz > len(raw) or filesz > memsz: raise InventoryDenied("ELF_SEGMENT_BOUNDS")
        if kind == 1: loads.append((vaddr, fileoff, filesz))
        if kind == 2:
            if dynamic is not None or filesz % 16 or filesz > 65536: raise InventoryDenied("AMBIGUOUS_ELF_DYNAMIC")
            dynamic = (fileoff, filesz)
        if kind == 3:
            if interpreter is not None or not 1 < filesz <= 4096: raise InventoryDenied("AMBIGUOUS_ELF_INTERPRETER")
            text = raw[fileoff:fileoff+filesz]
            if text[-1:] != b"\0" or b"\0" in text[:-1]: raise InventoryDenied("MALFORMED_ELF_INTERPRETER")
            interpreter = absolute(text[:-1].decode("ascii"))
    entries = []
    if dynamic is not None:
        start, size = dynamic
        for n in range(size//16):
            tag, value = struct.unpack_from("<qQ", raw, start+n*16)
            if tag == 0: break
            entries.append((tag, value))
        else: raise InventoryDenied("UNTERMINATED_ELF_DYNAMIC")
    strings = [v for t,v in entries if t == 5]; sizes = [v for t,v in entries if t == 10]
    if entries and (len(strings) != 1 or len(sizes) != 1 or not 0 < sizes[0] <= 1048576):
        raise InventoryDenied("ELF_STRING_TABLE_MISSING")
    table = b""
    if strings:
        remaining, address, parts = sizes[0], strings[0], []
        while remaining:
            matches = [(off+address-addr, size-(address-addr)) for addr,off,size in loads if addr <= address < addr+size]
            if len(matches) != 1: raise InventoryDenied("ELF_STRING_TABLE_OUTSIDE_LOAD")
            offset, available = matches[0]; count = min(available, remaining)
            parts.append(raw[offset:offset+count]); remaining -= count; address += count
        table = b"".join(parts)
    def text(index):
        if index >= len(table): raise InventoryDenied("ELF_STRING_OFFSET")
        end = table.find(b"\0", index)
        if end < 0 or end-index > 4096: raise InventoryDenied("ELF_STRING_UNBOUNDED")
        return table[index:end].decode("ascii")
    needed = [text(v) for t,v in entries if t == 1]
    if len(needed) > 256 or len(set(needed)) != len(needed) or any(not n or "/" in n for n in needed):
        raise InventoryDenied("ELF_UNEXPECTED_DEPENDENCY_NAME")
    search_paths = [text(v) for t,v in entries if t in (15,29)]
    return {"interpreter":interpreter, "needed":needed, "search_paths":search_paths}


def collect_dependency_closure(roots, reader, sonames, *, maximum=512, approved_search_paths=None):
    """Exact externally approved SONAME resolution; no host search fallback."""
    pending, files, dependencies = list(roots), {}, {}
    while pending:
        path = pending.pop()
        if path in files: continue
        if len(files) >= maximum: raise InventoryDenied("DEPENDENCY_CLOSURE_OVERFLOW")
        data, info = reader.collect(path)
        loading = elf_loading(data)
        if loading["search_paths"] != (approved_search_paths or {}).get(path, []):
            raise InventoryDenied("ELF_RPATH_RUNPATH_REQUIRES_SEPARATE_REVIEW")
        edges = []
        if loading["interpreter"]: edges.append(loading["interpreter"])
        for soname in loading["needed"]:
            if soname not in sonames: raise InventoryDenied("UNAPPROVED_ELF_DEPENDENCY:"+soname)
            edges.append(absolute(sonames[soname]))
        files[path] = {"sha256":hashlib.sha256(data).hexdigest(), "metadata":info}
        dependencies[path] = list(dict.fromkeys(edges)); pending.extend(edges)
    return {"files":files, "dependencies":dependencies, "provenance":"UNSIGNED_CANDIDATE",
            "dynamic_python_nss_loading":"RUNTIME_ACCEPTANCE_NOT_EXECUTED"}


class PinnedSourceExport:
    """Externally reviewed commit->export binding, with actual byte validation.

    The export manifest is produced AFTER the source commit, outside Git, so
    no commit/manifest contains its own hash. Its reviewer reconciles each
    module against Git blobs; runtime does not execute git as root. No receipt
    or signing key is created here. Approval of this export is not activation.
    """
    def __init__(self, record, signature, *, verifier, reader):
        from probe_a_session import decode
        self.raw=canonical(record);self.record=decode(self.raw,300000)
        self.signature,self.verifier,self.reader=signature,verifier,reader

    def __call__(self, commit, source_paths, digests):
        from probe_a_session import hexvalue
        r=self.record
        if (set(r)!={'v','source_commit','modules'} or type(r['v']) is not int or r['v']!=1
                or not hexvalue(r['source_commit'],40) or r['source_commit']!=commit
                or type(r['modules']) is not dict or set(r['modules'])!=set(source_paths)
                or canonical(r)!=self.raw or self.reader.synthetic
                or self.verifier(b'ProbeA source export\0'+self.raw,self.signature) is not True):
            raise InventoryDenied('EXTERNAL_SOURCE_EXPORT_BINDING_INVALID')
        for path,expected in r['modules'].items():
            if not hexvalue(expected,64) or digests.get(path)!=expected or hashlib.sha256(self.reader.read_asset(path)).hexdigest()!=expected:
                raise InventoryDenied('EXACT_SOURCE_COMMIT_EXPORT_DRIFT')
        return True


def construct_native_inventory(document, signature, *, verifier, reader, source_export,
                               kernel_facts):
    """Connect actual protected readers/verifier to existing v2 inventory.

    Runner/kernel requirement collector and native package loader remain
    explicit in-scope omissions. No permissive fact callback is installed.
    """
    from probe_a_inventory_integration import IntegratedInventory
    from probe_a_native_verifier import OpenSSLEd25519
    if (not isinstance(verifier,OpenSSLEd25519) or not isinstance(reader,NativeAssetReader)
            or reader.synthetic or not isinstance(source_export,PinnedSourceExport)):
        raise InventoryDenied('CONCRETE_NATIVE_VERIFIER_READERS_REQUIRED')
    if not isinstance(kernel_facts,NativeKernelFacts):
        raise InventoryDenied('CONCRETE_NATIVE_KERNEL_FACT_COLLECTOR_REQUIRED')
    return IntegratedInventory(document,signature,verify_signature=verifier,
        read_asset=reader.read_asset,inspect_asset=reader.inspect_asset,read_alias=reader.read_alias,
        verify_source=source_export,read_facts=kernel_facts.facts,read_requirements=kernel_facts.requirements)


class NativeKernelFacts:
    """Bounded native facts plus externally verified kernel feature receipt.

    Read-only source, never exercised natively here. Kernel release and cgroup
    filesystem do not prove clone3/seccomp/delegation behavior. Those require
    an externally collected feature receipt bound to this boot and actual
    facts; no local boolean upgrades missing acceptance evidence.
    """
    def __init__(self, context, feature_record, signature, *, verifier, activated=False, clock=time.monotonic):
        from probe_a_session import decode
        self.context,self.raw=context,canonical(feature_record)
        self.record,self.signature=decode(self.raw,300000),signature
        self.verifier,self.activated,self.clock=verifier,activated is True,clock

    def _gate(self):
        if not self.activated or os.geteuid()!=0 or self.clock()>=self.context.end:
            raise InventoryDenied('NATIVE_KERNEL_FACT_COLLECTION_DISABLED_OR_EXPIRED')

    def _read(self, path, maximum=65536):
        self._gate();absolute(path)
        fds=[]
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);fds.append(fd)
            components=path.split('/')[1:]
            for component in components[:-1]:
                fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);fds.append(fd)
                info=os.fstat(fd)
                if info.st_uid!=0 or info.st_mode & 0o022:raise InventoryDenied('KERNEL_FACT_PARENT_UNCONTROLLED')
            child=os.open(components[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd);fds.append(child)
            before=os.fstat(child)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=0:raise InventoryDenied('KERNEL_FACT_NOT_APPROVED_REGULAR_VIEW')
            result=bytearray()
            while True:
                self._gate();part=os.read(child,min(8192,maximum+1-len(result)))
                if not part:break
                result.extend(part)
                if len(result)>maximum:raise InventoryDenied('KERNEL_FACT_BOUNDS')
            after=os.fstat(child)
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):raise InventoryDenied('KERNEL_FACT_REPLACED')
            return bytes(result)
        finally:
            for fd in reversed(fds):os.close(fd)

    def boot_identity(self):
        from uuid import UUID
        text=self._read('/proc/sys/kernel/random/boot_id',64).decode('ascii').strip()
        if str(UUID(text))!=text:raise InventoryDenied('BOOT_IDENTITY_MALFORMED')
        return text

    def facts(self):
        self._gate()
        from probe_a_linux_launcher import OwnedCgroup
        fd=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            info=os.fstat(fd);OwnedCgroup(fd,(info.st_dev,info.st_ino)).verify()
            controllers=self._read('/sys/fs/cgroup/cgroup.controllers').decode('ascii').split()
        finally:os.close(fd)
        nss=self._read('/etc/nsswitch.conf')
        from probe_a_execution_contract import local_nss
        local_nss(nss)
        kernel=os.uname()
        return {'kernel.release':kernel.release,'kernel.machine':kernel.machine,'cgroup.version':2,
                'cgroup.controllers':controllers,'cgroup.mount':'/sys/fs/cgroup','nss.passwd_backend':'files'}

    def requirements(self):
        from probe_a_inventory_integration import REQUIREMENTS
        r=self.record
        if (set(r)!={'v','boot','facts','requirements','provenance'} or type(r['v']) is not int or r['v']!=1
                or r['provenance']!='INDEPENDENT_KERNEL_FEATURE_RECEIPT' or r['boot']!=self.boot_identity()
                or canonical(r)!=self.raw or canonical(r['facts'])!=canonical(self.facts())
                or canonical(r['requirements'])!=canonical(REQUIREMENTS)
                or self.verifier(b'ProbeA kernel features\0'+self.raw,self.signature) is not True):
            raise InventoryDenied('EXTERNALLY_VERIFIED_KERNEL_FEATURE_RECEIPT_REQUIRED')
        return dict(REQUIREMENTS)
