"""Uninstalled Linux policy source: seccomp socket-family guard + AppArmor.

Only the intended x86_64/nft backend is supported. This is defense in depth,
not a read-only CAP_NET_ADMIN. Profiles, mount layout and capability profiles
still require an externally reviewed runner package. No installation on import.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
from probe_a_session import SessionDenied, canonical
from probe_a_linux_identity import read_at, read_process_attribute

# Classic BPF over struct seccomp_data, x86_64 syscall ABI only.
LD_ABS, JEQ, JSET, RET = 0x20, 0x15, 0x45, 0x06
ALLOW, DENY, KILL = 0x7fff0000, 0x00050000 | errno.EPERM, 0x80000000
ARCH_X86_64 = 0xc000003e
DANGEROUS = (101,155,161,165,166,175,176,246,272,298,304,308,310,311,312,313,321,323,425,426,427,438)
# ptrace,pivot_root,chroot,mount,umount,module,kexec,unshare,perf,open_by_handle,
# setns,process_vm_read/write,finit_module,bpf,userfaultfd,io_uring*.


def socket_filter(role):
    """Root helper cannot use AF_UNIX delegation, packet sockets or IP egress.

    Existing authenticated Unix descriptors remain usable. NFNETLINK is the
    only new root socket route, required by reviewed iptables-nft. Worker/peer
    IP behavior remains subject to UID firewall and separately reviewed LSM.
    No IPv4 legacy-control fallback. Blocking dangerous alternate mechanisms
    prevents common policy bypasses; this is not a general syscall sandbox.
    """
    if role not in ("supervisor","guardian","observer","controller","read-command","guardian-command","worker","peer"):
        raise SessionDenied("UNSUPPORTED_NATIVE_POLICY_ROLE")
    code = [(LD_ABS,0,0,4),(JEQ,1,0,ARCH_X86_64),(RET,0,0,KILL),(LD_ABS,0,0,0)]
    # x32 syscalls and execveat remain unsupported; ordinary execve(fd) uses
    # execveat in CPython and thus MUST remain available to the reviewed exec.
    code += [(JSET,0,1,0x40000000),(RET,0,0,KILL)]
    for syscall in DANGEROUS:
        code += [(JEQ,0,1,syscall),(RET,0,0,DENY)]
    # Classic clone's namespace flags are inline and can be checked. clone3's
    # pointed-to struct cannot be dereferenced by seccomp, so only the fixed
    # trusted parents may use it; leaf/untrusted roles deny it altogether.
    namespace_flags=0x00020000|0x02000000|0x04000000|0x08000000|0x10000000|0x20000000|0x40000000
    code += [(JEQ,0,4,56),(LD_ABS,0,0,16),(JSET,0,1,namespace_flags),
             (RET,0,0,DENY),(LD_ABS,0,0,0)]
    if role in ('controller','worker','peer','read-command','guardian-command'):
        code += [(JEQ,0,1,435),(RET,0,0,DENY)]
    if role in ("supervisor","guardian","observer","worker","peer"):
        # Ancestors must not install socket denials inherited by a legitimate
        # worker/peer. Root denial belongs to the authenticated stacked LSM
        # ROLE profile. The retained BASE still denies namespace/escape routes.
        code.append((RET,0,0,ALLOW))
        return tuple(code)
    # socketpair is denied AFTER allocation; root helpers cannot obtain a new
    # indirect UNIX route. AF_NETLINK protocol12 is Netfilter, never Route.
    code += [(JEQ,0,1,53),(RET,0,0,DENY), (JEQ,1,0,41),(RET,0,0,ALLOW),
             (LD_ABS,0,0,16),(JEQ,1,0,16),(RET,0,0,DENY),
             (LD_ABS,0,0,32),(JEQ,1,0,12),(RET,0,0,DENY),(RET,0,0,ALLOW)]
    return tuple(code)


class SockFilter(ctypes.Structure):
    _fields_ = [("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [("length",ctypes.c_ushort),("filter",ctypes.POINTER(SockFilter))]


class NativePolicyAdapter:
    """Concrete child policy installation + kernel label/status inspection.

    AppArmor profiles are already installed by a SEPARATELY approved runner
    provisioner. This module does not install profiles or remount filesystems.
    Source mount must be read-only and role capabilities externally pinned.
    Bootstrap profile must deny unapproved binaries, ledger access by child
    roles, filesystem writes, descriptor acquisition and cgroup delegation.
    Those necessary profile assets are currently an explicit source blocker.
    """
    def __init__(self, context, *, profiles, source_mount, backend, policy_identity,
                 verify_policy_package, grant, base_profile="probe-a-base", activated=False):
        self.context, self.profiles, self.mount = context, dict(profiles), source_mount
        self.backend, self.policy_identity, self.verify_package = backend, policy_identity, verify_policy_package
        self.grant, self.activated = grant, activated is True
        self.base_profile=base_profile

    def label(self,role):
        return self.base_profile+"//&"+self.profiles[role]+" (enforce)"

    def prepare_base(self):
        """One trusted initial runner BASE; before any role construction.

        Linux v6.12 AppArmor caches the NNP baseline during change_profile.
        Never first establish NNP under a restrictive guardian label. A
        later role exec retains BASE and may replace only the ROLE component.
        No effect unless explicit activation and genuine runner verification.
        """
        self._gate('supervisor')
        if self.base_profile!='probe-a-base':raise SessionDenied('UNSUPPORTED_BASE_PROFILE')
        current=open('/proc/self/attr/current','rb').read(4097)
        if current!=b'probe-a-base (enforce)\n':raise SessionDenied('EXTERNAL_RUNNER_BASE_REQUIRED')
        libc=ctypes.CDLL(None,use_errno=True)
        if len(os.listdir('/proc/self/task'))!=1 or libc.prctl(38,1,0,0,0)!=0:
            raise SessionDenied('POLICY_NNP_OR_SINGLE_THREAD_REQUIRED')
        self._write_attribute('current',b'changeprofile probe-a-base')
        return True

    @staticmethod
    def _write_attribute(name,payload):
        if name not in ('current','exec'):raise SessionDenied('UNAPPROVED_POLICY_ATTRIBUTE')
        fd=os.open('/proc/self/attr/'+name,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            if os.write(fd,payload)!=len(payload):raise SessionDenied('APPARMOR_TRANSITION_UNCERTAIN')
        finally:os.close(fd)

    def _gate(self, role):
        if (not self.activated or os.geteuid() != 0 or platform.machine() != "x86_64"
                or self.backend != "iptables-nft" or role not in self.profiles
                or not self.grant.active(cleanup=role in ("read-command","guardian-command","supervisor"))
                or self.verify_package(self.policy_identity) is not True):
            raise SessionDenied("NATIVE_POLICY_DISABLED_OR_RUNNER_PACKAGE_UNSUPPORTED")

    def enforce_child(self, role, policy, inherited):
        self._gate(role)
        from probe_a_native_credentials import NativeRoleCredentials
        NativeRoleCredentials().install(role,policy)
        # A profile name/status is insufficient authentication of its rules.
        # Activation requires an independently pinned policy-package verifier.
        profile = self.profiles[role]
        if type(profile) is not str or not profile.startswith("probe-a-") or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in profile):
            raise SessionDenied("UNAPPROVED_APPARMOR_PROFILE")
        current = open("/proc/self/attr/current","rb").read(4097)
        if b"unconfined" in current or len(current) > 4096:
            raise SessionDenied("BOOTSTRAP_APPARMOR_CONFINEMENT_REQUIRED")
        labels=current.decode('ascii').strip().removesuffix(' (enforce)').split('//&')
        if self.base_profile not in labels or len(set(labels))!=len(labels):
            raise SessionDenied('RETAINED_BASE_PROFILE_REQUIRED')
        self._write_attribute('exec',b'exec '+(self.base_profile+'//&'+profile).encode('ascii'))
        instructions = socket_filter(role)
        native = (SockFilter*len(instructions))(*(SockFilter(*i) for i in instructions))
        program = SockFprog(len(native),native)
        libc = ctypes.CDLL(None,use_errno=True)
        # NoNewPrivs then irreversible per-thread filter; threaded roots reject.
        if len(os.listdir("/proc/self/task")) != 1 or libc.prctl(38,1,0,0,0) != 0:
            raise SessionDenied("POLICY_NNP_OR_SINGLE_THREAD_REQUIRED")
        if libc.syscall(ctypes.c_long(317),ctypes.c_uint(1),ctypes.c_uint(0),ctypes.byref(program)) != 0:
            raise SessionDenied("SECCOMP_INSTALL_FAILED_NO_FALLBACK")
        return True

    def inspect_actor(self, role, identity, context, policy):
        self._gate(role)
        if context != self.context.identifier or role not in self.profiles:
            raise SessionDenied("POLICY_INSPECTOR_CONTEXT_MISMATCH")
        from probe_a_linux_identity import ProcessBinding
        binding = ProcessBinding(identity.pid)
        try:
            if binding.identity != identity or binding.verify() is not True:
                raise SessionDenied("POLICY_INSPECTION_STALE_PROCESS")
            label = read_process_attribute(binding).strip()
            status = read_at(binding.procfd,"status")
            fields={}
            for line in status.splitlines():
                key,sep,value=line.partition(':')
                if sep:
                    if key in fields:raise SessionDenied('MALFORMED_POLICY_STATUS')
                    fields[key]=value.strip()
            if label != self.label(role) or fields.get("Seccomp") != "2" or fields.get('NoNewPrivs')!='1':
                raise SessionDenied("KERNEL_PROFILE_OR_SECCOMP_NOT_ENFORCING")
            # Actual mount topology/configuration is part of the independent
            # signed package verifier, never a caller-provided 'readonly' bit.
            if self.verify_package(self.policy_identity) is not True or binding.verify() is not True:
                raise SessionDenied("POLICY_PACKAGE_OR_PROCESS_DRIFT")
            return True
        finally: binding.close()


class InstalledPolicyInspector:
    """Authenticate actual kernel raw policy bytes and immutable source mount.

    Signed expected hashes come from separately approved policy compilation;
    a label name, Seccomp=2 or signed 'readonly' boolean is insufficient.
    Unsupported securityfs/raw-data/mount layouts reject, never fall back.
    """
    def __init__(self, record, *, reader, profiles, source_mount):
        self.record,self.reader,self.profiles,self.mount=record,reader,profiles,source_mount
    def __call__(self,identity):
        import hashlib
        from probe_a_linux_identity import read_fd
        r=self.record
        if (set(r)!={'identity','raw_profiles','source_mount_id'} or identity!=r['identity']
                or set(r['raw_profiles'])!=set(self.profiles.values())|{'probe-a-base'}):
            raise SessionDenied('INSTALLED_POLICY_CLOSURE_INCOMPLETE')
        for name,asset in r['raw_profiles'].items():
            if (set(asset)!={'path','sha256'} or not asset['path'].startswith('/sys/kernel/security/apparmor/policy/profiles/'+name+'.')
                    or asset['path'].rsplit('/',1)[-1]!='raw_data'
                    or hashlib.sha256(self.reader.read_asset(asset['path'])).hexdigest()!=asset['sha256']):
                raise SessionDenied('INSTALLED_POLICY_CONTENT_DRIFT')
        fd=os.open('/proc/self/mountinfo',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:raw=read_fd(fd,131072).decode('ascii')
        finally:os.close(fd)
        rows=[]
        for line in raw.splitlines():
            left,sep,right=line.partition(' - ');fields=left.split();tail=right.split()
            if not sep or len(fields)<6 or len(tail)<3:raise SessionDenied('MALFORMED_MOUNT_INSPECTION')
            # This reviewed layout has no escaped names or nested mounts.
            # A read-only parent says nothing about a writable child mount.
            path=fields[4]
            if '\\' in path or not path.startswith('/') or any(p in ('.','..') for p in path.split('/')):
                raise SessionDenied('UNSUPPORTED_ESCAPED_OR_NONCANONICAL_MOUNT')
            if path.startswith(self.mount.rstrip('/')+'/'):
                raise SessionDenied('UNAPPROVED_SOURCE_DESCENDANT_MOUNT')
            if path==self.mount:rows.append((fields,tail))
        if (len(rows)!=1 or rows[0][0][0]!=str(r['source_mount_id'])
                or not {'ro','nosuid','nodev'}<=set(rows[0][0][5].split(','))
                or 'ro' not in rows[0][1][2].split(',')):
            raise SessionDenied('SOURCE_MOUNT_NOT_AUTHENTICATED_IMMUTABLE')
        return True
