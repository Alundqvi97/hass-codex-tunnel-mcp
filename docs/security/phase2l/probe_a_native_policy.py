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
from probe_a_linux_identity import read_at

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
    if role in ("worker","peer"):
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
                 verify_policy_package, grant, activated=False):
        self.context, self.profiles, self.mount = context, dict(profiles), source_mount
        self.backend, self.policy_identity, self.verify_package = backend, policy_identity, verify_policy_package
        self.grant, self.activated = grant, activated is True

    def _gate(self, role):
        if (not self.activated or os.geteuid() != 0 or platform.machine() != "x86_64"
                or self.backend != "iptables-nft" or role not in self.profiles
                or not self.grant.active(cleanup=role in ("read-command","guardian-command","supervisor"))
                or self.verify_package(self.policy_identity) is not True):
            raise SessionDenied("NATIVE_POLICY_DISABLED_OR_RUNNER_PACKAGE_UNSUPPORTED")

    def enforce_child(self, role, policy, inherited):
        self._gate(role)
        # A profile name/status is insufficient authentication of its rules.
        # Activation requires an independently pinned policy-package verifier.
        profile = self.profiles[role]
        if type(profile) is not str or not profile.startswith("probe-a-") or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in profile):
            raise SessionDenied("UNAPPROVED_APPARMOR_PROFILE")
        current = open("/proc/self/attr/current","rb").read(4097)
        if b"unconfined" in current or len(current) > 4096:
            raise SessionDenied("BOOTSTRAP_APPARMOR_CONFINEMENT_REQUIRED")
        fd = os.open("/proc/self/attr/exec",os.O_WRONLY|os.O_CLOEXEC)
        try:
            payload = b"exec "+profile.encode("ascii")
            if os.write(fd,payload) != len(payload): raise SessionDenied("APPARMOR_EXEC_TRANSITION_UNCERTAIN")
        finally: os.close(fd)
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
        if context != self.context.identifier or role not in self.profiles:
            raise SessionDenied("POLICY_INSPECTOR_CONTEXT_MISMATCH")
        from probe_a_linux_identity import ProcessBinding
        binding = ProcessBinding(identity.pid)
        try:
            if binding.identity != identity or binding.verify() is not True:
                raise SessionDenied("POLICY_INSPECTION_STALE_PROCESS")
            label = read_at(binding.procfd,"attr/current",4096).decode("ascii").strip()
            status = read_at(binding.procfd,"status").decode("ascii")
            fields = dict(line.split(":",1) for line in status.splitlines() if ":" in line)
            if label != self.profiles[role]+" (enforce)" or fields.get("Seccomp","").strip() != "2":
                raise SessionDenied("KERNEL_PROFILE_OR_SECCOMP_NOT_ENFORCING")
            # Actual mount topology/configuration is part of the independent
            # signed package verifier, never a caller-provided 'readonly' bit.
            if self.verify_package(self.policy_identity) is not True or binding.verify() is not True:
                raise SessionDenied("POLICY_PACKAGE_OR_PROCESS_DRIFT")
            return True
        finally: binding.close()
