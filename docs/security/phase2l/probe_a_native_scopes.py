"""Independent cgroup-v2 observation and separately gated provisioning source.

No cgroup operation on import/default calls. Native functions are UNEXECUTED
in this delivery. Fixtures inject filesystem/kernel boundaries only.
"""
from __future__ import annotations

import os
import stat
import time
from probe_a_session import SessionDenied, canonical
from probe_a_os_inventory import ROLES
from probe_a_linux_launcher import OwnedCgroup, empty_group
from probe_a_linux_identity import ProcessBinding, read_at


class NativeScopeObserver:
    def __init__(self, context, groups, *, parent_identities, clock=time.monotonic):
        if set(groups) != ROLES or set(parent_identities) != {"/sys/fs/cgroup", "/sys/fs/cgroup/p2a-"+context.plan.scope}:
            raise SessionDenied("NATIVE_SCOPE_PARENTS_MUST_BE_PINNED")
        self.context, self.groups, self.parents, self.clock = context, groups, parent_identities, clock

    def _time(self):
        if self.clock() >= self.context.end: raise SessionDenied("NATIVE_SCOPE_OBSERVATION_EXPIRED")

    def __call__(self, role, identity, context):
        self._time()
        if role not in ROLES or context != self.context.identifier or self.groups[role].identity != identity:
            raise SessionDenied("NATIVE_SCOPE_CONTEXT_SUBSTITUTION")
        group = self.groups[role]; group.verify()
        scope = "/sys/fs/cgroup/p2a-"+self.context.plan.scope
        owned = []
        try:
            # Independently reopen parent/path; retained old FDs alone miss
            # path substitution. No-follow is applied to EVERY ancestor.
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC); owned.append(fd)
            path = ""
            for component in ("sys", "fs", "cgroup", "p2a-"+self.context.plan.scope, role):
                self._time()
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd); owned.append(fd)
                path += "/"+component; info = os.fstat(fd)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise SessionDenied("NATIVE_CGROUP_ANCESTRY_UNCONTROLLED")
                expected = self.parents.get(path, identity if path == scope+"/"+role else None)
                if expected is not None and (info.st_dev,info.st_ino) != tuple(expected):
                    raise SessionDenied("NATIVE_CGROUP_PARENT_OR_GROUP_REPLACED")
            st = os.fstat(fd)
            if stat.S_IMODE(st.st_mode) != 0o700 or st.st_gid != 0:
                raise SessionDenied("NATIVE_CGROUP_OWNER_OR_MODE")
            children = [n for n in os.listdir(fd) if stat.S_ISDIR(os.stat(n,dir_fd=fd,follow_symlinks=False).st_mode)]
            if len(children) > 128: raise SessionDenied("NATIVE_CGROUP_DESCENDANT_OVERFLOW")
            members = []
            procs = read_at(fd,"cgroup.procs")
            events = read_at(fd,"cgroup.events")
            population = not empty_group(events,procs)
            for item in procs.splitlines():
                self._time()
                if not item.isdecimal() or int(item) <= 1 or len(members) >= 256:
                    raise SessionDenied("NATIVE_SCOPE_PROCESS_BOUNDS")
                binding = ProcessBinding(int(item))
                try:
                    if read_at(binding.procfd,"cgroup") != "0::/p2a-"+self.context.plan.scope+"/"+role+"\n":
                        raise SessionDenied("NATIVE_SCOPE_PROCESS_MOVED_OR_ESCAPED")
                    if binding.verify() is not True: raise SessionDenied("NATIVE_SCOPE_STALE_INCARNATION")
                    members.append([binding.identity.pid,binding.identity.starttime])
                finally:
                    binding.close()
            if members:
                raise SessionDenied("SOURCE_GAP_INDEPENDENT_PREEXEC_ATTACHMENT_TRACE")
            delegated = (read_at(fd,"cgroup.subtree_control").strip() != ""
                         or read_at(fd,"cgroup.type").strip() != "domain")
            control = os.stat("cgroup.procs",dir_fd=fd,follow_symlinks=False)
            delegated |= control.st_uid != 0 or control.st_gid != 0 or bool(control.st_mode & 0o022)
            # Membership churn or detached descendants cannot become empty.
            if read_at(fd,"cgroup.procs") != procs or read_at(fd,"cgroup.events") != events:
                raise SessionDenied("NATIVE_SCOPE_CHANGED_DURING_OBSERVATION")
            group.verify(); self._time()
            return {"context":context,"role":role,"identity":list(identity),"version":2,
                "owner":[st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)],
                "ancestry":["/sys/fs/cgroup","p2a-"+self.context.plan.scope,role],
                "delegated":bool(delegated),"children":sorted(children),"members":members,
                "populated":population,"atomic":True,"pidfd":True}
        finally:
            for fd in reversed(owned): os.close(fd)


def provision_scopes(context, root_fd, permission, signature, *, verify, activated=False):
    """Exclusive seven-scope creation, only under SEPARATE provision approval.

    Does not move a PID or start an actor. Never cleans uncertain populated
    groups. Failure reports the precise created set for an owned-only teardown.
    Scope device/inodes are collected only after provisioning, never invented.
    """
    expected = {"v":1,"purpose":"provision-probe-a-scopes","context":context.identifier,
                "roles":sorted(ROLES)}
    if (activated is not True or os.geteuid() != 0 or permission != expected
            or type(signature) is not bytes or verify(b"ProbeA cgroup provisioning\x00"+canonical(expected),signature) is not True):
        raise SessionDenied("SEPARATE_SCOPE_PROVISIONING_AUTHORIZATION_REQUIRED")
    st = os.fstat(root_fd)
    root = OwnedCgroup(root_fd,(st.st_dev,st.st_ino)); root.verify()
    name = "p2a-"+context.plan.scope; created, result, fd = [], {}, None
    try:
        os.mkdir(name,0o700,dir_fd=root_fd)
        fd = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root_fd)
        for role in sorted(ROLES):
            context.check_time(time.monotonic())
            os.mkdir(role,0o700,dir_fd=fd); created.append(role)
            child = os.open(role,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            info = os.fstat(child); group = OwnedCgroup(child,(info.st_dev,info.st_ino))
            try: group.verify(empty=True)
            except BaseException: os.close(child); raise
            result[role] = group
        return result
    except BaseException as error:
        for group in result.values(): os.close(group.fd)
        raise SessionDenied("PARTIAL_SCOPE_PROVISIONING:"+",".join(created)) from error
    finally:
        if fd is not None: os.close(fd)


def teardown_scopes(context, groups, *, permission, signature, verify, activated=False):
    expected = {"v":1,"purpose":"teardown-probe-a-scopes","context":context.identifier,
                "groups":{r:list(g.identity) for r,g in groups.items()}}
    if (activated is not True or os.geteuid() != 0 or set(groups) != ROLES or permission != expected
            or verify(b"ProbeA cgroup teardown\x00"+canonical(expected),signature) is not True):
        raise SessionDenied("SEPARATE_SCOPE_TEARDOWN_AUTHORIZATION_REQUIRED")
    # Reopen exact parent and compare every retained inode; no blind rmtree.
    parent_path = "/sys/fs/cgroup/p2a-"+context.plan.scope
    parent = os.open(parent_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for role in sorted(ROLES):
            groups[role].verify(empty=True)
            info = os.stat(role,dir_fd=parent,follow_symlinks=False)
            if (info.st_dev,info.st_ino) != groups[role].identity:
                raise SessionDenied("TEARDOWN_PATH_OR_OWNERSHIP_UNCERTAIN")
            os.rmdir(role,dir_fd=parent)
        os.rmdir(parent_path)
    finally:
        os.close(parent)
