"""Inactive provisioning and root-confinement contracts for the existing launcher.

The independent OS adapter is an external, reviewed trusted computing base.
No provisioner, policy installer or kernel evidence collector is bundled.
Read-only RPC restricts requests; it does not remove root/CAP_NET_ADMIN power.
"""
from __future__ import annotations

import time
from probe_a_session import canonical, decode, digest, SessionDenied
from probe_a_os_inventory import ROLES


class ExecutionDenied(SessionDenied):
    pass


def local_nss(raw):
    """Root helpers must never initiate DNS/LDAP/SSS/NIS through NSS."""
    if type(raw) is not bytes or len(raw) > 65536:
        raise ExecutionDenied("NSS_CONFIGURATION_BOUNDS")
    entries = {}
    try:
        for line in raw.decode("ascii").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            key, value = line.split(":", 1)
            if key in entries or value.split() != ["files"]:
                raise ExecutionDenied("NSS_NETWORK_OR_UNREVIEWED_BACKEND")
            entries[key] = value.strip()
    except (ValueError, UnicodeError):
        raise ExecutionDenied("MALFORMED_NSS_POLICY") from None
    if not {"passwd", "group", "shadow", "gshadow", "hosts"} <= set(entries):
        raise ExecutionDenied("NSS_CLOSURE_INCOMPLETE")
    return True


class OwnedScopeSet:
    """Read observations supplied by an independent trusted provisioning adapter.

    Every group has one root-owned canonical ancestry beneath the signed scope;
    no delegation, unexpected child group or writable actor cgroup descriptor.
    No mkdir, cgroup write or post-spawn PID migration exists here.
    """
    def __init__(self, context, groups, *, observe):
        if set(groups) != ROLES or len({g.identity for g in groups.values()}) != len(ROLES):
            raise ExecutionDenied("SEPARATE_ALL_ROLE_SCOPES_REQUIRED")
        if not callable(observe):
            raise ExecutionDenied("INDEPENDENT_SCOPE_OBSERVER_REQUIRED")
        self.context, self.groups, self.observe = context, dict(groups), observe
        self.uncertain = False

    def check(self, role, *, empty=False, identity=None):
        try:
            group = self.groups[role]
            record = self.observe(role, group.identity, self.context.identifier)
            fields = {"context", "role", "identity", "version", "owner", "ancestry",
                      "delegated", "children", "members", "populated", "atomic", "pidfd"}
            if (type(record) is not dict or set(record) != fields
                    or record["context"] != self.context.identifier or record["role"] != role
                    or record["identity"] != list(group.identity) or type(record["version"]) is not int or record["version"] != 2
                    or type(record["owner"]) is not list or any(type(n) is not int for n in record["owner"])
                    or record["owner"] != [0, 0, 0o700]
                    or record["ancestry"] != ["/sys/fs/cgroup", "p2a-" + self.context.plan.scope, role]
                    or record["delegated"] is not False or record["children"] != []
                    or record["atomic"] is not True or record["pidfd"] is not True
                    or type(record["members"]) is not list
                    or any(type(p) is not list or len(p) != 2
                           or any(type(n) is not int or n <= 1 for n in p) for p in record["members"])
                    or len({tuple(p) for p in record["members"]}) != len(record["members"])
                    or type(record["populated"]) is not bool
                    or record["populated"] != bool(record["members"])):
                raise ExecutionDenied("OWNERSHIP_ANCESTRY_DELEGATION_OR_KERNEL_FACTS")
            if empty and (record["members"] or record["populated"]):
                raise ExecutionDenied("DETACHED_DESCENDANT_OR_NONEMPTY_SCOPE")
            if identity is not None and [identity.pid, identity.starttime] not in record["members"]:
                raise ExecutionDenied("PROCESS_INCARNATION_OUTSIDE_OWNED_SCOPE")
            return record
        except BaseException:
            self.uncertain = True
            raise

    def preflight(self):
        if self.uncertain:
            raise ExecutionDenied("UNCERTAIN_PROVISIONING_CANNOT_BE_REUSED")
        for role in sorted(ROLES):
            self.check(role, empty=True)
        return True

    def cleanup_observed(self):
        # Teardown uncertainty is sticky. Never infer emptiness from kill/exit.
        try:
            for role in sorted(ROLES):
                self.check(role, empty=True)
        except BaseException:
            return False
        return not self.uncertain


class ReviewedExecutionContract:
    """One immutable session, signed policy and external kernel-enforcement API.

    verify_policy authenticates against an external trust root. enforce_child
    must install/verify the reviewed OS policy BEFORE exec; absence blocks.
    Root network denial must cover AF_INET/AF_INET6 and NSS, while allowing only
    reviewed firewall control operations. Scope observation cannot be actor RPC.
    Dependency injection is a source test technique, not kernel certification.
    """
    def __init__(self, context, inventory, scopes, policy, signature, *,
                 verify_policy=None, enforce_child=None, inspect_actor=None,
                 clock=time.monotonic):
        self.context, self.inventory, self.scopes = context, inventory, scopes
        self.policy_bytes = canonical(policy)
        self.policy = decode(self.policy_bytes)
        self.signature, self.verify_policy = signature, verify_policy
        self.enforce_child, self.inspect_actor, self.clock = enforce_child, inspect_actor, clock
        self.used_roles = set()
        self.permit = None
        self.children = {}
        self.poisoned = False

    def verify(self):
        p = self.policy
        if (self.poisoned or canonical(p) != self.policy_bytes
                or set(p) != {"v", "context", "inventory", "roles", "policy_digest"}
                or type(p["v"]) is not int or p["v"] != 1
                or p["context"] != self.context.identifier or p["inventory"] != self.context.inventory
                or not isinstance(self.scopes, OwnedScopeSet) or self.scopes.context != self.context
                or type(p["roles"]) is not dict or set(p["roles"]) != ROLES
                or not callable(self.verify_policy) or not callable(self.enforce_child)
                or not callable(self.inspect_actor) or type(self.signature) is not bytes
                or not self.signature
                or self.verify_policy(b"ProbeA confinement\x00" + self.policy_bytes, self.signature) is not True
                or self.inventory.verify_integration(self.context) is not True):
            raise ExecutionDenied("REVIEWED_EXTERNAL_CONFINEMENT_REQUIRED")
        from probe_a_session import hexvalue
        if not hexvalue(p["policy_digest"], 64):
            raise ExecutionDenied("UNIDENTIFIED_OS_POLICY")
        for role, rule in p["roles"].items():
            if (type(rule) is not dict or set(rule) != {"uids", "gids", "caps", "pre_exec_caps", "network", "nss", "fd_isolation", "source_mount"}
                    or rule["network"] != ("case-scoped" if role in ("worker", "peer") else "deny-inet-inet6")
                    or rule["nss"] != "files-only" or rule["fd_isolation"] != "exact-sealed-descriptors"
                    or rule["source_mount"] != "immutable-reviewed"
                    or type(rule["uids"]) is not list or len(rule["uids"]) != 4
                    or type(rule["gids"]) is not list or len(rule["gids"]) != 4
                    or type(rule["caps"]) is not list or len(rule["caps"]) != 5
                    or type(rule["pre_exec_caps"]) is not list or len(rule["pre_exec_caps"]) != 5
                    or any(type(n) is not int or n < 0 for n in rule["uids"] + rule["gids"] + rule["caps"] + rule["pre_exec_caps"])
                    or role == "controller" and (rule["uids"] != [65534]*4 or rule["gids"] != [65534]*4 or any(rule["caps"]))
                    or role != "worker" and rule["pre_exec_caps"] != rule["caps"]
                    or role == "worker" and (rule["uids"] != [self.context.plan.uid]*4 or rule["gids"] != [self.context.plan.uid]*4 or any(rule["caps"]))
                    or role not in ("worker", "controller") and rule["uids"] != [0]*4):
                raise ExecutionDenied("INCOMPLETE_OR_PERMISSIVE_ROOT_POLICY")
        return True

    def before_spawn(self, spec, deadline):
        self.verify()
        from probe_a_integrated_bootstrap import AttemptPermit
        if (not isinstance(self.permit, AttemptPermit) or self.permit.context != self.context
                or not self.permit.active(cleanup=spec.role == "guardian-command")):
            raise ExecutionDenied("EXTERNAL_ACTIVE_ATTEMPT_REQUIRED")
        self.context.check_time(self.clock(), cleanup=spec.role == "guardian-command")
        if (deadline > (self.context.end if spec.role == "guardian-command" else self.context.cutoff)
                or spec.group is not self.scopes.groups[spec.role]
                or spec.role in ("guardian", "observer", "controller") and spec.role in self.used_roles):
            raise ExecutionDenied("ROLE_REPLAY_OR_DEADLINE_EXTENSION")
        self.scopes.check(spec.role, empty=True)
        if self.clock() >= self.context.cutoff:
            from probe_contract import emergency_deny_commands, emergency_barrier_command
            safe = {c.argv for c in (*self.context.plan.inspect, *self.context.plan.teardown,
                                     *emergency_deny_commands(self.context.plan), emergency_barrier_command(self.context.plan))}
            from probe_a_os_boundary import SAVE4, SAVE6, VERSION4, VERSION6
            safe |= {SAVE4, SAVE6, VERSION4, VERSION6}
            if spec.argv not in safe:
                raise ExecutionDenied("WORK_DURING_RESERVED_CLEANUP")
        self.used_roles.add(spec.role)
        return True

    def child_ready_for_exec(self, spec):
        # This trusted adapter is supplied only to the bootstrap, never via IPC.
        if self.enforce_child(spec.role, self.policy, spec.inherited) is not True:
            raise ExecutionDenied("KERNEL_CONFINEMENT_NOT_ESTABLISHED")
        return True

    def verify_child_identity(self, spec):
        from probe_a_linux_identity import ProcessBinding
        import os
        own = ProcessBinding(os.getpid())
        try:
            rule = self.policy["roles"][spec.role]
            expected_uids = [0]*4 if spec.role == "worker" else rule["uids"]
            expected_gids = [0]*4 if spec.role == "worker" else rule["gids"]
            identity = own.identity
            if (list(identity.uids) != expected_uids or list(identity.gids) != expected_gids
                    or list(identity.capabilities) != rule["pre_exec_caps"] or identity.no_new_privs != 1
                    or spec.role == "controller" and identity.groups or own.verify() is not True):
                raise ExecutionDenied("UNEXPECTED_PRE_EXEC_EFFECTIVE_IDENTITY")
            return True
        finally:
            own.close()

    def ready(self, role, identity):
        self.verify()
        self.scopes.check(role, identity=identity)
        rule = self.policy["roles"][role]
        if (list(identity.uids) != rule["uids"] or list(identity.gids) != rule["gids"]
                or list(identity.capabilities) != rule["caps"] or identity.no_new_privs != 1
                or self.inspect_actor(role, identity, self.context.identifier, self.policy_bytes) is not True):
            raise ExecutionDenied("ACTOR_OS_POLICY_IDENTITY_UNVERIFIED")
        return True

    def stopped(self, role, identity):
        self.verify()
        self.scopes.check(role, empty=True)
        return True

    def child_spawned(self, role, handle):
        from probe_a_linux_identity import ProcessBinding
        from probe_a_session import DelegatedProcessBinding
        import select
        if role in self.children or select.select([handle.pidfd], [], [], 0)[0]:
            raise ExecutionDenied("DUPLICATE_OR_STALE_ATOMIC_CHILD")
        fields = [line.split(":",1)[1].strip() for line in DelegatedProcessBinding._fdinfo(handle.pidfd).splitlines() if line.startswith("Pid:")]
        if fields != [str(handle.pid)]:
            raise ExecutionDenied("WRONG_ATOMIC_PIDFD")
        binding = ProcessBinding(handle.pid)
        if select.select([handle.pidfd], [], [], 0)[0]:
            binding.close()
            raise ExecutionDenied("CHILD_EXIT_DURING_KERNEL_BINDING")
        self.children[role] = (handle, binding)

    def worker_identity(self, pid, uid):
        handle, binding = self.children["worker"]
        if pid != handle.pid or uid != self.context.plan.uid or handle.exited():
            raise ExecutionDenied("WORKER_PIDFD_OR_UID_MISMATCH")
        observed = binding.snapshot()
        if (observed.pid != pid or observed.starttime != binding.identity.starttime
                or observed.uids != (uid,)*4 or observed.gids != (uid,)*4 or observed.groups
                or any(observed.capabilities) or observed.no_new_privs != 1):
            return False  # a setpriv transition may still be in progress
        alias = self.inventory.document["aliases"].get("/usr/bin/python3")
        target = alias["target"] if alias is not None else "/usr/bin/python3"
        expected = self.inventory.document["metadata"][target]
        if observed.executable != (expected["device"], expected["inode"]):
            raise ExecutionDenied("WRONG_WORKER_INTERPRETER")
        self.scopes.check("worker", identity=observed)
        return self.inspect_actor("worker", observed, self.context.identifier, self.policy_bytes) is True

    def worker_listener(self, pid):
        from probe_a_resources import attest_listener
        if not self.worker_identity(pid, self.context.plan.uid): return False
        observed = self.children["worker"][1].snapshot()
        answer = attest_listener(pid)
        if self.children["worker"][1].snapshot() != observed:
            raise ExecutionDenied("LISTENER_PROCESS_INCARNATION_DRIFT")
        return answer is True

    def child_finished(self, role):
        value = self.children.pop(role, None)
        if value is not None: value[1].close()
