"""Disabled native adapter for the existing CgroupV2Containment contract.

No provisioning, post-spawn PID migration or process launch at import. Each
worker/root peer is attached by clone3 before exec. Killing a group includes
detached descendants, subject to separately UNVERIFIED kernel acceptance.
Independent broker readback, not this mutation adapter, owns final evidence.
"""
from __future__ import annotations

import math
import time

from probe_a_exec_adapter import checked_reply
from probe_a_linux_launcher import NativeAtomicSpawner, NativeBoundedCapture, LaunchDenied, empty_group
from probe_a_workload import CASES_ORDER, exact_argv, peer_argv
from probe_contract import validate_plan


class NativeContainmentAdapter:
    def __init__(self, plan, specs, *, spawner, independent_uid_absent,
                 activated=False, approval=None, clock=time.monotonic):
        expected = {exact_argv(plan, case) for case in CASES_ORDER} | {peer_argv()}
        if (validate_plan(plan) != "OFFLINE_SAFE_SCOPED_PLAN_NOT_KERNEL_VERIFIED"
                or set(specs) != expected or not isinstance(spawner, NativeAtomicSpawner)
                or not callable(independent_uid_absent)):
            raise LaunchDenied("EXACT_CONTAINMENT_BINDINGS_REQUIRED")
        for argv, spec in specs.items():
            role = "peer" if argv == peer_argv() else "worker"
            if spec.argv != argv or spec.role != role or spec.inherited:
                raise LaunchDenied("WORKER_PEER_ROLE_OR_DESCRIPTOR_MISMATCH")
        worker_specs = {argv: spec for argv, spec in specs.items() if argv != peer_argv()}
        worker_groups = {spec.group.identity for spec in worker_specs.values()}
        if (len(worker_groups) != 1
                or specs[peer_argv()].group.identity in worker_groups):
            raise LaunchDenied("DISTINCT_WORKER_AND_ROOT_PEER_GROUPS_REQUIRED")
        self.groups = (next(iter(worker_specs.values())).group, specs[peer_argv()].group)
        self.plan, self.path, self.clock = plan, "/sys/fs/cgroup/p2a-" + plan.scope, clock
        self.spawner, self.activated, self.approval = spawner, activated, approval
        self.independent_uid_absent = independent_uid_absent
        # Separate bounded executor permits the fixed peer during worker READY.
        self.worker = NativeBoundedCapture(worker_specs, spawner=spawner,
                                          plan=plan, activated=activated, approval=approval, clock=clock)
        self.peer = NativeBoundedCapture({peer_argv(): specs[peer_argv()]}, spawner=spawner,
                                        plan=plan, activated=activated, approval=approval, clock=clock)
        self.stopped = False

    def _scope(self, path):
        if path != self.path or self.activated is not True:
            raise LaunchDenied("CONTAINMENT_DISABLED_OR_SCOPE_MISMATCH")

    def preflight_atomic_spawn(self, path):
        self._scope(path)
        if self.spawner.inventory is None or self.spawner.inventory.verify() is not True:
            raise LaunchDenied("CONTAINMENT_INVENTORY_REQUIRED")
        from probe_a_execution_contract import ReviewedExecutionContract
        if not isinstance(self.spawner.contract, ReviewedExecutionContract):
            raise LaunchDenied("INDEPENDENT_CONTAINMENT_POLICY_REQUIRED")
        for role in ("worker", "peer"):
            self.spawner.contract.scopes.check(role, empty=True)
        for group in self.groups:
            group.verify(empty=True)
        # This selects actual CLONE_INTO_CGROUP machinery, not proof that an
        # untested kernel enforces quotas/no delegation/no escape. No PASS.
        return True

    def capture_atomic(self, path, argv, timeout, **callbacks):
        self._scope(path)
        if self.stopped or set(callbacks) - {"on_spawn", "on_chunk"}:
            raise LaunchDenied("STOPPED_OR_UNREVIEWED_WORKER_CALLBACKS")
        capture = self.peer if argv == peer_argv() else self.worker
        return checked_reply(capture(argv, timeout, **callbacks))

    def kill_all(self, path, deadline):
        self._scope(path)
        self.stopped = True
        if not self.clock() < deadline:
            return False
        for group in self.groups:
            group.kill_all()
        return self.clock() < deadline  # writes issued; NEVER cleanup proof

    def readback(self, path, deadline):
        self._scope(path)
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not self.clock() < deadline):
            raise LaunchDenied("CONTAINMENT_READBACK_DEADLINE")
        # Aggregate only strictly parsed kernel observations of both groups.
        snapshots = [group.readback() for group in self.groups]
        if self.clock() >= deadline:
            raise LaunchDenied("CONTAINMENT_READBACK_EXPIRED")
        empty = all(empty_group(*value) for value in snapshots)
        if empty:
            # Guardian-local reads cannot substitute for the independent scope
            # authority that includes descendants and exact owned group IDs.
            for role in ("worker", "peer"):
                self.spawner.contract.scopes.check(role, empty=True)
        return ("populated " + ("0" if empty else "1") + "\n",
                "".join(value[1] for value in snapshots))

    def check_uid_absent(self, uid, deadline):
        if uid != self.plan.uid or self.clock() >= deadline:
            return False
        value = self.independent_uid_absent(uid, deadline)
        return value is True and self.clock() < deadline
