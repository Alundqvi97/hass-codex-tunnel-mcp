"""Inactive sealed handoff composition for TrustedActorBootstrap/clone3.

External runner policy, inventory signature, atomic authorization ledger and
preprovisioned scopes are mandatory. No automatic entrypoint or provisioning.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import time
from probe_a_session import (SessionDenied, PendingRoleConfiguration, RoleConfiguration,
                             canonical, decode, digest)
from probe_a_linux_identity import ProcessBinding, CredentialSocket
from probe_a_ipc import BoundedSocketIPC
from probe_a_coordinator import ActorReadinessCoordinator
from probe_a_linux_launcher import (ExecSpec, NativeAtomicSpawner, IndependentSupervisor,
                                    deadline_pair)


class AttemptPermit:
    """External signed context + trusted persistent atomic anti-replay ledger.

    A process-local 'used' flag alone is insufficient across bootstrap crashes.
    Boot identity and monotonic deadline must be independently observed by the
    authorization service. No signing or approval creation occurs here.
    """
    def __init__(self, context, record, signature, *, verify=None, consume=None,
                 boot_identity=None, clock=time.monotonic):
        self.context, self.record_bytes = context, canonical(record)
        self.record = decode(self.record_bytes)
        self.signature, self.verify, self.consume = signature, verify, consume
        self.boot_identity, self.clock, self.used = boot_identity, clock, False
        self.granted = False
        self._bootstrap_receipt = None

    def claim(self):
        if (self.used or canonical(self.record) != self.record_bytes
                or set(self.record) != {"v", "context", "boot", "purpose", "expires"}
                or type(self.record["v"]) is not int or self.record["v"] != 1
                or self.record["context"] != self.context.identifier
                or self.record["purpose"] != "one-probe-a-attempt"
                or self.record["expires"] != self.context.end
                or not callable(self.boot_identity) or self.record["boot"] != self.boot_identity()
                or not callable(self.verify) or not callable(self.consume)
                or type(self.signature) is not bytes or not self.signature
                or self.verify(b"ProbeA attempt\x00"+self.record_bytes, self.signature) is not True):
            raise SessionDenied("EXTERNAL_ONE_ATTEMPT_AUTHORIZATION_REQUIRED")
        self.used = True  # uncertainty consumes the attempt, even if ledger fails
        self.context.check_time(self.clock())
        if self.consume(self.context.session, digest(self.record), self.record["boot"]) is not True:
            raise SessionDenied("REPLAY_OR_UNCERTAIN_AUTHORIZATION_LEDGER")
        self.granted = True
        self._bootstrap_receipt = object()
        return self.active()

    def consume_bootstrap_receipt(self, receipt):
        if receipt is None or receipt is not self._bootstrap_receipt or not self.active():
            raise SessionDenied("BOOTSTRAP_CLAIM_HANDOFF_REPLAY_OR_SUBSTITUTION")
        self._bootstrap_receipt = None
        return True

    def active(self, *, cleanup=False):
        return (self.used and self.granted and canonical(self.record) == self.record_bytes
                and callable(self.boot_identity) and self.record["boot"] == self.boot_identity()
                and self.clock() < (self.context.end if cleanup else self.context.cutoff))


@dataclass
class ActorPreparation:
    spec: ExecSpec
    pending: PendingRoleConfiguration
    startup: object
    configuration: RoleConfiguration | None = None
    owner: object | None = None


class ReviewedActorFactory:
    """Trusted allocation interface, disconnected until a claimed permit exists.

    The separately reviewed allocation function creates private socketpairs,
    readonly memfd views and exact per-role pidfd copies; no actor supplies it.
    Validation here binds its output to the existing immutable ExecSpec and
    signed role vectors, then derives incarnation from the blocked cloned child.
    """
    def __init__(self, context, bootstrap_identity, *, allocate):
        self.context, self.bootstrap_identity, self.allocate = context, bootstrap_identity, allocate
        self.used = set()

    def prepare(self, role, bindings, *, permit, contract):
        if role in self.used or not isinstance(permit, AttemptPermit) or not permit.active():
            raise SessionDenied("FACTORY_DISABLED_OR_ROLE_REPLAY")
        self.used.add(role)
        prepared = self.allocate(role, dict(bindings), permit, contract)
        if (not isinstance(prepared, ActorPreparation) or not isinstance(prepared.spec, ExecSpec)
                or not isinstance(prepared.pending, PendingRoleConfiguration)
                or prepared.spec.role != role
                or ("config", prepared.pending.reader) not in prepared.spec.inherited):
            raise SessionDenied("UNREVIEWED_ACTOR_ALLOCATION")
        previous_build = prepared.pending.build
        def build(kernel_identity):
            config = previous_build(kernel_identity)
            if (not isinstance(config, RoleConfiguration) or config.context != self.context
                    or config.role != role or config.bootstrap != self.bootstrap_identity
                    or config.identity.pid != kernel_identity.pid
                    or config.identity.starttime != kernel_identity.starttime
                    or set(dict(config.descriptors).values()) != {
                        fd for kind, fd in prepared.spec.inherited if kind != "config"}
                    or role == "controller" and dict(config.peers) != {
                        r: bindings[r].identity for r in ("guardian", "observer")}):
                raise SessionDenied("ACTOR_ALLOCATION_CONTEXT_OR_DESCRIPTOR_SUBSTITUTION")
            st = os.fstat(prepared.spec.executable_fd)
            if config.identity.executable != (st.st_dev, st.st_ino):
                raise SessionDenied("WRONG_ROLE_EXECUTABLE_HANDOFF")
            prepared.configuration = config
            return config
        prepared.pending.build = build
        return prepared


class IntegratedBootstrap:
    """Extension of the existing launcher, not a second process architecture."""
    def __init__(self, *, spawner, factory, permit, clock=time.monotonic, bootstrap_receipt=None):
        if not isinstance(spawner, NativeAtomicSpawner) or not isinstance(factory, ReviewedActorFactory):
            raise SessionDenied("EXISTING_ATOMIC_LAUNCHER_REQUIRED")
        self.spawner, self.factory, self.permit, self.clock = spawner, factory, permit, clock
        self.used = False
        self.bootstrap_receipt = bootstrap_receipt

    def launch(self, *, activated=False, approval=None, evidence_audit=None):
        if activated is not True or os.geteuid() != 0:
            raise SessionDenied("INTEGRATED_BOOTSTRAP_DISABLED_OR_UNPRIVILEGED")
        actors, bindings, allocations = {}, {}, []
        try:
            if self.used: raise SessionDenied("INTEGRATED_BOOTSTRAP_CONSUMED")
            self.used = True
            contract = self.spawner.contract
            context = self.factory.context
            from probe_a_evidence import IndependentEvidenceAudit
            if (not isinstance(evidence_audit, IndependentEvidenceAudit) or evidence_audit.context != context
                    or evidence_audit.groups != {r:list(g.identity) for r,g in contract.scopes.groups.items()}):
                raise SessionDenied("INDEPENDENT_LIFECYCLE_EVIDENCE_AUDIT_REQUIRED")
            deadline_pair(context.end, context.cutoff, self.clock())
            if not isinstance(self.permit, AttemptPermit) or self.permit.context != context:
                raise SessionDenied("EXTERNAL_BOOTSTRAP_GATES_REQUIRED")
            if self.bootstrap_receipt is None:
                if self.permit.claim() is not True: raise SessionDenied("BOOTSTRAP_CLAIM_REQUIRED")
                self.bootstrap_receipt = self.permit._bootstrap_receipt
            if (self.permit.consume_bootstrap_receipt(self.bootstrap_receipt) is not True
                    or contract.context != context
                    or contract.verify() is not True or contract.scopes.preflight() is not True):
                raise SessionDenied("EXTERNAL_BOOTSTRAP_GATES_REQUIRED")
            contract.permit = self.permit
            coordinator = ActorReadinessCoordinator(context,
                verify_ready=lambda a, _c: contract.ready(a.role, a.binding.identity),
                verify_stopped=lambda a, _c: contract.stopped(a.role, a.binding.identity), clock=self.clock)
            for role in ("observer", "guardian", "controller"):
                # Guardian/observer readiness is observed before controller clone.
                prepared = self.factory.prepare(role, bindings, permit=self.permit, contract=contract)
                allocations.append(prepared)
                actors[role] = self.spawner.spawn(prepared.spec, deadline=context.cutoff,
                    activated=True, approval=approval, pending=prepared.pending)
                config = prepared.configuration
                if config is None: raise SessionDenied("CONFIG_NOT_SEALED_BEFORE_EXEC")
                # An exec transition can be in progress. Read ONLY actual kernel
                # identity until exact sealed expected state appears, bounded by
                # the immutable startup cutoff and an eight-second local cap.
                local_end = min(context.cutoff, self.clock()+8)
                while self.clock() < local_end:
                    if actors[role].exited(): raise SessionDenied("ACTOR_DIED_DURING_STARTUP")
                    binding = ProcessBinding(actors[role].pid)
                    if binding.identity == config.identity: break
                    binding.close()
                    time.sleep(min(0.01, max(0, local_end-self.clock())))
                else: raise SessionDenied("ACTOR_POST_EXEC_IDENTITY_DEADLINE")
                bindings[role] = binding
                # Parent endpoints were allocated before fork. They must verify
                # the actual exec identity on every IPC chunk, not SO_PEERCRED.
                channel = BoundedSocketIPC(CredentialSocket(prepared.startup, binding), clock=self.clock)
                coordinator.register(role, config, binding, channel, actors[role])
                if prepared.owner is not None:
                    prepared.owner.close() # numeric slot reuse remains uncertain
                else:
                    for _, fd in prepared.spec.inherited: os.close(fd)
                prepared.pending.reader = None
                coordinator.await_ready(role)
            coordinator.release_work(before_controller=evidence_audit.before_controller)
            supervisor = IndependentSupervisor(actors, end=context.end, cutoff=context.cutoff, clock=self.clock)
            supervisor.coordinator = coordinator
            supervisor.bindings = bindings
            supervisor.evidence_audit = evidence_audit
            return supervisor
        except BaseException:
            try:
                if isinstance(evidence_audit, IndependentEvidenceAudit):
                    evidence_audit.persist_partial()
            except BaseException:
                pass
            # Guardian retains EOF/deadline cleanup independently of this parent.
            # No interrupted privileged bootstrap returns to caller Python.
            os._exit(76)
