"""Authenticated readiness/lifecycle coordination over existing bounded IPC.

State transitions are not evidence of kernel enforcement. Independent readers
must verify identity, confinement and post-exit cleanup. No launch on import.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from probe_a_session import (ACTORS, MAX_STARTUP, ExecutionContext, SessionDenied,
                             canonical, decode, digest, identity_record)

STATES = ("NOT_STARTED", "STARTING", "IDENTITY_VERIFIED", "READY", "RUNNING",
          "CLEANUP_REQUESTED", "CLEANUP_IN_PROGRESS", "CLEANUP_INCOMPLETE",
          "UNEXPECTED_FAILURE", "STOPPED_INDEPENDENTLY_OBSERVED")
TRANSITIONS = {
    "NOT_STARTED": {"STARTING"}, "STARTING": {"IDENTITY_VERIFIED"},
    "IDENTITY_VERIFIED": {"READY"}, "READY": {"RUNNING", "CLEANUP_REQUESTED"},
    "RUNNING": {"CLEANUP_REQUESTED"}, "CLEANUP_REQUESTED": {"CLEANUP_IN_PROGRESS"},
    "CLEANUP_IN_PROGRESS": {"CLEANUP_INCOMPLETE"},
}


class CoordinationDenied(SessionDenied):
    pass


@dataclass
class ActorRegistration:
    role: str
    config: object
    binding: object
    channel: object
    handle: object
    state: str = "NOT_STARTED"
    sequence: int = 0
    control_sequence: int = 0


def readiness_message(config, state, sequence):
    return canonical({"v": 1, "context": config.context.identifier, "role": config.role,
                      "identity": digest(identity_record(config.identity)),
                      "config": digest(config.record()), "seq": sequence, "state": state})


class ActorReadinessCoordinator:
    def __init__(self, context, *, verify_ready, verify_stopped, clock=time.monotonic):
        if (not isinstance(context, ExecutionContext) or not callable(verify_ready)
                or not callable(verify_stopped)):
            raise CoordinationDenied("INDEPENDENT_COORDINATOR_BINDINGS_REQUIRED")
        self.context, self.verify_ready, self.verify_stopped = context, verify_ready, verify_stopped
        self.clock, self.actors = clock, {}
        self.aborted = False
        self.abort_reason = None

    def register(self, role, config, binding, channel, handle):
        self.context.check_time(self.clock())
        if (role not in ACTORS or role in self.actors or config.role != role
                or config.context != self.context or binding.identity != config.identity
                or handle.pid != config.identity.pid or binding.verify() is not True
                or any(a.handle.pid == handle.pid for a in self.actors.values())):
            raise CoordinationDenied("STALE_SUBSTITUTED_OR_DUPLICATE_ACTOR")
        self.actors[role] = ActorRegistration(role, config, binding, channel, handle)

    def accept(self, role, raw):
        try:
            return self._accept(role, raw)
        except BaseException:
            self.abort("READINESS_PARSE_IDENTITY_DEADLINE_OR_VERIFIER_FAILURE")
            raise

    def _accept(self, role, raw):
        if self.aborted or role not in self.actors:
            raise CoordinationDenied("UNREGISTERED_OR_ABORTED_SESSION")
        actor = self.actors[role]
        value = decode(raw, MAX_STARTUP)
        expected = {"v", "context", "role", "identity", "config", "seq", "state"}
        if (type(value) is not dict or set(value) != expected
                or type(value["v"]) is not int or value["v"] != 1
                or value["context"] != self.context.identifier or value["role"] != role
                or value["identity"] != digest(identity_record(actor.config.identity))
                or value["config"] != digest(actor.config.record())
                or type(value["seq"]) is not int or value["seq"] != actor.sequence+1
                or type(value["state"]) is not str or value["state"] not in STATES
                or actor.binding.verify() is not True):
            self.abort("FORGED_OR_REPLAYED_READINESS")
            raise CoordinationDenied("FORGED_OR_REPLAYED_READINESS")
        actor.sequence = value["seq"]  # uncertain transitions are consumed
        state = value["state"]
        self.context.check_time(self.clock(), cleanup=state.startswith("CLEANUP"))
        if state == "STOPPED_INDEPENDENTLY_OBSERVED":
            self.abort("SELF_ATTESTED_SHUTDOWN")
            raise CoordinationDenied("ACTOR_CANNOT_ATTEST_ITS_OWN_SHUTDOWN")
        if state == "UNEXPECTED_FAILURE":
            actor.state = state; self.abort("ACTOR_UNEXPECTED_FAILURE")
            return state
        if state not in TRANSITIONS.get(actor.state, set()):
            self.abort("REORDERED_LIFECYCLE")
            raise CoordinationDenied("REORDERED_LIFECYCLE")
        if state == "READY" and self.verify_ready(actor, self.context) is not True:
            self.abort("INDEPENDENT_READINESS_UNVERIFIED")
            raise CoordinationDenied("INDEPENDENT_READINESS_UNVERIFIED")
        if state == "RUNNING" and (actor.control_sequence != 1 or
                role == "controller" and not self.running_authorized):
            self.abort("WORK_BEFORE_READINESS")
            raise CoordinationDenied("WORK_BEFORE_READINESS")
        actor.state = state
        return state

    @property
    def running_authorized(self):
        return (not self.aborted and set(self.actors) == set(ACTORS)
                and all(a.state in ("READY", "RUNNING") for a in self.actors.values())
                and all(a.control_sequence == 1 for a in self.actors.values()))

    def await_ready(self, role):
        try:
            actor = self.actors[role]
            while actor.state != "READY":
                self.context.check_time(self.clock())
                if actor.handle.exited():
                    raise CoordinationDenied("ACTOR_EXIT_IS_NOT_READINESS")
                self.accept(role, actor.channel.recv_bytes(MAX_STARTUP, deadline=self.context.cutoff))
            return True
        except BaseException:
            self.abort("INTERRUPTED_BOUNDED_STARTUP")
            raise

    def release_work(self, *, before_controller=None):
        self.context.check_time(self.clock())
        if (self.aborted or set(self.actors) != set(ACTORS)
                or any(a.state != "READY" or a.control_sequence for a in self.actors.values())):
            raise CoordinationDenied("ALL_ACTORS_MUST_BE_INDEPENDENTLY_READY")
        # Check all actors again immediately before admitting controller work.
        for actor in self.actors.values():
            if actor.binding.verify() is not True or self.verify_ready(actor, self.context) is not True:
                self.abort("READINESS_DRIFT")
                raise CoordinationDenied("READINESS_DRIFT")
        try:
            # Controller is LAST; interrupted release cannot start untrusted work
            # before the independent guardian and observer have been released.
            for role in ("observer", "guardian", "controller"):
                actor = self.actors[role]
                actor.control_sequence = 1
                release={"v": 1, "context": self.context.identifier,
                    "role": role, "seq": 1, "command": "RUN",
                    "controller": identity_record(self.actors["controller"].config.identity)}
                if 'guardian-audit' in dict(self.actors['observer'].config.descriptors):
                    release['actors']={r:identity_record(a.config.identity) for r,a in self.actors.items()}
                actor.channel.send_bytes(canonical(release), deadline=self.context.cutoff)
                if before_controller is not None and role != "controller":
                    # The native integrated path starts independent services
                    # and observes RUNNING before taking the baseline barrier.
                    self.accept(role, actor.channel.recv_bytes(MAX_STARTUP, deadline=self.context.cutoff))
                    if actor.state != "RUNNING":
                        raise CoordinationDenied("SERVICE_NOT_RUNNING_BEFORE_CONTROLLER")
                if before_controller is not None and role == "guardian":
                    if before_controller(self) is not True:
                        raise CoordinationDenied("INDEPENDENT_BASELINE_BARRIER_FAILED")
        except BaseException:
            self.abort("INTERRUPTED_WORK_RELEASE")
            raise

    def abort(self, reason):
        if not self.aborted:
            self.aborted, self.abort_reason = True, reason
        # Closing bootstrap channels is bounded and independent of controller.
        # Guardian's own shared cutoff/EOF journal remains its cleanup authority.
        for actor in self.actors.values():
            try: actor.channel.close()
            except BaseException: pass

    def request_cleanup(self, reason):
        self.context.check_time(self.clock(), cleanup=True)
        self.abort(reason)
        for actor in self.actors.values():
            if actor.state not in ("UNEXPECTED_FAILURE", "STOPPED_INDEPENDENTLY_OBSERVED"):
                actor.state = "CLEANUP_REQUESTED"

    def independently_stopped(self, role):
        actor = self.actors[role]
        try:
            self.context.check_time(self.clock(), cleanup=True)
            if (actor.state not in ("CLEANUP_REQUESTED", "CLEANUP_IN_PROGRESS", "CLEANUP_INCOMPLETE",
                               "UNEXPECTED_FAILURE") or not actor.handle.exited()
                or actor.handle.reap() is None
                or self.verify_stopped(actor, self.context) is not True):
                raise CoordinationDenied("INDEPENDENT_SHUTDOWN_UNVERIFIED")
        except BaseException:
            actor.state = "CLEANUP_INCOMPLETE"
            return False
        actor.state = "STOPPED_INDEPENDENTLY_OBSERVED"
        return True


class RoleStartup:
    """Actor side; kernel identity is checked separately by the coordinator."""
    def __init__(self, config, channel, *, clock=time.monotonic):
        self.config, self.channel, self.clock = config, channel, clock
        self.sequence = 0
        self.released = False

    def announce(self, state):
        self.config.context.check_time(self.clock(), cleanup=state.startswith("CLEANUP"))
        self.sequence += 1
        self.channel.send_bytes(readiness_message(self.config, state, self.sequence),
                                deadline=self.config.context.end if state.startswith("CLEANUP")
                                else self.config.context.cutoff)

    def wait_for_release(self):
        self.config.context.check_time(self.clock())
        if self.released or self.sequence != 3:
            raise CoordinationDenied("STARTUP_REPLAY_OR_NOT_READY")
        value = decode(self.channel.recv_bytes(MAX_STARTUP, deadline=self.config.context.cutoff), MAX_STARTUP)
        from probe_a_session import identity_from
        fields={"v", "context", "role", "seq", "command", "controller"}
        if type(value) is not dict or set(value) not in (fields,fields|{'actors'}):
            raise CoordinationDenied("FORGED_WORK_RELEASE")
        self.controller = identity_from(value["controller"])
        self.controller.require_controller()
        expected={"v": 1, "context": self.config.context.identifier,
                     "role": self.config.role, "seq": 1, "command": "RUN",
                     "controller": identity_record(self.controller)}
        self.actors={}
        if 'actors' in value:
            if type(value['actors']) is not dict or set(value['actors'])!=set(ACTORS):raise CoordinationDenied('INCOMPLETE_ACTOR_RELEASE')
            self.actors={r:identity_from(i) for r,i in value['actors'].items()}
            if (self.actors[self.config.role]!=self.config.identity or self.actors['controller']!=self.controller
                    or any(self.actors[r]!=i for r,i in self.config.peers)):
                raise CoordinationDenied('ACTOR_RELEASE_SUBSTITUTION')
            expected['actors']=value['actors']
        if 'guardian-audit' in dict(self.config.descriptors) and not self.actors:
            raise CoordinationDenied('GUARDIAN_AUDIT_RELEASE_REQUIRED')
        if (value != expected
                or self.config.role == "controller" and self.controller != self.config.identity):
            raise CoordinationDenied("FORGED_WORK_RELEASE")
        self.released = True
