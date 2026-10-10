"""Explicit sealed guardian/observer/controller startup; NO CLI entrypoint.

No environment variable or import starts a role. Separately reviewed bootstrap
code supplies services and activation. Root startup failures terminate the
process irreversibly; guardian cleanup stays outside controller lifetime.
"""
from __future__ import annotations

import os
import select
import socket
import time
from probe_a_session import (ACTORS, SessionDenied, load_sealed, DelegatedProcessBinding)
from probe_a_linux_identity import ProcessBinding, CredentialSocket
from probe_a_ipc import BoundedSocketIPC
from probe_a_coordinator import RoleStartup
from probe_a_privilege import verify_unprivileged


def authenticated_channel(fd, peer, clock):
    stream = socket.socket(fileno=fd)
    try:
        if stream.family != socket.AF_UNIX or stream.type & 15 != socket.SOCK_STREAM:
            raise SessionDenied("UNEXPECTED_STARTUP_SOCKET")
        return BoundedSocketIPC(CredentialSocket(stream, peer), clock=clock)
    except BaseException:
        stream.close()
        raise


class RoleServices:
    """Trusted source-side composition of EXISTING guardian and read broker.

    All root command paths must use NativeBoundedCapture with the same signed
    contract. The reviewed factory supplies workload/resource interfaces; their
    review and actual OS enforcement remain external acceptance prerequisites.
    This object can never be supplied over actor IPC or sealed JSON.
    """
    def __init__(self, *, contract, guardian_core=None, observer_broker=None, controller_io=None):
        self.contract = contract
        self.guardian_core, self.observer_broker, self.controller_io = guardian_core, observer_broker, controller_io

    def prepare(self, config):
        if config.role == "controller":
            if self.controller_io is not None:
                raise SessionDenied("NO_CONTROLLER_IO_SUBSTITUTION")
            return True  # readiness belongs to the independently trusted parent
        from probe_a_execution_contract import ReviewedExecutionContract
        if (not isinstance(self.contract, ReviewedExecutionContract)
                or self.contract.context != config.context or self.contract.verify() is not True):
            raise SessionDenied("ROLE_SERVICES_REQUIRE_REVIEWED_CONTEXT")
        if config.role == "guardian":
            from probe_a_guardian import GuardianCore
            from probe_a_linux_launcher import NativeBoundedCapture
            command = getattr(self.guardian_core, "command", None)
            from probe_a_workload import FixedWorkload
            from probe_a_client_process import ClientProcess
            from probe_a_containment import CgroupV2Containment
            from probe_a_linux_containment import NativeContainmentAdapter
            work = getattr(self.guardian_core, "work", None)
            client = getattr(work, "invoke", None)
            if (not isinstance(self.guardian_core, GuardianCore) or self.guardian_core.plan != config.context.plan
                    or not isinstance(command, ContainedRootCommands)
                    or not isinstance(command.capture, NativeBoundedCapture)
                    or command.capture.spawner.contract is not self.contract
                    or any(s.role != "guardian-command" for s in command.capture.specs.values())
                    or not isinstance(work, FixedWorkload) or not isinstance(client, ClientProcess)
                    or not isinstance(client.containment, CgroupV2Containment)
                    or not isinstance(client.containment.agent, NativeContainmentAdapter)
                    or client.containment.agent.spawner.contract is not self.contract
                    or client.stream != client.containment.capture
                    or client.check_uid != self.contract.worker_identity
                    or client.check_listener != self.contract.worker_listener):
                raise SessionDenied("GUARDIAN_CONTAINED_COMMAND_SERVICES_REQUIRED")
        if config.role == "observer":
            from probe_a_readonly_broker import ReadOnlyBroker, NativeReadCommands, catalog
            broker = self.observer_broker
            if (not isinstance(broker, ReadOnlyBroker) or not isinstance(broker.command, NativeReadCommands)
                    or broker.command.capture.spawner.contract is not self.contract
                    or broker.identity != config.identity or broker.inventory_id != config.context.inventory
                    or broker.end != config.context.end or broker.commands != catalog(config.context.plan)):
                raise SessionDenied("INDEPENDENT_OBSERVER_SERVICES_REQUIRED")
        return True

    def run(self, config, startup, channels, clock):
        if config.role == "guardian":
            from probe_a_guardian import GuardianChannel, installed_signal_abort
            # Kernel-verified post-drop controller identity, delivered solely
            # over the authenticated bootstrap release channel.
            peer = ProcessBinding(startup.controller.pid)
            try:
                if peer.identity != startup.controller or peer.verify() is not True:
                    raise SessionDenied("CONTROLLER_INCARNATION_SUBSTITUTION")
                controller = authenticated_channel(channels["controller"], peer, clock)
                installed_signal_abort(lambda: self.guardian_core.cleanup(config.context.end))
                startup.announce('RUNNING')
                return GuardianChannel(self.guardian_core, clock=clock).serve(controller,
                    end=config.context.end, cleanup_cutoff=config.context.cutoff)
            finally:
                peer.close()
        if config.role == "observer":
            return self._observe(config, startup, channels, clock)
        # The caller verifies all UID/GID/capability/NNP fields before this
        # import; untrusted controller code never executes in a root actor.
        from probe_a_guardian import RemoteIO
        from probe_a_controller import control
        peers = dict(config.peers)
        bindings = []
        try:
            for role in ("guardian", "observer"):
                peer = DelegatedProcessBinding(peers[role], channels[role + "-pidfd"], sealed=config, role=role)
                bindings.append(peer)
                channels[role] = authenticated_channel(channels[role], peer, clock)
            if self.controller_io is not None:
                raise SessionDenied("NO_CONTROLLER_IO_SUBSTITUTION")
            # Existing RemoteIO preserves guardian journals. Independent broker
            # remains available separately; its reports cannot promote PASS.
            from probe_a_readonly_broker import BrokerClient
            remote = RemoteIO(channels["guardian"], config.context.plan, clock=clock)
            broker = BrokerClient(config.context.plan, channel=channels["observer"],
                observer_identity=peers["observer"], inventory_id=config.context.inventory)
            io = IndependentControllerIO(remote, broker, config.context, clock=clock)
            startup.announce('RUNNING')
            return control(config.context.plan, io, clock, absolute_deadline=config.context.end,
                           cleanup_cutoff=config.context.cutoff)
        finally:
            for peer in bindings: peer.close()

    def _observe(self, config, startup, descriptors, clock):
        from probe_a_readonly_broker import ReadOnlyBroker, MAX_FRAME, MAX_REQUEST
        identities = {"controller": startup.controller, "audit": config.bootstrap}
        if 'guardian-audit' in descriptors:
            identities['guardian-audit']=startup.actors['guardian']
        from probe_a_ipc import IncrementalRequest
        owned, channels, brokers, frames = [], {}, {}, {}
        try:
            for name, expected in identities.items():
                peer = ProcessBinding(expected.pid); owned.append(peer)
                if peer.identity != expected or peer.verify() is not True:
                    raise SessionDenied("OBSERVER_CALLER_IDENTITY_MISMATCH")
                channels[name] = authenticated_channel(descriptors[name], peer, clock)
                b = self.observer_broker
                command = b.command.for_audit(config, peer) if name == "audit" else b.command
                frames[name] = IncrementalRequest(channels[name],
                    end=config.context.end if name != "controller" else config.context.cutoff)
                brokers[name] = ReadOnlyBroker(config.context.plan, command=command,
                    read_resource=b.read_resource, observer_identity=config.identity,
                    expected_peer=expected, inventory_id=config.context.inventory,
                    end=config.context.end if name != "controller" else config.context.cutoff, clock=clock,
                    purpose='supervisor-audit' if name=='audit' else 'guardian-uid-audit' if name=='guardian-audit' else 'controller')
            startup.announce('RUNNING')
            while channels and clock() < config.context.end:
                readable, _, _ = select.select([c.stream for c in channels.values()], [], [],
                                              min(0.05, config.context.end-clock()))
                for name in ("audit", "guardian-audit", "controller"):
                    if name not in channels: continue
                    channel = channels[name]
                    if name == "controller" and clock() >= config.context.cutoff:
                        channel.close(); del channels[name]; continue
                    try:
                        request = frames[name].receive_available()
                        if request is None: continue
                        # Controller responses cannot occupy the audit reserve.
                        bound = 8 if name == "audit" else 0.05
                        channel.send_bytes(brokers[name].handle(request),
                            deadline=min(brokers[name].end, clock()+bound))
                    except BaseException:
                        channel.close(); del channels[name]
                        if name == "audit": raise  # no independent audit authority
            return "UNVERIFIED_OBSERVER_STOP_NOT_PROBE_PASS"
        finally:
            for channel in channels.values(): channel.close()
            for peer in owned: peer.close()


class ContainedRootCommands:
    def __init__(self, capture, *, clock=time.monotonic):
        self.capture, self.clock = capture, clock

    def __call__(self, argv, deadline):
        from probe_a_linux_launcher import NativeBoundedCapture
        if (not isinstance(self.capture, NativeBoundedCapture) or argv not in self.capture.specs
                or self.capture.specs[argv].role != "guardian-command"):
            raise SessionDenied("ROOT_EXECUTION_OUTSIDE_REVIEWED_CONTAINMENT")
        remaining = min(8, deadline-self.clock())
        if remaining <= 0:
            raise SessionDenied("ROOT_COMMAND_DEADLINE")
        if self.capture.spawner.inventory.verify() is not True:
            raise SessionDenied("ROOT_COMMAND_DEPENDENCY_DRIFT")
        result = self.capture(argv, remaining)
        if self.capture.spawner.inventory.verify() is not True:
            raise SessionDenied("ROOT_COMMAND_DEPENDENCY_DRIFT")
        return result


class IndependentControllerIO:
    """Guardian mutates; the separately bound broker supplies read observations."""
    def __init__(self, guardian, broker, context, *, clock=time.monotonic):
        from probe_a_observer import KernelReadback
        self.guardian, self.broker, self.context, self.clock = guardian, broker, context, clock
        self.readback = KernelReadback(context.plan, read=broker.read, clock=clock)

    def _deadline(self, cleanup=False):
        return min(self.context.end if cleanup else self.context.cutoff, self.clock()+8)

    def preflight(self, plan):
        return (plan == self.context.plan and self.guardian.preflight(plan) is True
                and self.readback.preflight(self._deadline()) is True)
    def snapshot(self): return self.readback.snapshot(self._deadline())
    def counters(self, family): return self.readback.counters(family, self._deadline())
    def issue(self, command, deadline): return self.guardian.issue(command, min(deadline, self.context.cutoff))
    def exercise(self, case, deadline): return self.guardian.exercise(case, min(deadline, self.context.cutoff))
    def stop(self, deadline): return self.guardian.stop(min(deadline, self.context.end))
    def cleanup(self, plan, attempted, deadline): return self.guardian.cleanup(plan, attempted, min(deadline, self.context.end))
    def cleanup_readback(self, key, baseline, deadline):
        # Post-guardian reaping and observer shutdown remain supervisor duties.
        return self.broker.readback(key, min(deadline, self._deadline(cleanup=True)))


class TrustedRoleServiceFactory:
    """Explicit trusted source factory invoked only AFTER inherited-FD audit.

    Its implementation must be pinned in the signed source closure. The
    reviewed entry script supplies it; serialized configuration and IPC cannot
    contain Python callables. Root executable/cgroup fds are opened by this
    reviewed factory after exec, never inherited from the bootstrap.
    """
    def __init__(self, build):
        self.build = build

    def create(self, configuration):
        services = self.build(configuration)
        if not isinstance(services, RoleServices):
            raise SessionDenied("UNREVIEWED_ROLE_SERVICE_FACTORY_OUTPUT")
        return services


def run_role(role, *, config_fd=None, services=None, services_factory=None, activated=False, clock=time.monotonic):
    if activated is not True or role not in ACTORS:
        raise SessionDenied("SEALED_ROLE_ENTRYPOINT_DISABLED")
    owned = startup = None
    root = os.geteuid() == 0
    try:
        config = load_sealed(config_fd)
        if (config.role != role or services is not None and not isinstance(services, RoleServices)
                or services is None and not isinstance(services_factory, TrustedRoleServiceFactory)
                or services is not None and services_factory is not None):
            raise SessionDenied("WRONG_ROLE_OR_SERVICES")
        config.context.check_time(clock())
        if config.context.end > clock()+240:
            raise SessionDenied("UNBOUNDED_ACTOR_LIFETIME")
        if role == "controller" and (root or verify_unprivileged() is not True):
            raise SessionDenied("CONTROLLER_PRIVILEGE_DROP_NOT_COMPLETE")
        owned = ProcessBinding(os.getpid())
        if owned.identity != config.identity or owned.verify() is not True:
            raise SessionDenied("ACTUAL_EXECUTABLE_OR_PROCESS_IDENTITY_MISMATCH")
        descriptors = dict(config.descriptors)
        expected_fds = {0, 1, 2, config_fd, owned.procfd, owned.pidfd, *descriptors.values()}
        # Listing /proc/self/fd also opens one transient directory descriptor;
        # verify every remaining entry still exists before rejecting it.
        for entry in os.listdir("/proc/self/fd"):
            fd = int(entry)
            if fd not in expected_fds:
                try: os.fstat(fd)
                except OSError: continue
                raise SessionDenied("UNAPPROVED_INHERITED_DESCRIPTOR")
        if services is None:
            services = services_factory.create(config)
        if role == "controller":
            peer = DelegatedProcessBinding(config.bootstrap, descriptors["startup-pidfd"], sealed=config, role="startup")
        else:
            peer = ProcessBinding(config.bootstrap.pid)
            if peer.identity != config.bootstrap: raise SessionDenied("BOOTSTRAP_INCARNATION_CHANGED")
        startup = RoleStartup(config, authenticated_channel(descriptors["startup"], peer, clock), clock=clock)
        startup.announce("STARTING")
        startup.announce("IDENTITY_VERIFIED")
        services.prepare(config)
        startup.announce("READY")
        startup.wait_for_release()
        result = services.run(config, startup, descriptors, clock)
        if root:
            from probe_a_guardian import LIFECYCLE_COMPLETE
            os._exit(0 if role == "observer" or result == LIFECYCLE_COMPLETE else 10)
        return result
    except BaseException:
        # Cleanup before fail-stop is guardian-owned and deadline bounded. It
        # can fail; failure never grants success or returns privileged Python.
        if role == "guardian" and isinstance(services, RoleServices) and startup is not None:
            try: services.guardian_core.cleanup(startup.config.context.end)
            except BaseException: pass
        if root: os._exit(78)
        raise
    finally:
        if owned is not None: owned.close()
        if startup is not None: startup.channel.close()


def guardian_entrypoint(**kwargs): return run_role("guardian", **kwargs)
def observer_entrypoint(**kwargs): return run_role("observer", **kwargs)
def controller_entrypoint(**kwargs): return run_role("controller", **kwargs)
