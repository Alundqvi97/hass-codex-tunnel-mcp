"""Disabled concrete allocation and existing GuardianCore service composition.

No controller import, role execution, socket creation or allocation on import.
The guardian->observer audit handoff is sealed and server-purpose scoped.
Package-descriptor/entry wiring remains incomplete; nothing runs on import.
"""
from __future__ import annotations

from dataclasses import replace
import os
import errno
import fcntl
import socket
import time
from probe_a_session import SessionDenied, PendingRoleConfiguration, RoleConfiguration
from probe_a_integrated_bootstrap import ActorPreparation, ReviewedActorFactory
from probe_a_native_ledger import NativeAttemptPermit, ExistingAttemptGrant
from probe_a_native_inventory import NativeAssetReader
from probe_a_linux_launcher import ExecSpec, NativeAtomicSpawner, NativeBoundedCapture, command_catalog
from probe_a_role_entrypoints import RoleServices, ContainedRootCommands, TrustedRoleServiceFactory


class NativeActorAllocator:
    """One owned private descriptor topology; fd exec and sealed incarnation.

    Channel pairs are allocated only inside the activated root fail-stop
    boundary after durable claim. No numerical descriptor is supplied by a
    controller. Signed actor vectors must include the exact configuration FD.
    The allocator derives final identity from kernel incarnation plus approved
    policy and retained executable identity; startup verifies it after exec.
    """
    def __init__(self, context, bootstrap, inventory, reader):
        if not isinstance(reader,NativeAssetReader) or reader.synthetic:
            raise SessionDenied("NATIVE_FACTORY_REQUIRES_PROTECTED_SOURCE_ASSETS")
        self.context, self.bootstrap, self.inventory, self.reader = context,bootstrap,inventory,reader
        self.pairs, self.used = None,set()

    def _pairs(self):
        created = {}
        try:
            for name in ('observer-startup','guardian-startup','controller-startup','guardian-controller','observer-controller','observer-audit','guardian-audit'):
                left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM|socket.SOCK_CLOEXEC)
                created[name]=(left,right)
            self.pairs=created
        except BaseException:
            for pair in created.values():
                for stream in pair:stream.close()
            raise

    def __call__(self, role, bindings, permit, contract):
        if (os.geteuid()!=0 or not isinstance(permit,NativeAttemptPermit) or not permit.active()
                or permit.context != self.context or contract.inventory is not self.inventory
                or role in self.used or role not in ('guardian','observer','controller')):
            raise SessionDenied("NATIVE_ALLOCATION_DISABLED_OR_REPLAYED")
        self.used.add(role)
        self.inventory.verify_integration(self.context)
        if self.pairs is None:self._pairs()
        from probe_a_native_package import DescriptorOwner
        owner=DescriptorOwner()
        descriptors={}
        extras=[];pending=None;executable=None
        try:
            descriptors['startup']=owner.open(self.pairs[role+'-startup'][1].detach)
            if role=='controller':
                for peer in ('guardian','observer'):
                    if peer not in bindings or bindings[peer].verify() is not True:
                        raise SessionDenied("PRIVILEGED_PEERS_NOT_READY_FOR_PIDFD_HANDOFF")
                    descriptors[peer]=owner.open(self.pairs[peer+'-controller'][1].detach)
                    descriptors[peer+'-pidfd']=owner.open(os.dup,bindings[peer].pidfd)
                descriptors['startup-pidfd']=owner.open(os.pidfd_open,self.bootstrap.pid,0)
            else:
                descriptors['controller']=owner.open(self.pairs[role+'-controller'][0].detach)
                if role=='observer':descriptors['audit']=owner.open(self.pairs['observer-audit'][1].detach)
                descriptors['guardian-audit' if role=='observer' else 'observer-audit']=owner.open(self.pairs['guardian-audit'][0 if role=='observer' else 1].detach)
            rule=contract.policy['roles'][role]
            vectors=self.inventory.base.document['exec'][role]
            if (len(vectors)!=1 or vectors[0][-2]!='--sealed-config-fd'
                    or not vectors[0][-1].isdecimal() or not 3<=int(vectors[0][-1])<1048576):
                raise SessionDenied("FIXED_REVIEWED_CONFIGURATION_DESCRIPTOR_SLOT_REQUIRED")
            config_slot=int(vectors[0][-1])
            # Native inventory reader resolves only externally pinned aliases.
            executable_path=vectors[0][0]
            alias=self.inventory.document['aliases'].get(executable_path)
            target=alias['target'] if alias else executable_path
            executable=owner.open(self.reader.open_verified_fd,target)
            st=os.fstat(executable)
            def build(kernel):
                expected=replace(kernel,uids=tuple(rule['uids']),gids=tuple(rule['gids']),groups=(),
                    capabilities=tuple(rule['caps']),no_new_privs=1,executable=(st.st_dev,st.st_ino))
                return RoleConfiguration(self.context,role,expected,self.bootstrap,tuple(descriptors.items()),
                    tuple((peer,bindings[peer].identity) for peer in ('guardian','observer')) if role=='controller'
                    else (('observer',bindings['observer'].identity),) if role=='guardian' else ())
            pending=PendingRoleConfiguration.allocate(build=build,permit=permit,activated=True)
            owner.acquire(pending.reader)
            # Move into a reviewed descriptor slot WITHOUT overwriting any
            # existing descriptor. F_DUPFD_CLOEXEC must return the exact slot.
            if pending.reader!=config_slot:
                try:os.fstat(config_slot)
                except OSError as error:
                    if error.errno!=errno.EBADF:raise
                else:raise SessionDenied("REVIEWED_DESCRIPTOR_SLOT_ALREADY_OWNED")
                moved=fcntl.fcntl(pending.reader,fcntl.F_DUPFD_CLOEXEC,config_slot)
                if moved!=config_slot:
                    os.close(moved);raise SessionDenied("CONFIGURATION_SLOT_ALLOCATION_UNCERTAIN")
                os.close(owner.release(pending.reader));pending.reader=None
                pending.reader=owner.open(lambda:moved)
            argv=tuple(vectors[0])
            inherited=(('config',pending.reader),)+tuple(
                ('pidfd' if name.endswith('-pidfd') else 'ipc',fd) for name,fd in descriptors.items())
            return ActorPreparation(ExecSpec(role,executable,argv,contract.scopes.groups[role],inherited),
                pending,self.pairs[role+'-startup'][0],owner=owner)
        except BaseException:
            try:
                if pending is not None:
                    if pending.reader in owner.handles:pending.reader=None
                    pending.close()
            finally:owner.close()
            raise

    def factory(self):
        return ReviewedActorFactory(self.context,self.bootstrap,allocate=self)


class NativeRoleServiceAssembly(TrustedRoleServiceFactory):
    """Actual GuardianCore -> FixedWorkload -> ClientProcess -> atomic adapter.

    The native post-exec package loader must authenticate this assembly before
    constructing it. independent_uid_client must be an observer BrokerClient,
    never a guardian-local callable or caller-supplied boolean. The existing
    configuration now hands the independently authenticated channel to guardian.
    Post-exec package/entry and complete native policy remain blockers.
    """
    def __init__(self, *, contract, specs, grant, resources, independent_uid_client=None, guard=None, activation_signature=None, activated=False):
        self.contract,self.specs,self.grant,self.resources=contract,dict(specs),grant,resources
        self.uid_client,self.activated=independent_uid_client,activated is True
        self.activation_signature=activation_signature
        self.guard=guard
        super().__init__(self._build)

    def _build(self, configuration):
        if configuration.role=='controller':return RoleServices(contract=None)
        if (not self.activated or not isinstance(self.grant,ExistingAttemptGrant) or not self.grant.active()
                or configuration.context!=self.contract.context or type(self.activation_signature) is not bytes):
            raise SessionDenied("EXTERNALLY_VERIFIED_EXISTING_GRANT_REQUIRED_AFTER_EXEC")
        self.contract.permit=self.grant
        spawner=NativeAtomicSpawner(inventory=self.contract.inventory,contract=self.contract,guard=self.guard)
        if configuration.role=='observer':
            from probe_a_readonly_broker import NativeReadCommands,ReadOnlyBroker
            capture=NativeBoundedCapture(self.specs['read-command'],spawner=spawner,
                plan=configuration.context.plan,activated=True,approval=self.activation_signature)
            command=NativeReadCommands(configuration.context.plan,capture=capture,inventory=self.contract.inventory)
            broker=ReadOnlyBroker(configuration.context.plan,command=command,read_resource=self.resources.readback,
                observer_identity=configuration.identity,inventory_id=configuration.context.inventory,end=configuration.context.end)
            return RoleServices(contract=self.contract,observer_broker=broker)
        from probe_a_readonly_broker import BrokerClient
        if self.uid_client is None:
            from probe_a_linux_identity import ProcessBinding
            from probe_a_role_entrypoints import authenticated_channel
            expected=dict(configuration.peers).get('observer')
            if expected is None or 'observer-audit' not in dict(configuration.descriptors):
                raise SessionDenied('INDEPENDENT_OBSERVER_HANDOFF_REQUIRED')
            peer=ProcessBinding(expected.pid)
            try:
                if peer.identity!=expected or peer.verify() is not True:raise SessionDenied('OBSERVER_IDENTITY_SUBSTITUTION')
                channel=authenticated_channel(dict(configuration.descriptors)['observer-audit'],peer,time.monotonic)
                self.uid_client=BrokerClient(configuration.context.plan,channel=channel,
                    observer_identity=expected,inventory_id=configuration.context.inventory)
            except BaseException:peer.close();raise
        if not isinstance(self.uid_client,BrokerClient):raise SessionDenied('INDEPENDENT_OBSERVER_CLIENT_REQUIRED')
        from probe_a_guardian import GuardianCore
        from probe_a_linux_containment import NativeContainmentAdapter
        from probe_a_containment import CgroupV2Containment
        from probe_a_client_process import ClientProcess
        from probe_a_workload import FixedWorkload
        def uid_absent(uid,deadline):
            return uid==configuration.context.plan.uid and self.uid_client.readback('numeric_uid_process_absent',deadline) is True
        agent=NativeContainmentAdapter(configuration.context.plan,self.specs['workload'],spawner=spawner,
            independent_uid_absent=uid_absent,activated=True,approval=self.activation_signature)
        containment=CgroupV2Containment(configuration.context.plan,agent=agent);containment.arm()
        client=ClientProcess(configuration.context.plan,stream=containment.capture,containment=containment,
            check_uid=self.contract.worker_identity,check_listener=self.contract.worker_listener)
        work=FixedWorkload(configuration.context.plan,invoke=client,stop=client.stop)
        capture=NativeBoundedCapture(self.specs['guardian-command'],spawner=spawner,
            plan=configuration.context.plan,activated=True,approval=self.activation_signature)
        core=GuardianCore(configuration.context.plan,command=ContainedRootCommands(capture),work=work,resources=self.resources)
        return RoleServices(contract=self.contract,guardian_core=core)
