"""Explicit post-exec package reconstruction from an immutable runner anchor.

No CLI/env activation. The initial verifier and this loader belong to the
externally approved immutable runner, never to a package-selected import.
Package data carries public signatures only, no Python callbacks or keys.
"""
from __future__ import annotations
import fcntl, hashlib, os, stat, time
from pathlib import Path
from probe_a_session import SessionDenied, canonical, decode, SEALS
from probe_a_linux_launcher import ExecSpec, OwnedCgroup, command_catalog
from probe_a_native_assembly import NativeRoleServiceAssembly
from probe_a_native_ledger import DurableAttemptLedger, ExistingAttemptGrant
from probe_a_native_inventory import NativeAssetReader, PinnedSourceExport, NativeKernelFacts, construct_native_inventory
from probe_a_execution_contract import OwnedScopeSet, ReviewedExecutionContract
from probe_a_native_scopes import NativeScopeObserver
from probe_a_native_policy import NativePolicyAdapter, InstalledPolicyInspector
from probe_a_native_resources import NativeResourceCollector
from probe_a_role_entrypoints import TrustedRoleServiceFactory, RoleServices, run_role


class DescriptorOwner:
    """Pin each open-file description; never confuse a reused numeric slot.

    F_DUPFD_QUERY=1027 is checked in the available Linux UAPI header. A target
    without this operation is unsupported; no inode-only fallback. This is a
    new explicit target feature requirement, not approval of this cloud kernel.
    """
    def __init__(self, *, query=None):
        self.handles={};self.query=query or (lambda pin,fd:fcntl.fcntl(pin,1027,fd))
    def acquire(self,fd):
        if fd in self.handles:raise SessionDenied('DUPLICATE_DESCRIPTOR_OWNER')
        pin=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,3)
        try:
            if self.query(pin,fd)!=1:raise SessionDenied('OFD_QUERY_REQUIRED')
            self.handles[fd]=pin
        except BaseException:os.close(pin);raise
        return fd
    def release(self,fd):
        if fd not in self.handles:raise SessionDenied('UNOWNED_DESCRIPTOR_TRANSFER')
        pin=self.handles.pop(fd)
        try:
            if self.query(pin,fd)!=1:raise SessionDenied('DESCRIPTOR_SLOT_REUSED')
            return fd
        finally:os.close(pin)
    def open(self,opener,*args,**kwargs):
        """Take custody of a newly opened handle, including acquisition failure."""
        fd=opener(*args,**kwargs)
        try:return self.acquire(fd)
        except BaseException:
            os.close(fd)
            raise
    def close(self):
        handles,self.handles=self.handles,{}
        uncertain=False
        for fd,pin in handles.items():
            try:
                if self.query(pin,fd)==1:os.close(fd)
                else:uncertain=True
            except OSError:uncertain=True
            finally:os.close(pin)
        if uncertain:raise SessionDenied('DESCRIPTOR_DISPOSAL_UNCERTAIN')


def read_package(fd):
    if type(fd) is not int or fd<3:raise SessionDenied('INVALID_PACKAGE_DESCRIPTOR')
    st=os.fstat(fd)
    if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022
        or not 0<st.st_size<=300000 or fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY
        or fcntl.fcntl(fd,fcntl.F_GET_SEALS)&SEALS!=SEALS):
        raise SessionDenied('SEALED_READONLY_ROOT_PACKAGE_REQUIRED')
    raw=os.pread(fd,300001,0)
    if os.fstat(fd)!=st or len(raw)!=st.st_size:raise SessionDenied('PACKAGE_DESCRIPTOR_DRIFT')
    return decode(raw,300000)


class NativePackageLoader(TrustedRoleServiceFactory):
    """No privileged callback is selected by serialized package data.

    The anchor verifier/reader/boot collector are installed by the immutable
    runner. Their own source/interpreter/library/mount identity must be pinned
    BEFORE invoking this code. That initial trust is not self-authentication.
    Root roles reconstruct an already committed grant; never claim it again.
    """
    def __init__(self, package, signature, *, verifier, reader, facts, guard,
                 immutable_runner_source, activated=False):
        self.raw=canonical(package);self.package=decode(self.raw,300000)
        self.signature,self.verifier,self.reader,self.facts=signature,verifier,reader,facts
        self.guard,self.anchor=guard,dict(immutable_runner_source)
        self.activated=activated is True;self.owned=DescriptorOwner();self.ledger=None
        super().__init__(self._build)

    def _authenticate(self,configuration):
        from probe_a_native_verifier import OpenSSLEd25519
        from probe_a_native_deadline import NativeDeadlineGuard
        from probe_a_attestation import SOURCE_NAMES
        if (not self.activated or not isinstance(self.verifier,OpenSSLEd25519)
            or not isinstance(self.reader,NativeAssetReader) or self.reader.synthetic
            or not isinstance(self.facts,NativeKernelFacts) or not isinstance(self.guard,NativeDeadlineGuard)):
            raise SessionDenied('IMMUTABLE_RUNNER_ANCHOR_AND_NATIVE_GUARD_REQUIRED')
        p=self.package;c=configuration.context
        fields={'v','context','source','inventory','inventory_signature','source_export','source_signature',
                'policy','policy_signature','policy_identity','profiles','mount','backend','groups','parents',
                'grant','grant_signature','activation_signature','ledger','installed_policy'}
        if (canonical(p)!=self.raw or set(p)!=fields or p['v']!=1 or p['context']!=c.identifier
            or p['source']!=c.source_commit or self.verifier(b'ProbeA native package v1\0'+self.raw,self.signature) is not True):
            raise SessionDenied('PACKAGE_SIGNATURE_CONTEXT_OR_SCHEMA')
        root=Path(__file__).resolve().parent
        if set(self.anchor)!=set(SOURCE_NAMES):raise SessionDenied('INITIAL_RUNNER_SOURCE_CLOSURE_INCOMPLETE')
        for name,expected in self.anchor.items():
            raw=self.reader.read_asset(str(root/name))
            if hashlib.sha256(raw).hexdigest()!=expected:raise SessionDenied('INITIAL_RUNNER_SOURCE_DRIFT')
        return p

    def _build(self,configuration):
        from probe_a_native_deadline import NativeDeadlineGuard
        if type(self.guard) is not NativeDeadlineGuard or self.guard.context!=configuration.context:
            raise SessionDenied('EXACT_NATIVE_GUARD_CONTEXT_REQUIRED')
        end=min(configuration.context.cutoff,time.monotonic()+8)
        return self.guard.call(self._construct,configuration,deadline=end)

    def _construct(self,configuration):
        p=self._authenticate(configuration);c=configuration.context
        if configuration.role=='controller':
            # The sealed root coordinator owns ledger/policy observations.
            # Controller cannot inspect privileged metadata or root storage.
            configuration.identity.require_controller()
            return RoleServices(contract=None)
        if os.geteuid()!=0:raise SessionDenied('ROOT_SERVICES_REQUIRE_ROOT_ACTOR')
        def sig(key):
            value=p[key]
            if type(value) is not str or len(value)!=128:raise SessionDenied('PUBLIC_SIGNATURE_BOUNDS')
            return bytes.fromhex(value)
        try:
            export=PinnedSourceExport(p['source_export'],sig('source_signature'),verifier=self.verifier,reader=self.reader)
            inventory=construct_native_inventory(p['inventory'],sig('inventory_signature'),verifier=self.verifier,
                reader=self.reader,source_export=export,kernel_facts=self.facts)
            inventory.verify_integration(c)
            self.ledger=DurableAttemptLedger(p['ledger'])
            grant=ExistingAttemptGrant(c,p['grant'],sig('grant_signature'),verify=self.verifier,
                ledger=self.ledger,boot_identity=self.facts.boot_identity,policy_digest=p['policy']['policy_digest'])
            if grant.active() is not True:raise SessionDenied('EXISTING_COMMITTED_GRANT_REQUIRED')
            if set(p['groups'])!=set(p['policy']['roles']):raise SessionDenied('PACKAGE_SCOPE_SET_MISMATCH')
            groups={}
            for role,record in p['groups'].items():
                if record['path']!='/sys/fs/cgroup/p2a-'+c.plan.scope+'/'+role:
                    raise SessionDenied('PACKAGE_SCOPE_PATH_SUBSTITUTION')
                fd=self.owned.open(os.open,record['path'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                groups[role]=OwnedCgroup(fd,tuple(record['identity']));groups[role].verify()
            observation=NativeScopeObserver(c,groups,parent_identities=p['parents'])
            scopes=OwnedScopeSet(c,groups,observe=observation)
            installed=InstalledPolicyInspector(p['installed_policy'],reader=self.reader,
                profiles=p['profiles'],source_mount=p['mount'])
            adapter=NativePolicyAdapter(c,profiles=p['profiles'],source_mount=p['mount'],backend=p['backend'],
                policy_identity=p['policy_identity'],verify_policy_package=installed,grant=grant,activated=True)
            contract=ReviewedExecutionContract(c,inventory,scopes,p['policy'],sig('policy_signature'),
                verify_policy=self.verifier,enforce_child=adapter.enforce_child,inspect_actor=adapter.inspect_actor)
            contract.permit=grant;contract.verify()
            specs={'read-command':{},'guardian-command':{},'workload':{}}
            for role in ('read-command','guardian-command','worker','peer'):
                vectors=inventory.base.document['exec'][role]
                for vector in vectors:
                    argv=tuple(vector)
                    if role.endswith('command') and argv not in command_catalog(c.plan,role):
                        raise SessionDenied('PACKAGE_COMMAND_CATALOG_WIDENED')
                    path=p['inventory']['aliases'].get(argv[0],{}).get('target',argv[0])
                    fd=self.owned.open(self.reader.open_verified_fd,path)
                    spec=ExecSpec(role,fd,argv,groups[role]);spec.validate()
                    specs[role if role.endswith('command') else 'workload'][argv]=spec
            resources=NativeResourceCollector(c,scopes,self.reader,activated=True)
            result=NativeRoleServiceAssembly(contract=contract,specs=specs,grant=grant,resources=resources,
                guard=self.guard,activation_signature=sig('activation_signature'),activated=True).create(configuration)
            result.package_owner=self
            return result
        except BaseException:
            self.close();raise

    def close(self):
        try:self.owned.close()
        finally:
            ledger,self.ledger=self.ledger,None
            if ledger is not None:ledger.close()


def run_native_role(role, *, config_fd=None, loader=None, guard=None, activated=False):
    """Externally pinned entry interface; never enabled by CLI/env/defaults."""
    if activated is not True:raise SessionDenied('NATIVE_ENTRY_DISABLED')
    root=os.geteuid()==0
    try:
        from probe_a_native_deadline import NativeDeadlineGuard
        if (type(loader) is not NativePackageLoader or type(guard) is not NativeDeadlineGuard
                or guard is not loader.guard):
            raise SessionDenied('IMMUTABLE_ENTRY_ANCHOR_REQUIRED')
        return guard.call(run_role,role,config_fd=config_fd,services_factory=loader,
                          activated=True,deadline=guard.context.end)
    except BaseException:
        if root:os._exit(76)
        raise
