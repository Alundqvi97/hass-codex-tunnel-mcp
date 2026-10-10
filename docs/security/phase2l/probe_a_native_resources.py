"""Independent fixed-path bounded resource observations, inactive by default.

Only an approved observer/supervising owner can enable native reads. No procfs
reads, command, process, socket or filesystem mutation occurs at import.
"""
from __future__ import annotations
import os
import stat
import time
from probe_a_session import SessionDenied
from probe_a_linux_identity import ProcessBinding, read_at
from probe_a_resources import _listeners
from probe_contract import CLEANUP_READBACKS


class NativeResourceCollector:
    def __init__(self, context, scopes, asset_reader, *, activated=False, clock=time.monotonic):
        self.context,self.scopes,self.assets=context,scopes,asset_reader
        self.activated,self.clock=activated is True,clock
        self.resolver_before=None

    def _gate(self, deadline):
        if (not self.activated or os.geteuid()!=0 or not self.clock()<deadline<=self.context.end
                or deadline-self.clock()>8):
            raise SessionDenied('NATIVE_RESOURCE_OBSERVATION_DISABLED_OR_EXPIRED')

    def _net_text(self, path, deadline):
        self._gate(deadline)
        if path not in ('/proc/net/tcp','/proc/net/tcp6'):
            raise SessionDenied('UNAPPROVED_PROC_NETWORK_RESOURCE')
        # /proc/net is an intentional kernel alias to /proc/self/net. Retain
        # actual self procdir via ProcessBinding rather than follow that alias.
        binding=ProcessBinding(os.getpid());fd=None
        try:
            fd=os.open('net',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=binding.procfd)
            raw=read_at(fd,path.rsplit('/',1)[1],131072)
            self._gate(deadline)
            return raw.decode('ascii')
        finally:
            if fd is not None:os.close(fd)
            binding.close()

    def numeric_uid_absence(self, deadline):
        self._gate(deadline)
        observed=[]
        # Bounded enumeration. Missing/inaccessible/racing entries mean
        # uncertainty, never 'absent'. Caller may collect a later new snapshot.
        root=os.open('/proc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            names=[n for n in os.listdir(root) if n.isdecimal()]
            if len(names)>32768:raise SessionDenied('PROC_ENUMERATION_CAPACITY_EXCEEDED')
            for name in names:
                self._gate(deadline)
                binding=ProcessBinding(int(name))
                try:
                    identity=binding.identity
                    if self.context.plan.uid in identity.uids:
                        observed.append([identity.pid,identity.starttime])
                    if binding.verify() is not True:raise SessionDenied('PROC_ENUMERATION_INCARNATION_CHANGED')
                finally:binding.close()
            self._gate(deadline)
            return {'uid':self.context.plan.uid,'matches':observed,'enumerated':len(names),
                    'interval_end':self.clock(),'context':self.context.identifier}
        finally:os.close(root)

    def listener_observation(self, deadline):
        rows=_listeners(19468,read_text=lambda p:self._net_text(p,deadline))
        return {'port':19468,'listeners':[list(row) for row in rows],
                'context':self.context.identifier,'interval_end':self.clock()}

    def preflight(self):
        end=min(self.context.cutoff,self.clock()+8)
        self._gate(end)
        if self.listener_observation(end)['listeners']:
            raise SessionDenied('PREEXISTING_PROBE_LISTENER')
        # Immutable reviewed resolver identity includes approved alias/target.
        alias=self.assets.aliases.get('/etc/resolv.conf')
        target=alias['target'] if alias else '/etc/resolv.conf'
        if alias:self.assets.read_alias('/etc/resolv.conf')
        self.resolver_before=self.assets.inspect_asset(target),self.assets.read_asset(target)
        return True

    def readback(self, key, deadline):
        self._gate(deadline)
        if key not in CLEANUP_READBACKS:raise SessionDenied('UNKNOWN_NATIVE_RESOURCE_KEY')
        if key=='numeric_uid_process_absent':return not self.numeric_uid_absence(deadline)['matches']
        if key=='test_listeners_absent':return not self.listener_observation(deadline)['listeners']
        if key=='temporary_files_absent':
            try:os.lstat('/tmp/p2a-'+self.context.plan.scope)
            except FileNotFoundError:return True
            return False
        if key=='resolver_unchanged':
            alias=self.assets.aliases.get('/etc/resolv.conf');target=alias['target'] if alias else '/etc/resolv.conf'
            if alias:self.assets.read_alias('/etc/resolv.conf')
            return self.resolver_before==(self.assets.inspect_asset(target),self.assets.read_asset(target))
        if key=='watchdog_absent':return False # observer lacks supervising owner's reaping authority
        # Firewall/account/restoration observations belong to contained fixed
        # commands plus KernelReadback, never an inferred boolean here.
        raise SessionDenied('RESOURCE_REQUIRES_CONTAINED_COMMAND_OR_SUPERVISING_OWNER')
