"""Inactive libbpf attachment ownership and bounded raw observation decoding.

Partial syscall collection is not DNS/netfilter/cookie/rule measurement.
Never promote raw events or synthetic decoder fixtures into runtime evidence.
"""
from __future__ import annotations
import ctypes, os, struct, time
from probe_a_session import SessionDenied, canonical
PROGRAMS=('enter_connect','exit_connect','enter_sendto','exit_sendto','enter_recvfrom','exit_recvfrom','enter_close')
EVENT=struct.Struct('<QQQQIIqq')


class TraceDecoder:
    """ABI start identity is task.start_boottime nanoseconds, NOT proc ticks.

    The external collector must independently obtain this exact kernel field.
    No implicit conversion from ProcessIdentity.starttime is supported. Events
    reordered across CPUs remain incomplete; arrival order is not a kernel
    guarantee, and this partial decoder never grants measurement acceptance.
    """
    def __init__(self, *, begin_ns,end_ns,incarnations_ns):
        if (type(begin_ns) is not int or type(end_ns) is not int or not 0<=begin_ns<end_ns
            or type(incarnations_ns) is not dict or not incarnations_ns
            or any(type(pid) is not int or pid<=1 or type(ns) is not int or ns<=0 for pid,ns in incarnations_ns.items())):
            raise SessionDenied('TRACE_EXACT_NANOSECOND_IDENTITY_REQUIRED')
        self.begin,self.end,self.identities=begin_ns,end_ns,dict(incarnations_ns)
        self.sequence=0;self.events=[];self.incomplete=[]
    def consume(self,raw):
        try:
            if type(raw) is not bytes or len(raw)!=EVENT.size:raise SessionDenied('TRACE_TRUNCATED_EVENT')
            seq,stamp,pidtid,start,version,kind,arg,result=EVENT.unpack(raw);pid=pidtid>>32
            if (version!=1 or not 1<=kind<=7 or seq!=self.sequence+1
                or not self.begin<=stamp<self.end or self.identities.get(pid)!=start or len(self.events)>=4096):
                raise SessionDenied('TRACE_REPLAY_LOSS_INCARNATION_OR_INTERVAL')
            self.sequence=seq;self.events.append((stamp,pid,start,kind,arg,result))
        except SessionDenied as error:self.incomplete.append(str(error));raise
    def finish(self,*,kernel_lost_events):
        if type(kernel_lost_events) is not int or kernel_lost_events<0:raise SessionDenied('TRACE_LOSS_COUNTER_INVALID')
        if kernel_lost_events:self.incomplete.append('TRACE_RINGBUFFER_LOSS')
        return {'events':tuple(self.events),'defects':tuple(self.incomplete),
                'provenance':'INCOMPLETE_RUNTIME_EVIDENCE','result':'BLOCKED_NO_TRUSTED_RUNTIME_PASS',
                'missing':('DNS/loopback payload correlation','socket FD/cookie reuse','netfilter reject/rule/counter attribution')}


class NativeTraceLoader:
    """Separate provisioning authority, not a guardian/observer runtime power.

    The immutable runner pins loaded libbpf and ELF dependencies beforehand.
    No API call occurs in constructor/default attach. Only own links destroyed.
    """
    def __init__(self,context,library,*,reader,clock=time.monotonic):
        self.context,self.lib,self.reader,self.clock=context,library,reader,clock
        self.object=None;self.links=[];self.asset_fd=None
    def attach(self,object_path,expected_hash,configuration,signature,*,verify,activated=False):
        import hashlib
        expected={'purpose':'provision-probe-a-trace','context':self.context.identifier,
                  'object_sha256':expected_hash,'configuration':configuration,'programs':list(PROGRAMS)}
        if (activated is not True or os.geteuid()!=0 or self.object is not None
            or verify(b'ProbeA trace provisioning v1\0'+canonical(expected),signature) is not True):
            raise SessionDenied('SEPARATE_TRACE_PROVISIONING_REQUIRED')
        self.context.check_time(self.clock())
        raw=self.reader.read_asset(object_path)
        if hashlib.sha256(raw).hexdigest()!=expected_hash:raise SessionDenied('TRACE_OBJECT_DRIFT')
        lib=self.lib
        declarations={'bpf_object__open_file':(ctypes.c_void_p,[ctypes.c_char_p,ctypes.c_void_p]),
            'libbpf_get_error':(ctypes.c_long,[ctypes.c_void_p]),'bpf_object__load':(ctypes.c_int,[ctypes.c_void_p]),
            'bpf_object__next_program':(ctypes.c_void_p,[ctypes.c_void_p,ctypes.c_void_p]),
            'bpf_program__name':(ctypes.c_char_p,[ctypes.c_void_p]),'bpf_program__attach':(ctypes.c_void_p,[ctypes.c_void_p]),
            'bpf_link__destroy':(ctypes.c_int,[ctypes.c_void_p]),'bpf_object__close':(None,[ctypes.c_void_p])}
        for name,(restype,args) in declarations.items():
            fn=getattr(lib,name);fn.restype=restype;fn.argtypes=args
        self.asset_fd=self.reader.open_verified_fd(object_path)
        if hashlib.sha256(os.pread(self.asset_fd,32*1024*1024+1,0)).hexdigest()!=expected_hash:
            os.close(self.asset_fd);self.asset_fd=None
            raise SessionDenied('TRACE_OPENED_OBJECT_HASH_MISMATCH')
        self.object=lib.bpf_object__open_file(('/proc/self/fd/'+str(self.asset_fd)).encode('ascii'),None)
        if not self.object or lib.libbpf_get_error(self.object):
            self.object=None;os.close(self.asset_fd);self.asset_fd=None
            raise SessionDenied('TRACE_ELF_OPEN_FAILED')
        try:
            programs=[];current=None
            while True:
                current=lib.bpf_object__next_program(self.object,current)
                if not current:break
                programs.append((lib.bpf_program__name(current).decode('ascii'),current))
                if len(programs)>len(PROGRAMS):raise SessionDenied('UNAPPROVED_TRACE_PROGRAM')
            if {name for name,_ in programs}!=set(PROGRAMS):raise SessionDenied('TRACE_PROGRAM_SET_MISMATCH')
            if lib.bpf_object__load(self.object)!=0:raise SessionDenied('TRACE_KERNEL_LOAD_FAILED_NO_FALLBACK')
            # Configuration map remains disabled (zero) deliberately: actual
            # cgroup/UID/interval activation and measurement schema are still
            # incomplete source, not an activation permission workaround.
            for _,program in programs:
                link=lib.bpf_program__attach(program)
                if not link or lib.libbpf_get_error(link):raise SessionDenied('TRACE_ATTACH_PARTIAL')
                self.links.append(link)
            if hashlib.sha256(self.reader.read_asset(object_path)).hexdigest()!=expected_hash:
                raise SessionDenied('TRACE_ASSET_CHANGED_DURING_ATTACHMENT')
            return tuple(self.links)
        except BaseException:self.close();raise
    def close(self):
        links,self.links=self.links,[];uncertain=False
        for link in reversed(links):
            if self.lib.bpf_link__destroy(link)!=0:uncertain=True
        obj,self.object=self.object,None
        if obj is not None:self.lib.bpf_object__close(obj)
        if self.asset_fd is not None:os.close(self.asset_fd);self.asset_fd=None
        if uncertain:raise SessionDenied('TRACE_OWNED_DETACH_UNCERTAIN')
