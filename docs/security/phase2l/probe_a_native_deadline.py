"""Wrapper for externally pinned deadline-guard artifact, default disabled.

No Python signal callback and no root thread. The compiled C implementation
uses a monotonic kernel timer whose handler calls _exit(76), so native C stalls
cannot merely defer a Python exception. It never certifies successful cleanup.
"""
from __future__ import annotations
import ctypes
import fcntl
import hashlib
import stat
import os
import time
import math
from probe_a_session import SessionDenied


class NativeDeadlineGuard:
    def __init__(self, library_fd, context, *, artifact_identity, artifact_sha256=None, activated=False):
        if activated is not True or os.geteuid()!=0:
            raise SessionDenied("NATIVE_DEADLINE_GUARD_DISABLED")
        info=os.fstat(library_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022
                or fcntl.fcntl(library_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY
                or (info.st_dev,info.st_ino)!=artifact_identity or type(artifact_sha256) is not str
                or hashlib.sha256(os.pread(library_fd,32*1024*1024+1,0)).hexdigest()!=artifact_sha256):
            raise SessionDenied("UNPINNED_DEADLINE_GUARD_ARTIFACT")
        self.context=context
        self.deadlines=[]
        self.lib=ctypes.CDLL('/proc/self/fd/'+str(library_fd))
        for name in ('probe_a_guard_initialize','probe_a_guard_arm','probe_a_guard_reinitialize_child'):
            fn=getattr(self.lib,name);fn.argtypes=[ctypes.c_double];fn.restype=ctypes.c_int
        self.lib.probe_a_guard_restore_final.argtypes=[]
        self.lib.probe_a_guard_restore_final.restype=ctypes.c_int
        if self.lib.probe_a_guard_initialize(context.end)!=0 or self.lib.probe_a_guard_restore_final()!=0:
            os._exit(76)

    def after_clone(self,deadline):
        """Direct clone3 child rearming; no claim that timers survive exec."""
        if (self.lib.probe_a_guard_reinitialize_child(self.context.end)!=0
            or self.lib.probe_a_guard_arm(min(deadline,self.context.end))!=0):os._exit(76)
        self.deadlines=[min(deadline,self.context.end)]

    def call(self, function, *args, deadline, **kwargs):
        # Cannot extend final lifetime, even when cleanup is interrupted.
        enclosing=self.deadlines[-1] if self.deadlines else self.context.end
        if type(deadline) not in (int,float) or not math.isfinite(deadline):os._exit(76)
        deadline=min(deadline,enclosing)
        if not time.monotonic()<deadline<=self.context.end or self.lib.probe_a_guard_arm(deadline)!=0:
            os._exit(76)
        self.deadlines.append(deadline)
        try:return function(*args,**kwargs)
        finally:
            self.deadlines.pop()
            # A nested call must not restore the final lifetime and silently
            # extend its enclosing factory/collector/cleanup budget.
            restore=self.deadlines[-1] if self.deadlines else self.context.end
            if self.lib.probe_a_guard_arm(restore)!=0:os._exit(76)
