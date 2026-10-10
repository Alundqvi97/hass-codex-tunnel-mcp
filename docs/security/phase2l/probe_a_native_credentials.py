"""Inactive fixed role credential installation. No operations on import.

The existing immutable runner must authenticate libc/libcap before this code.
Only the native policy adapter invokes installation, inside the launcher's
irreversible child fail-stop boundary. Controller uses existing drop_controller.
NNP plus NOROOT prevents exec from recovering the root bounding capabilities.
The native candidate supports equal five-set profiles only; no widening fallback.
"""
from __future__ import annotations
import ctypes, os
from probe_a_privilege import NativeCapabilityOps
from probe_a_execution_contract import ROLE_CAPABILITY_LIMITS,WORKER_BOOTSTRAP_LIMIT
from probe_a_session import SessionDenied


def role_mask(role,policy):
    if role not in ROLE_CAPABILITY_LIMITS:raise SessionDenied('UNKNOWN_CREDENTIAL_ROLE')
    values=policy['roles'][role]['pre_exec_caps']
    limit=WORKER_BOOTSTRAP_LIMIT if role=='worker' else ROLE_CAPABILITY_LIMITS[role]
    if (type(values) is not list or len(values)!=5 or any(type(n) is not int or n<0 or n&~limit for n in values)
        or len(set(values))!=1 or role=='worker' and values[0]!=WORKER_BOOTSTRAP_LIMIT):
        raise SessionDenied('UNSUPPORTED_EXACT_NATIVE_CAPABILITY_PROFILE')
    return values[0]


class NativeRoleCredentials(NativeCapabilityOps):
    def set_process_sets(self,mask):
        lib=ctypes.CDLL('libcap.so.2',use_errno=True)
        declarations={'cap_init':(ctypes.c_void_p,[]),'cap_free':(ctypes.c_int,[ctypes.c_void_p]),
            'cap_set_flag':(ctypes.c_int,[ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.c_int]),
            'cap_set_proc':(ctypes.c_int,[ctypes.c_void_p])}
        for name,(result,args) in declarations.items():getattr(lib,name).restype=result;getattr(lib,name).argtypes=args
        caps=lib.cap_init()
        if not caps:raise SessionDenied('ROLE_LIBCAP_INIT_FAILED')
        try:
            numbers=[n for n in range(64) if mask&(1<<n)]
            if numbers:
                array=(ctypes.c_int*len(numbers))(*numbers)
                for flag in (0,1,2):
                    if lib.cap_set_flag(caps,flag,len(numbers),array,1)!=0:raise SessionDenied('ROLE_LIBCAP_FLAG_FAILED')
            if lib.cap_set_proc(caps)!=0:raise SessionDenied('ROLE_LIBCAP_INSTALL_FAILED')
        finally:
            if lib.cap_free(caps)!=0:raise SessionDenied('ROLE_LIBCAP_DISPOSAL_FAILED')
        return True

    def install(self,role,policy):
        mask=role_mask(role,policy)
        if role=='controller':return True # existing complete UID/GID/cap drop follows
        if os.geteuid()!=0 or self.thread_count()!=1:raise SessionDenied('ROOT_SINGLE_THREAD_CREDENTIAL_INSTALL_REQUIRED')
        maximum=self.last_capability()
        if mask>> (maximum+1):raise SessionDenied('ROLE_CAPABILITY_OUTSIDE_KERNEL_RANGE')
        if not self.no_new_privs() or not self.clear_ambient():raise SessionDenied('ROLE_NNP_OR_AMBIENT_CLEAR_FAILED')
        # NOROOT locked; NO_SETUID_FIXUP locked OFF; KEEP_CAPS locked OFF.
        # UID changes in setpriv must still clear permitted/effective/ambient.
        if self._prctl(28,0x2b)!=0:raise SessionDenied('ROLE_SECUREBITS_INSTALL_FAILED')
        # Observer deliberately lacks SETGID. Do not make an unnecessary
        # privileged call when its inherited supplementary groups are empty.
        if os.getgroups():os.setgroups([])
        if os.getgroups():raise SessionDenied('ROLE_SUPPLEMENTARY_GROUPS_REMAIN')
        for number in range(maximum+1):
            present=self.bounding_member(number)
            if mask&(1<<number):
                if not present:raise SessionDenied('REQUIRED_ROLE_BOUNDING_CAPABILITY_ABSENT')
            elif present and not self.drop_bounding(number):raise SessionDenied('ROLE_BOUNDING_DROP_FAILED')
        if not self.set_process_sets(mask):raise SessionDenied('ROLE_PROCESS_SETS_FAILED')
        for number in range(maximum+1):
            if mask&(1<<number) and self._prctl(47,2,number)!=0:raise SessionDenied('ROLE_AMBIENT_RAISE_FAILED')
        return True
