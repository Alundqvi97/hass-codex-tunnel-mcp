"""Ed25519 verification via existing vetted OpenSSL 3 EVP implementation.

No cryptography implementation, key creation, signing or subprocess fallback.
A native runner must externally pin libcrypto and its dependency closure in
its immutable image. Public RFC8032 vectors are test data, never approvals.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import stat
from probe_a_session import SessionDenied


class OpenSSLEd25519:
    def __init__(self, library_fd, *, library_identity, public_key, domains):
        if type(public_key) is not bytes or len(public_key) != 32 or not domains or any(
                type(d) is not bytes or not d.endswith(b"\0") for d in domains):
            raise SessionDenied("EXTERNAL_ED25519_TRUST_ROOT_AND_DOMAINS_REQUIRED")
        st = os.fstat(library_fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                or (st.st_dev, st.st_ino) != library_identity):
            raise SessionDenied("VERIFIER_LIBRARY_DESCRIPTOR_SUBSTITUTION")
        self.public_key, self.domains = public_key, tuple(domains)
        # Descriptor was authenticated by NativeAssetReader and externally
        # pinned assembly. dlopen constructors/dependencies belong to that TCB.
        self.lib = ctypes.CDLL("/proc/self/fd/"+str(library_fd))
        declarations = {
            "EVP_PKEY_new_raw_public_key_ex": (ctypes.c_void_p, [ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t]),
            "EVP_PKEY_free": (None,[ctypes.c_void_p]),
            "EVP_MD_CTX_new": (ctypes.c_void_p,[]), "EVP_MD_CTX_free": (None,[ctypes.c_void_p]),
            "EVP_DigestVerifyInit": (ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]),
            "EVP_DigestVerify": (ctypes.c_int,[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t]),
        }
        for name,(result,args) in declarations.items():
            fn = getattr(self.lib,name); fn.restype, fn.argtypes = result,args

    def verify_raw(self, message, signature):
        if type(message) is not bytes or len(message) > 300000 or type(signature) is not bytes or len(signature) != 64:
            return False
        keybuf = ctypes.create_string_buffer(self.public_key)
        key = self.lib.EVP_PKEY_new_raw_public_key_ex(None,b"ED25519",None,keybuf,32)
        ctx = self.lib.EVP_MD_CTX_new()
        try:
            if not key or not ctx or self.lib.EVP_DigestVerifyInit(ctx,None,None,None,key) != 1:
                raise SessionDenied("OPENSSL_ED25519_UNAVAILABLE")
            sigbuf, msgbuf = ctypes.create_string_buffer(signature), ctypes.create_string_buffer(message)
            return self.lib.EVP_DigestVerify(ctx,sigbuf,len(signature),msgbuf,len(message)) == 1
        finally:
            if ctx: self.lib.EVP_MD_CTX_free(ctx)
            if key: self.lib.EVP_PKEY_free(key)

    def __call__(self, message, signature):
        if type(message) is not bytes or not any(message.startswith(d) for d in self.domains):
            return False
        return self.verify_raw(message, signature)


def pinned_verifier(reader, library, public_key, domains, *, library_sha256):
    """Concrete inventory verifier wiring; refuses synthetic native ownership."""
    if reader.synthetic:
        raise SessionDenied("NATIVE_VERIFIER_REQUIRES_PROTECTED_LIBRARY")
    if hashlib.sha256(reader.read_asset(library)).hexdigest() != library_sha256:
        raise SessionDenied("VERIFIER_LIBRARY_DIGEST_DRIFT")
    descriptors, _parents, name = reader._walk(library)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptors[-1])
        expected = reader.expected[library]
        if (os.fstat(fd).st_dev,os.fstat(fd).st_ino) != (expected["device"],expected["inode"]):
            raise SessionDenied("VERIFIER_LIBRARY_REPLACED")
        raw = os.pread(fd,32*1024*1024+1,0)
        if hashlib.sha256(raw).hexdigest() != library_sha256:
            raise SessionDenied("RETAINED_VERIFIER_LIBRARY_DIGEST_DRIFT")
        return OpenSSLEd25519(fd,library_identity=(expected["device"],expected["inode"]),
                             public_key=public_key,domains=domains)
    finally:
        if fd is not None: os.close(fd)
        for item in reversed(descriptors): os.close(item)
