"""Nonprivileged exec shim: a Linux child exits if its owning Core dies.

Only TunnelManager invokes this file. No downloads, shell, privilege changes or
process discovery. The inherited ownership descriptor survives exec.
"""
import ctypes
import os
import signal
import sys


def main():
    owner = int(sys.argv[1])
    if sys.platform != "linux":
        raise SystemExit("Linux parent-death notification is required")
    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_PDEATHSIG is an unprivileged process-lifetime setting.
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != owner:
        raise SystemExit(2)
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    main()
