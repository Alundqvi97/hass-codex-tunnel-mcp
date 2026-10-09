"""Bounded streaming subprocess capture; no command allowlist lives here.

Only the reviewed RestrictedHost boundary may call this helper for privileged
commands. Does nothing at import. Process-group termination on local failures
does NOT protect against SIGKILL of the parent or runner shutdown.
"""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time

MAX_BYTES = 131072
CHUNK = 8192


class StreamFailure(RuntimeError):
    pass


def capture(argv, timeout, *, spawn=subprocess.Popen, selector_factory=selectors.DefaultSelector,
            clock=time.monotonic):
    if (not isinstance(argv, tuple) or not argv
            or any(not isinstance(x, str) or not x or "\x00" in x for x in argv)
            or type(timeout) not in (int, float) or not 0 < timeout <= 8):
        raise StreamFailure("INVALID_CAPTURE_ARGUMENT")
    child = None
    selector = None
    data = bytearray()
    end = clock() + timeout
    try:
        child = spawn(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, close_fds=True,
            start_new_session=True,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
        )
        if child.stdout is None:
            raise StreamFailure("PIPE_UNAVAILABLE")
        os.set_blocking(child.stdout.fileno(), False)
        selector = selector_factory()
        selector.register(child.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = end - clock()
            if remaining <= 0:
                raise StreamFailure("CAPTURE_TIMEOUT")
            events = selector.select(min(remaining, 0.20))
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(data) + len(chunk) > MAX_BYTES:
                    raise StreamFailure("CAPTURE_OVERFLOW")
                data.extend(chunk)
        remaining = end - clock()
        if remaining <= 0:
            raise StreamFailure("CAPTURE_TIMEOUT")
        child.wait(timeout=remaining)
        try:
            decoded = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise StreamFailure("CAPTURE_ENCODING") from None
        if "\x00" in decoded:
            raise StreamFailure("CAPTURE_NUL")
        from probe_a_exec_adapter import Reply, checked_reply
        return checked_reply(Reply(child.returncode, decoded))
    except BaseException:
        raise StreamFailure("CAPTURE_FAILED") from None
    finally:
        if selector is not None:
            selector.close()
        if child is not None:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=0.5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if child.stdout is not None:
                child.stdout.close()
