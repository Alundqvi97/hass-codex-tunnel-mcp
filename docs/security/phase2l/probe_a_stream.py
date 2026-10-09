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


def _owns_unreaped_session(pid, *, getpgid=os.getpgid, getsid=os.getsid):
    """Only a still-unreaped child anchoring its own session can be signaled.

    Never kill a numeric process-group ID just because it equals an old PID:
    after reap, that number may be reused by an unrelated process.
    """
    if type(pid) is not int or pid<=1:
        return False
    try:
        return getpgid(pid)==pid and getsid(pid)==pid
    except (OSError, ValueError):
        return False


def capture(argv, timeout, *, spawn=subprocess.Popen, selector_factory=selectors.DefaultSelector,
            clock=time.monotonic, on_spawn=None, on_chunk=None,
            group_owner=_owns_unreaped_session, group_kill=os.killpg):
    if (not isinstance(argv, tuple) or not argv
            or any(not isinstance(x, str) or not x or "\x00" in x for x in argv)
            or type(timeout) not in (int, float) or not 0 < timeout <= 8
            or not callable(group_owner) or not callable(group_kill)):
        raise StreamFailure("INVALID_CAPTURE_ARGUMENT")
    child = None
    selector = None
    data = bytearray()
    end = clock() + timeout
    completed = False
    leader_reaped = False
    try:
        child = spawn(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, close_fds=True,
            start_new_session=True,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
        )
        if child.stdout is None:
            raise StreamFailure("PIPE_UNAVAILABLE")
        # Record and check the session while the child is still unreaped.
        # The process may already have exited, but a zombie still anchors its
        # own PID/session until wait(). Never rely on Popen.poll() here.
        if group_owner(child.pid) is not True:
            raise StreamFailure("SPAWNED_GROUP_NOT_OWNED")
        if on_spawn is not None:
            on_spawn(child.pid)
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
                if on_chunk is not None:
                    on_chunk(bytes(data))
                if clock() >= end:
                    raise StreamFailure("CAPTURE_TIMEOUT")
        remaining = end - clock()
        if remaining <= 0:
            raise StreamFailure("CAPTURE_TIMEOUT")
        # Reaping is intentionally deferred until the entire bounded stream
        # is closed. On failure before this point, an exited group leader
        # remains a known PID/session anchor for killpg().
        child.wait(timeout=remaining)
        leader_reaped = True
        try:
            decoded = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise StreamFailure("CAPTURE_ENCODING") from None
        if "\x00" in decoded:
            raise StreamFailure("CAPTURE_NUL")
        from probe_a_exec_adapter import Reply, checked_reply
        result = checked_reply(Reply(child.returncode, decoded))
        completed = True
        return result
    except BaseException:
        raise StreamFailure("CAPTURE_FAILED") from None
    finally:
        uncertain_termination = False
        if child is not None and not completed:
            # On any abnormal outcome, including an already-exited leader,
            # signal the entire *verified* session before wait/reap. Ordinary
            # detached descendants are outside that group: approved OS-backed
            # cgroups remain mandatory for complete containment.
            if not leader_reaped:
                try:
                    if group_owner(child.pid) is not True:
                        uncertain_termination = True
                    else:
                        group_kill(child.pid, signal.SIGKILL)
                except (OSError, ValueError):
                    uncertain_termination = True
            else:
                # The numeric PID can be reused after wait(). Never signal
                # a possibly unrelated group merely because output was bad.
                uncertain_termination = True
            if not leader_reaped:
                try:
                    child.wait(timeout=0.5)
                except (OSError, subprocess.TimeoutExpired):
                    uncertain_termination = True
        if selector is not None:
            try:
                selector.close()
            except OSError:
                uncertain_termination = True
        if child is not None and child.stdout is not None:
            try:
                child.stdout.close()
            except OSError:
                uncertain_termination = True
        if uncertain_termination:
            raise StreamFailure("GROUP_TERMINATION_UNVERIFIED") from None
