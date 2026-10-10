"""Offline-inert, deadline-bounded Unix socket IPC shared by guardian and controller.

No multiprocessing.Connection framing, no unbounded recv_bytes()/send_bytes(),
no network listener, and no socket creation at import. Only a reviewed launcher
may create a local AF_UNIX socketpair. This transports bounded JSON bytes,
not pickle and not privileged commands. All deadlines are absolute monotonic.
"""
from __future__ import annotations

import select
import socket
import struct
import time

MAX_FRAME = 300000
MAX_REQUEST = 256
_HEADER = struct.Struct("!I")
_CHUNK = 8192


class IpcDenied(RuntimeError):
    pass


class IpcDeadline(IpcDenied):
    pass


class IpcFraming(IpcDenied):
    pass


class BoundedSocketIPC:
    """One strict wire format on both sides of a nonblocking stream.

    poll() is only a bounded readiness hint; partial headers and payloads
    are handled by recv_bytes(limit, deadline=<absolute>) itself.
    """
    def __init__(self, stream, *, clock=time.monotonic, select_fn=select.select):
        if (not callable(clock) or not callable(select_fn)
                or not all(callable(getattr(stream, attr, None))
                           for attr in ("setblocking", "recv", "send", "close", "fileno"))):
            raise IpcDenied("UNREVIEWED_SOCKET_ENDPOINT")
        self.stream=stream
        self.clock=clock
        self.select_fn=select_fn
        self.closed=False
        self.stream.setblocking(False)

    def _ready(self, *, writing, deadline):
        while True:
            if self.closed:
                raise IpcDenied("IPC_CLOSED")
            remaining=deadline-self.clock()
            if remaining <= 0:
                raise IpcDeadline("IPC_TRANSACTION_DEADLINE")
            readers=[] if writing else [self.stream]
            writers=[self.stream] if writing else []
            try:
                r,w,e=self.select_fn(readers,writers,[self.stream],min(remaining,0.20))
            except InterruptedError:
                continue
            except (OSError,ValueError):
                raise IpcDenied("IPC_WAIT_FAILED") from None
            if e:
                raise IpcDenied("IPC_SOCKET_ERROR")
            if bool(w if writing else r):
                return True

    def poll(self, timeout):
        if self.closed:
            raise IpcDenied("IPC_CLOSED")
        if type(timeout) not in (int,float) or not 0 <= timeout <= 1:
            raise IpcDenied("INVALID_POLL_TIMEOUT")
        end=self.clock()+timeout
        while self.clock() < end:
            remaining=end-self.clock()
            try:
                r,_,e=self.select_fn([self.stream],[],[self.stream],min(remaining,0.20))
            except InterruptedError:
                continue
            except (OSError,ValueError):
                raise IpcDenied("IPC_POLL_FAILED") from None
            if e:
                raise IpcDenied("IPC_SOCKET_ERROR")
            if r:
                return True
        return False

    def _receive_exact(self, count, deadline):
        data=bytearray()
        while len(data)<count:
            self._ready(writing=False,deadline=deadline)
            try:
                block=self.stream.recv(min(_CHUNK,count-len(data)))
            except (BlockingIOError, InterruptedError):
                continue
            except (OSError,ValueError):
                raise IpcDenied("IPC_RECV_FAILED") from None
            if not block:
                raise EOFError("IPC_TRUNCATED_FRAME")
            data.extend(block)
        return bytes(data)

    def recv_bytes(self, maximum, *, deadline):
        if type(maximum) is not int or not 0 < maximum <= MAX_FRAME:
            raise IpcDenied("INVALID_FRAME_LIMIT")
        header=self._receive_exact(_HEADER.size,deadline)
        length=_HEADER.unpack(header)[0]
        if not 0 < length <= maximum:
            raise IpcFraming("IPC_OVERSIZED_OR_EMPTY_FRAME")
        return self._receive_exact(length,deadline)

    def send_bytes(self, payload, *, deadline):
        if (type(payload) is not bytes or
                not 0 < len(payload) <= MAX_FRAME):
            raise IpcFraming("IPC_INVALID_RESPONSE_SIZE")
        view=memoryview(_HEADER.pack(len(payload))+payload)
        position=0
        while position<len(view):
            self._ready(writing=True,deadline=deadline)
            try:
                sent=self.stream.send(view[position:])
            except (BlockingIOError,InterruptedError):
                continue
            except (BrokenPipeError,ConnectionResetError,OSError,ValueError):
                raise IpcDenied("IPC_SEND_FAILED") from None
            if type(sent) is not int or sent<=0:
                raise IpcDenied("IPC_SEND_STALLED")
            position+=sent
        return True

    def close(self):
        if not self.closed:
            self.closed=True
            self.stream.close()


def socket_channel_pair(*, clock=time.monotonic):
    """Single approved real transport factory; socketpair has no listener.

    Any underlying failure closes both descriptors. Tests inject mock
    factories rather than creating sockets or invoking privileged behavior.
    """
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        return BoundedSocketIPC(left,clock=clock),BoundedSocketIPC(right,clock=clock)
    except BaseException:
        left.close()
        right.close()
        raise


class IncrementalRequest:
    """One authenticated request, without waiting on a partial controller frame.

    The observer multiplexes private channels in one trusted thread. One read
    per turn, bounded allocation, no pipelining and a fixed first-byte timeout
    preserve audit capacity under controller flooding or slow partial frames.
    """
    def __init__(self, channel, *, end, maximum=MAX_REQUEST, frame_seconds=1):
        self.channel, self.end, self.maximum = channel, end, maximum
        self.frame_seconds, self.started = frame_seconds, None
        self.data, self.length = bytearray(), None

    def receive_available(self):
        now = self.channel.clock()
        if now >= self.end or self.started is not None and now >= self.started+self.frame_seconds:
            raise IpcDeadline("INCREMENTAL_REQUEST_EXPIRED")
        ready, _, _ = self.channel.select_fn([self.channel.stream], [], [], 0)
        if not ready:
            return None
        target = 4 if self.length is None else self.length+4
        try:
            block = self.channel.stream.recv(target-len(self.data))
        except (BlockingIOError, InterruptedError):
            return None
        if not block:
            raise EOFError("IPC_TRUNCATED_FRAME")
        if self.started is None:
            self.started = now
        self.data.extend(block)
        if self.length is None and len(self.data) == 4:
            self.length = _HEADER.unpack(self.data)[0]
            if not 0 < self.length <= self.maximum:
                raise IpcFraming("IPC_OVERSIZED_OR_EMPTY_FRAME")
        if self.length is not None and len(self.data) == self.length+4:
            payload = bytes(self.data[4:])
            self.data, self.length, self.started = bytearray(), None, None
            return payload
        return None
