"""Development fixture guard: deny non-loopback networking, including children."""
import ipaddress
import socket

_installed = False


def install():
    global _installed
    if _installed:
        return
    _installed = True
    def local(host):
        if isinstance(host, bytes):
            host = host.decode("ascii")
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except (ValueError, TypeError):
            return False
    def check(sock, address):
        if sock.family == socket.AF_UNIX:
            return
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or not isinstance(address, tuple) or not local(address[0]):
            raise OSError("Native fixture forbids non-loopback sockets")
    resolve = socket.getaddrinfo
    def dns(host, *args, **kwargs):
        if not local(host):
            raise OSError("Native fixture forbids external DNS")
        answers = resolve(host, *args, **kwargs)
        if any(not local(answer[4][0]) for answer in answers):
            raise OSError("Native fixture forbids non-loopback resolution")
        return answers
    socket.getaddrinfo = dns
    for name in ("connect", "connect_ex", "bind"):
        original = getattr(socket.socket, name)
        def guarded(self, address, *args, _original=original, **kwargs):
            check(self, address)
            return _original(self, address, *args, **kwargs)
        setattr(socket.socket, name, guarded)
    send = socket.socket.sendto
    def sendto(self, data, *args):
        check(self, args[-1])
        return send(self, data, *args)
    socket.socket.sendto = sendto
