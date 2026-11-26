#!/usr/bin/env python3
"""dhcpd.py IFACE [ADDRESS]: the tests' DHCP server. Whoever asks on IFACE is given ADDRESS
(default 10.0.2.15), for LEASE seconds (default 3600): what tap.sh runs beside an image
that has no address of its own. On a packet socket: no port to bind, nothing to route, and
it sees a client that has no address yet.

It is also what tools/dhcptest.py is made of: `Server` hears the client's messages (`get`)
and says what the test wants said (`say`), right or wrong.
"""
import os
import socket
import struct
import sys

COOKIE = bytes([99, 130, 83, 99])
KIND = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}


def csum(b):
    if len(b) & 1:
        b += b"\0"
    s = sum(struct.unpack(f">{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s ^ 0xFFFF


def ip(a):
    return socket.inet_aton(a)


class Msg:
    """A client's message: kind (1 DISCOVER, 3 REQUEST), xid, secs, mac, ciaddr, src (the
    IP header's source), to (its destination), opts {number: value}, length (of the frame)."""

    def __init__(self, f):
        self.length = len(f)
        self.src, self.to = socket.inet_ntoa(f[26:30]), socket.inet_ntoa(f[30:34])
        b = f[42:]
        self.bootp = len(b)
        self.xid, self.ciaddr, self.mac = b[4:8], socket.inet_ntoa(b[12:16]), b[28:34]
        self.secs = struct.unpack(">H", b[8:10])[0]
        self.opts, o = {}, b[240:]
        while o and o[0] != 255:
            if o[0] == 0:
                o = o[1:]
                continue
            self.opts[o[0]] = o[2:2 + o[1]]
            o = o[2 + o[1]:]
        self.kind = self.opts.get(53, b"\0")[0]

    def __str__(self):
        want = self.opts.get(50)
        return (f"{KIND.get(self.kind, self.kind)} xid={self.xid.hex()} from {self.src} ciaddr={self.ciaddr}"
                + (f" wants {socket.inet_ntoa(want)}" if want else ""))


class Server:
    def __init__(self, iface, me="10.0.2.2"):
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.s.bind((iface, 0))
        self.mac = self.s.getsockname()[4]
        self.me = me

    def get(self, timeout=None):
        """the next message a client sends (None after `timeout` seconds)"""
        self.s.settimeout(timeout)
        while True:
            try:
                f, a = self.s.recvfrom(4096)
            except (socket.timeout, BlockingIOError):
                return None
            if a[2] == socket.PACKET_OUTGOING or len(f) < 282 or f[23] != 17 or f[36:38] != b"\0\x43":
                continue
            if f[42] == 1 and f[278:282] == COOKIE:
                return Msg(f)

    def frame(self, m, kind, addr, lease=3600, *, xid=None, opts=None, src=None, to=None,
              sport=67, dport=68, sum="right", cut=None, tail=b""):
        """what `say` sends: a server's message of `kind` about `addr`, for the client that
        sent m. opts: the options as bytes, in place of ours. sum: "right", "none", "wrong".
        cut: the BOOTP message ends after so many bytes. tail: bytes behind the last option."""
        if opts is None:
            opts = bytes([53, 1, kind, 54, 4]) + ip(self.me) + bytes([51, 4]) + struct.pack(">I", lease) \
                + bytes([1, 4, 255, 255, 255, 0, 3, 4]) + ip(self.me) + b"\xff"
        b = bytes([2, 1, 6, 0]) + (xid or m.xid) + bytes(4) + ip(m.ciaddr if kind == 5 else "0.0.0.0") \
            + ip(addr) + ip(self.me) + bytes(4) + m.mac + bytes(10 + 192) + COOKIE + opts + tail
        b = b.ljust(300, b"\0") if cut is None else b[:cut]
        src, to = ip(src or self.me), ip(to or (addr if addr != "0.0.0.0" else "255.255.255.255"))
        u = struct.pack(">HHHH", sport, dport, 8 + len(b), 0) + b
        if sum != "none":
            c = csum(src + to + struct.pack(">HH", 17, len(u)) + u) or 0xFFFF
            if sum == "wrong":
                c ^= 0x0100
            u = u[:6] + struct.pack(">H", c) + u[8:]
        h = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0) + src + to
        h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
        return m.mac + self.mac + b"\x08\x00" + h + u

    def say(self, *a, **k):
        try:
            self.s.send(self.frame(*a, **k))
        except OSError as e:                                # (an interface whose MTU is less than a message)
            print(f"not sent: {e}", flush=True)


def main():
    iface = sys.argv[1]
    addr = sys.argv[2] if len(sys.argv) > 2 else "10.0.2.15"
    lease = int(os.environ.get("LEASE", "3600"))
    srv = Server(iface)
    while True:
        m = srv.get()
        if m.kind == 1:
            srv.say(m, 2, addr, lease)
        elif m.kind == 3:
            want = m.opts.get(50, ip(m.ciaddr))
            srv.say(m, 5 if want == ip(addr) else 6, addr if want == ip(addr) else "0.0.0.0", lease)
        print(m, flush=True)


if __name__ == "__main__":
    main()
