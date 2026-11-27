#!/usr/bin/env python3
"""IPv6, frame by frame, against an image that has an IPv6 address (make IP6=fd00:15::15):

    B=build-site6 unshare -Urn ./tap.sh python3 tools/v6test.py [SEED]     (seconds)

What a neighbour gets who asks for our address: the advertisement, as RFC 4861 has it
(from our address to the asker's, hop limit 255, solicited and override, our card's
address in its option, its checksum right). What gets nothing: a question for another
address, one that has passed a router (hop limit 254), one with a wrong checksum, one
cut short, one from nobody ("::": is this address free?), an echo request, a router's
advertisement. A SYN gets its SYN-ACK (hop limit 64, MSS 1220, the checksum right) from
our address and no other: not one sent to another address at
our card's, not one behind another header (hop by hop), not a fragment, not one with a
wrong checksum or of another version. A file of many segments comes in records of 1220
bytes at most (a record is a segment: with its headers that is 1280 bytes, which every
link of IPv6 has to carry, so no path is too narrow for it), also to a client that says
it takes 1440, and to one whose first ack says that our SYN-ACK noted 1440 for it (what
a SYN-ACK notes comes back in the ack's low bits, and is the client's to send back or
not: `Raw` is a TCP that does). Then 3,000 frames of IPv6 that are wrong in their lengths, as
tools/rawtest.py has them for IPv4, and after all that the page, fetched over IPv6 by
curl.
"""
import hashlib
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time

os.environ.setdefault("B", "build-site6")
from tlsclient import B, NAME, BioClient  # noqa: E402

SITE = json.load(open(f"{B}/site.json"))["paths"]
TAP = os.environ.get("TAP", "k2t")
OURS = socket.inet_pton(socket.AF_INET6, open(f"{B}/ip6").read().strip())
ME = socket.inet_pton(socket.AF_INET6, "fd00:15::2")
SEED = int(sys.argv[1]) if len(sys.argv) > 1 else random.randrange(1 << 32)
rnd = random.Random(SEED)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
s.bind((TAP, 0))
MAC = s.getsockname()[4]
failed = []


def check(what, ok, note=""):
    print(("ok   " if ok else "FAIL ") + what + (f": {note}" if note and not ok else ""), flush=True)
    if not ok:
        failed.append(what)


def csum(b):
    if len(b) & 1:
        b += b"\0"
    t = sum(struct.unpack(f">{len(b) // 2}H", b))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return t ^ 0xFFFF


def ip6(src, dst, nh, payload, hop=64, to=None, version=6, length=None):
    """a frame of IPv6 from us to the guest's card (or `to`)"""
    h = struct.pack(">IHBB", version << 28, len(payload) if length is None else length, nh, hop) + src + dst
    return (to or GUEST) + MAC + b"\x86\xdd" + h + payload


def summed(src, dst, nh, body, at):
    """body with its checksum (over IPv6's pseudo header) put at `at`"""
    c = csum(src + dst + struct.pack(">IHBB", len(body), 0, 0, nh) + body)
    return body[:at] + struct.pack(">H", c) + body[at + 2:]


def ns(target, src=None, dst=None, hop=255, to=None, bad=False, opt=True, cut=None):
    src = ME if src is None else src
    dst = dst or bytes.fromhex("ff0200000000000000000001ff") + target[13:]
    body = struct.pack(">BBHI", 135, 0, 0, 0) + target + (b"\x01\x01" + MAC if opt else b"")
    body = summed(src, dst, 58, body, 2)
    if bad:
        body = body[:2] + bytes([body[2] ^ 1]) + body[3:]
    if cut is not None:
        body = body[:cut]
    return ip6(src, dst, 58, body, hop, to or b"\x33\x33\xff" + target[13:])


def syn(dst=None, sport=None, nh=6, between=b"", bad=False, version=6, seq=None):
    dst = OURS if dst is None else dst
    t = struct.pack(">HHIIBBHHH", sport or rnd.randrange(20000, 60000), 443, seq or rnd.randrange(1 << 32), 0, 0x60, 2, 64240, 0, 0) \
        + bytes([2, 4, 5, 160])
    t = summed(ME, dst, 6, t, 16)
    if bad:
        t = t[:16] + bytes([t[16] ^ 1]) + t[17:]
    return ip6(ME, dst, nh, between + t, version=version)


def answer(frame, t=0.4, want=None):
    """what the guest sends to our card within t seconds of `frame` (the first frame `want` takes)"""
    s.settimeout(0.01)
    try:
        while True:
            s.recv(4096)                # (what lay about)
    except (socket.timeout, BlockingIOError):
        pass
    s.send(frame)
    end = time.time() + t
    while time.time() < end:
        s.settimeout(max(end - time.time(), 0.001))
        try:
            f, a = s.recvfrom(4096)
        except socket.timeout:
            break
        if a[2] != socket.PACKET_OUTGOING and f[6:12] == GUEST and (want is None or want(f)):
            return f
    return None


def fetch(t=5):
    ca = ["--cacert", f"{B}/ca.pem"] if os.path.getsize(f"{B}/ca.pem") else []
    r = subprocess.run(["curl", "-s", "--max-time", str(t), "--interface", "fd00:15::32", *ca,
                        "--connect-to", f"{NAME}:443:[{socket.inet_ntop(socket.AF_INET6, OURS)}]:443", f"https://{NAME}/"],
                       capture_output=True)
    return r.returncode == 0 and hashlib.sha256(r.stdout).hexdigest() == SITE["/"]["sha256"]


class Heard:
    """a socket that keeps what came in on it"""

    def __init__(self, sock):
        self.sock, self.heard = sock, b""

    def recv(self, n):
        got = self.sock.recv(n)
        self.heard += got
        return got

    def __getattr__(self, name):
        return getattr(self.sock, name)


class Raw:
    """A TCP of our own on the packet socket, from an address the kernel does not have (so
    the kernel says nothing to what comes back; the guest answers the card a frame came
    from). `lie`: what its first ack says our SYN-ACK noted, in its low six bits."""

    def __init__(self, lie, port=41000):
        self.me, self.port, self.seq, self.buf = socket.inet_pton(socket.AF_INET6, "fd00:15::99"), port, rnd.randrange(1 << 32), b""
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        f = answer(self.seg(2, bytes([2, 4, 5, 180])), 1, lambda f: self.ours(f) and f[67] & 0x12 == 0x12)
        isn, = struct.unpack(">I", f[58:62])
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        self.ack = (((isn & ~0x3F) | lie) + 1) & 0xFFFFFFFF     # (and from there on its bytes are numbered)

    def ours(self, f):
        return f[12:14] == b"\x86\xdd" and f[20] == 6 and f[38:54] == self.me and f[56:58] == struct.pack(">H", self.port)

    def seg(self, flags, data=b""):
        opt = data if flags & 2 else b""
        t = struct.pack(">HHIIBBHHH", self.port, 443, self.seq, 0 if flags & 2 else self.ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) \
            + (opt or data)
        return GUEST + MAC + b"\x86\xdd" + struct.pack(">IHBB", 6 << 28, len(t), 6, 64) + self.me + OURS + summed(self.me, OURS, 6, t, 16)

    def sendall(self, data):
        for i in range(0, len(data), 1200):
            s.send(self.seg(0x18, data[i:i + 1200]))
            self.seq = (self.seq + len(data[i:i + 1200])) & 0xFFFFFFFF

    def recv(self, n):
        s.settimeout(5)
        while not self.buf:
            f, a = s.recvfrom(70000)
            if a[2] == socket.PACKET_OUTGOING or not self.ours(f):
                continue
            data = f[54 + (f[66] >> 4) * 4:]
            if data and struct.unpack(">I", f[58:62])[0] == self.ack:
                self.buf, self.ack = data, (self.ack + len(data)) & 0xFFFFFFFF
            s.send(self.seg(0x10))
        got, self.buf = self.buf[:n], self.buf[n:]
        return got

    def close(self):
        s.send(self.seg(0x14))


def records(path, sock=None):
    """the lengths of the records in which `path` comes over IPv6 (the flight's left out)"""
    if sock is None:
        sock = socket.socket(socket.AF_INET6)
        sock.bind(("fd00:15::33", 0))
        sock.settimeout(10)
        sock.connect((socket.inet_ntop(socket.AF_INET6, OURS), 443))
    c = BioClient(Heard(sock))
    c.handshake()
    at = len(c.sock.heard)
    c.pump(lambda: c.tls.write(f"GET {path} HTTP/1.1\r\nHost: {NAME}\r\n\r\n".encode()))
    body, want = b"", SITE[path]["length"] + len(SITE[path]["head"])
    while len(body) < want:
        body += c.pump(lambda: c.tls.read(65536))
    raw, sizes = c.sock.heard[at:], []
    while len(raw) >= 5:
        n, = struct.unpack(">H", raw[3:5])
        sizes.append(n + 5)
        raw = raw[5 + n:]
    sock.close()
    return sizes


# its card's address: from the kernel's own neighbour table, once a fetch has gone
check("the page comes over IPv6 (curl, the certificate checked)", fetch())
out = subprocess.run(["ip", "-6", "neigh", "show", "dev", TAP], capture_output=True, text=True).stdout
GUEST = next((bytes.fromhex(line.split()[2].replace(":", "")) for line in out.splitlines()
              if line.startswith(socket.inet_ntop(socket.AF_INET6, OURS) + " ") and "lladdr" in line), None)
if GUEST is None:
    print(f"FAIL: the kernel has no neighbour {socket.inet_ntop(socket.AF_INET6, OURS)}: {out!r}")
    sys.exit(1)

na = lambda f: f[12:14] == b"\x86\xdd" and f[20] == 58 and f[54] == 136
f = answer(ns(OURS), want=na)
check("who has our address? gets the advertisement", f is not None)
if f:
    body = f[54:]
    check("  from our address to the asker's, with 255 hops, 32 bytes, solicited and override, our card's address in its option",
          (f[22:38], f[38:54], f[21], f[18:20], body[4], body[8:24], body[24:26], body[26:32], len(f)) ==
          (OURS, ME, 255, b"\x00\x20", 0x60, OURS, b"\x02\x01", GUEST, 86), f.hex())
    check("  and its checksum right", csum(f[22:54] + struct.pack(">IHBB", 32, 0, 0, 58) + body) == 0)
    check("  sent to the card that asked", f[0:6] == MAC)
f = answer(ns(OURS, dst=OURS, to=GUEST), want=na)
check("asked at our own address (a neighbour that looks whether we are still there): the same", f is not None and f[38:54] == ME)
other = OURS[:15] + bytes([OURS[15] ^ 1])
for what, frame in (
        ("a question for another address", ns(other)),
        ("one that has passed a router (254 hops left)", ns(OURS, hop=254)),
        ("one with a wrong checksum", ns(OURS, bad=True)),
        ("one cut short", ns(OURS, opt=False, cut=20)),
        ("one from nobody (\"::\": is this address free?)", ns(OURS, src=bytes(16), opt=False)),
        ("an echo request", ip6(ME, OURS, 58, summed(ME, OURS, 58, struct.pack(">BBHHH", 128, 0, 0, 1, 1) + b"ping", 2))),
        ("a router's advertisement", ip6(ME, OURS, 58, summed(ME, OURS, 58, struct.pack(">BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0), 2), hop=255))):
    check(f"  nothing for {what}", answer(frame, 0.3, lambda f: f[12:14] == b"\x86\xdd" and f[20] == 58) is None)

sa = lambda f: f[12:14] == b"\x86\xdd" and f[20] == 6 and f[54 + 13] & 0x12 == 0x12
f = answer(syn(sport=40000, seq=1000), want=sa)
check("a SYN gets its SYN-ACK", f is not None)
if f:
    t = f[54:]
    check("  from our address, 64 hops, no flow label, acknowledging the SYN, a segment may hold 1220 bytes",
          (f[14:18], f[21], f[22:38], f[38:54], t[0:4], t[8:12], t[20:24]) ==
          (b"\x60\0\0\0", 64, OURS, ME, struct.pack(">HH", 443, 40000), struct.pack(">I", 1001), bytes([2, 4, 4, 196])), f.hex())
    check("  its checksum right", csum(f[22:54] + struct.pack(">IHBB", len(t), 0, 0, 6) + t) == 0)
for port, (what, how) in enumerate((
        ("one for another address at our card's", dict(dst=other)),
        ("one behind another header (hop by hop)", dict(nh=0, between=bytes([6, 0, 1, 4, 0, 0, 0, 0]))),
        ("a fragment", dict(nh=44, between=bytes([6, 0, 0, 1, 0, 0, 0, 1]))),
        ("one with a wrong checksum", dict(bad=True)),
        ("one of another version", dict(version=7))), 40001):
    # (to its port: the SYN before these is answered three times more, having had no ack)
    to = lambda f, port=port: f[12:14] == b"\x86\xdd" and struct.pack(">H", port) in (f[56:58], f[76:78])
    check(f"  nothing for {what}", answer(syn(sport=port, **how), 0.3, to) is None)

large = max((p for p in SITE if SITE[p]["status"] == 200 and 20000 < SITE[p]["length"] < 400000), key=lambda p: SITE[p]["length"])
sizes = records(large)
check(f"{large} comes in records of 1220 bytes, a segment each, and the rest in a last one",
      len(sizes) > 10 and set(sizes[:-1]) == {1220} and sizes[-1] <= 1220, f"{sorted(set(sizes))}")
sizes = records(large, Raw(lie=3))
check("  also to a client whose ack says that our SYN-ACK noted 1440 for it",
      len(sizes) > 10 and set(sizes[:-1]) == {1220} and sizes[-1] <= 1220, f"{sorted(set(sizes))}")

# Frames that are wrong in their lengths
n = 0
for i in range(3000):
    f = bytearray(syn() if i % 3 else ns(OURS))
    how = rnd.randrange(6)
    if how == 0:                                # the length behind the header: anything
        struct.pack_into(">H", f, 18, rnd.choice([0, 1, 7, 19, 20, 21, 39, 40, 59, 60, 1500, 2000, 65535, rnd.randrange(65536)]))
    elif how == 1:                              # the frame ends early
        del f[rnd.randrange(14, len(f)):]
    elif how == 2:                              # TCP's header says another length
        f[54 + 12] = rnd.randrange(256)
    elif how == 3:                              # both
        struct.pack_into(">H", f, 18, rnd.randrange(80))
        del f[rnd.randrange(40, len(f)):]
    elif how == 4:                              # a long frame, of which the header knows little
        f += bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 1400)))
        struct.pack_into(">H", f, 18, rnd.randrange(1500))
    else:                                       # another kind of thing behind the header
        f[20] = rnd.choice([0, 6, 17, 43, 44, 50, 58, 59, 60, 255])
    s.send(bytes(f))
    n += 1
    if i % 500 == 499:
        time.sleep(0.05)
time.sleep(0.3)
check(f"after {n} frames of IPv6 with wrong lengths the page is there", fetch())
print(("all ok" if not failed else f"FAILED: {len(failed)}") + f" (seed {SEED})")
sys.exit(1 if failed else 0)
