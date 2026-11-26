#!/usr/bin/env python3
"""The image's DHCP client, against a server that does what a test wants (tools/dhcpd.py):

    DHCPD=none unshare -Urn ./tap.sh python3 tools/dhcptest.py [SEED]      (a minute)

An image without an address of its own (the default) must: answer nobody while it has
none (not even who asks for 0.0.0.0); ask again when nobody answers, each time with a
number of its own; take no notice of what is not a server's answer to it (another
number, the number of its question before this one, a wrong checksum, other ports, a
message cut short, options that say they are longer than the message) nor of an answer
it did not ask for; ask the server that made the offer for the address offered, and no
second server for another; take a yes only to the address it asked for, and serve on
it; ask to keep it at half its time, as RFC 2131 has a client ask that has heard nothing
from its own server; take an answer without a UDP checksum; give the address up when
told "no", ask anew, and serve on the new one and not on the old; and be there after a
few thousand answers damaged at random.
"""
import os
import random
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dhcpd import Server, ip  # noqa: E402

B = os.environ.get("B", "build")
NAME = open(f"{B}/name").read().strip()
A, A2, SID = "10.0.2.77", "10.0.2.99", "10.0.2.2"
SEED = int(sys.argv[1]) if len(sys.argv) > 1 else random.randrange(1 << 32)
rnd = random.Random(SEED)
srv = Server(os.environ.get("TAP", "k2t"))
failed = []


def check(what, ok, note=""):
    print(("ok   " if ok else "FAIL ") + what + (f": {note}" if note and not ok else ""), flush=True)
    if not ok:
        failed.append(what)


def fetch(addr, t=2):
    ca = ["--cacert", f"{B}/ca.pem"] if os.path.getsize(f"{B}/ca.pem") else []
    return subprocess.run(["curl", "-s", "--max-time", str(t), "-o", "/dev/null", "--interface", "10.0.2.32", *ca,
                           "--connect-to", f"{NAME}:443:{addr}:443", f"https://{NAME}/"]).returncode == 0


def say(m, kind, addr, lease=3600, **k):
    """(from another address each time: which processor takes the frame depends on it)"""
    srv.say(m, kind, addr, lease, src=f"10.0.2.{rnd.randrange(100, 200)}", **k)


def expect(kind, t, what):
    m = srv.get(t)
    check(what, m is not None and m.kind == kind, str(m))
    if m is None:
        print(f"FAIL: nothing came (seed {SEED})")
        sys.exit(1)
    return m


# 1. Nobody answers: it asks again, the same question
m1 = expect(1, 10, "it asks for an address (DISCOVER)")
t1 = time.time()
check("  as a broadcast of 342 bytes from 0.0.0.0, a message of 300, with no address named",
      (m1.length, m1.to, m1.src, m1.ciaddr, m1.bootp) == (342, "255.255.255.255", "0.0.0.0", "0.0.0.0", 300)
      and 50 not in m1.opts and 54 not in m1.opts, f"{m1} {m1.length} {m1.to} {m1.bootp} {m1.opts}")
arp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
arp.bind((os.environ.get("TAP", "k2t"), 0))
arp.settimeout(0.3)
arp.send(b"\xff" * 6 + srv.mac + b"\x08\x06" + bytes([0, 1, 8, 0, 6, 4, 0, 1]) + srv.mac + ip(SID) + bytes(6) + ip("0.0.0.0"))
try:
    while True:
        f, a = arp.recvfrom(100)
        if a[2] != socket.PACKET_OUTGOING and f[20:22] == b"\0\x02":
            check("  who asks for 0.0.0.0 meanwhile gets no answer", False, f.hex())
            break
except socket.timeout:
    check("  who asks for 0.0.0.0 meanwhile gets no answer", True)
m = expect(1, 6, "nobody answers: it asks again")
check("  2 or 4 s later, with another number, and says that it has asked for longer",
      1.5 < time.time() - t1 < 4.6 and m.xid != m1.xid and m.secs > m1.secs > 0, f"{time.time() - t1:.1f} s, {m.xid.hex()} {m1.xid.hex()}, {m1.secs} {m.secs}")

# 2. What is no answer to it
other = bytes(x ^ 0x55 for x in m.xid)
say(m, 5, A2, xid=other)                                    # another client's number
say(m, 5, A2, xid=m1.xid)                                   # the number of its question before this one
say(m, 2, A2, xid=m1.xid)
say(m, 5, A2, sum="wrong")
say(m, 5, A2, sport=1067)
say(m, 5, A2, dport=1068)
say(m, 5, A2, cut=236)                                      # ends before its options
say(m, 5, A2, cut=242)                                      # ends inside the first one
say(m, 5, A2, opts=bytes([53, 200, 5]))                     # an option longer than the message
say(m, 5, A2, opts=bytes([54, 4]) + ip(SID) + bytes([51, 4, 0, 0, 14, 16, 255]))  # no kind of message
say(m, 5, A2, opts=bytes([0] * 20 + [255, 53, 1, 5]))       # what is behind the end
say(m, 2, A2, xid=other)
say(m, 2, A2, cut=240)
check("no notice is taken of what is not an answer to it (10 kinds): no request follows", srv.get(0.5) is None)
check("  and it does not serve on the address they named", not fetch(A2, 1))

# 3. An offer: it asks that server for that address. The request is lost: it starts over
say(m, 2, A)
r = expect(3, 2, "an offer: it asks for the address (REQUEST)")
check("  from 0.0.0.0 still, naming the address and the server that offered it",
      (r.src, r.ciaddr, r.to) == ("0.0.0.0", "0.0.0.0", "255.255.255.255") and r.opts.get(50) == ip(A) and r.opts.get(54) == ip(SID),
      f"{r} {r.opts}")
say(m, 2, A2)
check("  another server's offer for the same question gets no request", srv.get(0.5) is None)
check("  and it does not serve on anything before it is told yes", not fetch(A, 1))
m = expect(1, 10, "no answer to the request: it asks anew (DISCOVER)")
say(m, 2, A)
r = expect(3, 2, "  and for the address again")
say(r, 5, A2, 6)                                            # yes, to another address than it asked for
say(r, 5, "0.0.0.0", 6)                                     # yes, to none
time.sleep(0.2)
check("a yes to another address than it asked for, or to none, is no yes", not fetch(A2, 1) and not fetch(A, 1))
say(r, 5, A, 6)                                             # yes, for six seconds
t0 = time.time()
time.sleep(0.2)
check("told yes: it serves on that address", fetch(A))
check("  and on no other", not fetch(A2, 1) and not fetch("10.0.2.15", 1))

# 4. Not asking: an answer is none
say(r, 5, A2)
say(r, 6, "0.0.0.0")
time.sleep(0.2)
check("an answer it did not ask for (yes to another address, no) changes nothing", fetch(A) and not fetch(A2, 1))

# 5. Half the time later (and a second) it asks to keep the address
r = expect(3, 8, "it asks to keep the address")
dt = time.time() - t0
check("  after half its time and a second", 3.5 < dt < 5.5, f"{dt:.1f} s")
check("  as its owner (ciaddr), from it, to everybody, naming neither address nor server, with a number of its own",
      (r.src, r.ciaddr, r.to) == (A, A, "255.255.255.255") and 50 not in r.opts and 54 not in r.opts and r.xid not in (m.xid, m1.xid),
      f"{r} to {r.to} {r.opts}")
say(r, 5, A, 6, sum="none")                                 # yes, without a UDP checksum
t0 = time.time()
r = expect(3, 8, "an answer without a UDP checksum counts")
dt = time.time() - t0
check("  (it asked again after half the time, not at once)", 3.5 < dt < 5.5, f"{dt:.1f} s")

# 6. No: it gives the address up, asks anew, and serves on what it is given then
say(r, 6, "0.0.0.0")
m = expect(1, 4, "told no: it asks anew (DISCOVER)")
check("  as one that has no address", (m.src, m.ciaddr) == ("0.0.0.0", "0.0.0.0"), str(m))
check("  and does not serve on the old one", not fetch(A, 1))
say(m, 2, A2)
r = expect(3, 2, "  it asks for the address offered now")
say(r, 5, A2, 2)
time.sleep(0.2)
check("  serves on it", fetch(A2))
check("  and not on the old one", not fetch(A, 1))

# 7. Answers damaged at random, a thousand a second, for a quarter of a minute. Most are
# offers, which it reads to the end and has no use for while it has an address; some say
# yes or no, and move it. A lease is two seconds, and a proper answer comes a second late:
# so it is asking, and reading them, a good part of the time. (One that would be read as
# a yes for longer than that is not sent: it would not ask again for as long, and read
# nothing. `reads` says how the image reads a message; if it reads otherwise, it shows in
# how often it asks.) It must be there afterwards, on the address it is given properly at
# the end.
def reads(f):
    """(which message, for how many seconds) the image takes the frame f to be"""
    end = 14 + struct.unpack_from(">H", f, 16)[0]
    val = {51: b"\xff" * 4, 52: b"", 53: bytes(4), 54: b""}
    b, p = bytes(f[:end]) + bytes(4), 282
    while p + 2 <= end and b[p] != 255:
        if b[p] == 0:
            p += 1
            continue
        t, p = b[p], p + 2
        if p + b[p - 1] > end:
            break
        if t in val:
            val[t] = b[p:p + 4]
        p += b[p - 1]
    return val[53][0], struct.unpack(">I", val[51])[0]


def proper(m, lease):
    if m.kind == 1:
        say(m, 2, A2)
    elif m.opts.get(50, ip(m.ciaddr)) == ip(A2):
        say(m, 5, A2, lease)
    else:
        say(m, 6, "0.0.0.0")


n, asked, due, end = 0, 0, None, time.time() + 15
while time.time() < end:
    got = srv.get(0.001)
    if got is not None:
        m, asked = got, asked + 1
        due = due or time.time() + 1
    if due and time.time() >= due:
        proper(m, 2)
        due = None
    f = bytearray(srv.frame(m, rnd.choice([2, 2, 2, 2, 2, 5, 6, 0, 7]), A2, rnd.choice([1, 2, 2, 3]),
                            src=f"10.0.2.{rnd.randrange(100, 200)}"))
    how = rnd.randrange(6)
    if how == 0:                                            # bytes of the options changed
        for _ in range(rnd.randrange(1, 6)):
            f[rnd.randrange(282, len(f))] = rnd.randrange(256)
    elif how == 1:                                          # an option's length
        f[283 + rnd.choice([0, 3, 9, 15])] = rnd.randrange(256)
    elif how == 2:                                          # cut short
        del f[rnd.randrange(42, len(f)):]
    elif how == 3:                                          # options of random bytes
        f[285:] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 80)))
    elif how == 4:                                          # an option at the very end, or half of one
        del f[rnd.randrange(285, 300):]
        f += bytes([rnd.choice([51, 53, 54, 255, 0, 7])] + [rnd.randrange(256) for _ in range(rnd.randrange(0, 5))])
    if how in (2, 3, 4):                                    # (the lengths in the headers as they are now)
        struct.pack_into(">H", f, 16, len(f) - 14)
        struct.pack_into(">H", f, 38, max(len(f) - 34, 0))
    f[40:42] = b"\0\0"                                      # (no checksum: it counts as it is)
    kind, lease = reads(f)
    if kind == 5 and lease > 3:
        continue
    srv.s.send(bytes(f))
    n += 1
up = False
end = time.time() + 20
while time.time() < end and not up:
    got = srv.get(0.5)
    if got is not None:
        proper(got, 3600)
        time.sleep(0.2)
    up = fetch(A2, 1)
check(f"after {n} answers damaged at random it is there, on the address it was given last", up)
check("  and it went on asking all the while", asked >= 6, f"it asked {asked} times")

print(("all ok" if not failed else f"FAILED: {len(failed)}") + f" (seed {SEED})")
sys.exit(1 if failed else 0)
