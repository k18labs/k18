#!/usr/bin/env python3
"""acktest.py: segments in a client's name that are not the client's.

Whoever sends for a client without seeing what we send it knows the client's address and
port and has to make up two numbers: where the client's sequence numbers are, and where
ours are (the ack). What becomes of a segment must depend on both (RFC 9293, 3.10.7.4:
the sequence number first; RFC 5961, 5.2: and the ack). The client's own begins within
64 KB of what we expect, either way, and its ack is for something we sent that is not
acknowledged yet, or older than that by less than can have been on its way at once (2^19
bytes: more than 255 segments). Of any other segment nothing is taken, not its ack, not
its data, not its FIN, and it gets an ack that says where we are.

Frame by frame, from an address that is not this machine's (so that its own TCP has no
part in it), on port 80:
- a request whose ack is not the client's gets a bare ack and no response, and the same
  request with the right ack then gets the response, acknowledged from the sequence
  number it had (nothing was taken). The same for a FIN, and after a SYN has come again
  for the connection (which is when a new connection may take an old one's place: but
  only with the cookie of that SYN's answer);
- an ack that is old by less than 2^19 is a packet that others overtook: its request is
  answered;
- a client that comes again from the same port while we still have its connection (its
  SYN, then the ack of our answer to that, with a request) is a new connection in the
  old one's place, wherever its new sequence numbers are: far from the old ones, or
  among them;
- what waits for an ack (port 80 sends 4 KiB at a time) is not let go by one whose
  sequence number is a megabyte from the client's, either way, though its ack is right;
  it is by the client's, also from a little before what we expect and a little behind;
- a RST ends a connection at one number, the one our acks have said: not a byte before
  it or behind, and, while an answer of several segments is on its way (when our acks
  hold the client's last byte back, `tcp_send`), at that held-back number and not where
  the client's own numbers are. That is the number a host has that knows nothing of
  the connection but our segments, which is what a RST is mostly from.
On port 443: bytes with such an ack are not put where the ClientHello goes, which then
gets its flight.
And before any of that: a SYN that says its client takes less than 216 bytes in a segment,
which is the smallest we cut ours to, is refused (a RST): nobody is sent more at a time
than they said (RFC 9293, 3.7.1).

And what it is for: a real client (this machine's TCP, Python's TLS) fetches the page;
then segments are sent in its name, with data and with FINs, where its sequence numbers
are with acks made up, and with its ack where its sequence numbers are not; then it
fetches the page again on the same connection. (Before these rules such bytes were taken
for the client's, the client's own then came second, and the connection was dead.)

    unshare -Urn ./tap.sh python3 tools/acktest.py        (the suite's `ack`; seconds)
"""
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hellofuzz import HOST, alive  # noqa: E402
from tlsclient import NAME, context, hello_record  # noqa: E402

TAP = os.environ.get("TAP", "k2t")
OURS = socket.inet_aton(HOST)
FAR = 1 << 19                   # what can have been on its way at once is less than this
M = 0xFFFFFFFF
failed = []


def check(what, ok, note=""):
    print(("ok   " if ok else "FAIL ") + what + (f": {note}" if note and not ok else ""), flush=True)
    if not ok:
        failed.append(what)


def csum(b):
    if len(b) & 1:
        b += b"\0"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(eth, src, sport, dport, flags, seq, ack, body=b"", opts=b""):
    th = struct.pack(">HHIIBBHHH", sport, dport, seq & M, ack & M, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    th = th[:16] + struct.pack(">H", csum(src + OURS + struct.pack(">BBH", 0, 6, len(th) + len(body)) + th + body)) + th[18:]
    ih = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(th) + len(body), 0, 0, 64, 6, 0, src, OURS)
    ih = ih[:10] + struct.pack(">H", csum(ih)) + ih[12:]
    return eth + ih + th + body


def parse(f):
    """(source, destination, their ports, flags, seq, ack, payload) of a frame of TCP over IPv4, or None"""
    if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
        return None
    at = 14 + (f[14] & 15) * 4
    off = (f[at + 12] >> 4) * 4
    end = 14 + int.from_bytes(f[16:18], "big")
    sport, dport, seq, ack = struct.unpack(">HHII", f[at:at + 12])
    return f[26:30], f[30:34], sport, dport, f[at + 13], seq, ack, f[at + off:end], f[at + 20:at + off]


def has_option(opts, want):
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts) or opts[i + 1] < 2 or i + opts[i + 1] > len(opts):
            break
        if kind == want and opts[i + 1] == 2:
            return True
        i += opts[i + 1]
    return False


class Raw:
    """A connection made of frames of our own, from an address nobody has."""
    ports = iter(range(52000, 53000))

    def __init__(self, s, mac, port, mss=1460, sack=False, wscale=False):
        self.s, self.port, self.sport = s, port, next(Raw.ports)
        self.eth = b"\xff" * 6 + mac + b"\x08\x00"
        self.src = socket.inet_aton("10.64.0.2")
        self.seq = 1000 * self.sport
        self.syn_options = b""
        opts = b"\x02\x04" + struct.pack(">H", mss) + (b"\x04\x02" if sack else b"")
        if wscale:
            opts += b"\x03\x03\x07"
        opts += b"\x01" * (-len(opts) % 4)
        syn_seq = self.seq
        self.seq += 1
        self.first = []
        for _ in range(3):                              # retry if the tap dropped a test SYN or reply
            self.send(0x02, 0, opts=opts, seq=syn_seq)
            self.first = self.got(1.0, first=True)      # (what the SYN got)
            if self.first:
                break
        syn = [g for g in self.first if g[0] & 0x12 == 0x12]
        self.iss = syn[0][1] if syn else None
        if syn:
            opts = self.syn_options
            got_sack = has_option(opts, 4)
            check("server advertises SACK receive support", got_sack)
            self.send(0x10, self.iss + 1)       # (the ack that makes the connection)
            self.got(0.05)

    def send(self, flags, ack, body=b"", opts=b"", seq=None):
        self.s.send(frame(self.eth, self.src, self.sport, self.port, flags, self.seq if seq is None else seq, ack, body, opts))

    def got(self, wait, first=False):
        """what the guest sent this connection within `wait` seconds: (flags, seq, ack, payload); SYN-ACKs sent again are left out"""
        out, end = [], time.time() + wait
        while time.time() < end:
            self.s.settimeout(max(end - time.time(), 0.001))
            try:
                p = parse(self.s.recv(65536))
            except TimeoutError:
                break
            if p and p[0] == OURS and p[1] == self.src and p[2] == self.port and p[3] == self.sport:
                if first:
                    self.syn_options = p[8]
                    return [p[4:-1]]
                if not p[4] & 2:
                    out.append(p[4:-1])
        return out

    def again(self, by):
        """The same client comes again: a SYN, `by` from where its sequence numbers were. Is it answered? (The answer's number is the new connection's.)"""
        self.seq += by
        self.send(0x02, 0, opts=b"\x02\x04\x05\xb4")
        self.seq += 1
        end = time.time() + 1.0
        while time.time() < end:                        # (the old connection's answer may come again first: nobody acknowledged it)
            for f, q, a, _ in self.got(end - time.time(), first=True):
                if f & 0x12 == 0x12 and a == self.seq & M:
                    self.iss = q
                    return True
        return False

    def refused(self, flags, ack, body=b"", seq=None):
        """Is a segment with this ack (where our sequence numbers are, or at `seq`) answered with acks that say we are where we were, and nothing else?"""
        self.send(flags, ack, body, seq=seq)
        g = self.got(0.3)
        return bool(g) and all(f == 0x10 and not data and a == self.seq and q == (self.iss + 1) & M for f, q, a, data in g), g

    def taken(self, body, ack=None, begins=b""):
        """Does this, with the right ack (or an old one), get an answer that begins so, which acknowledges it from where it was sent?"""
        for at in range(0, len(body), 1400):           # (a ClientHello can be longer than a frame)
            self.send(0x18, self.iss + 1 if ack is None else ack, body[at:at + 1400], seq=self.seq + at)
        g = self.got(0.5)
        data = b"".join(d for _, _, _, d in sorted(g, key=lambda x: (x[1] - self.iss) & M))
        acked = max(((a - self.seq) & M for _, _, a, _ in g), default=0)    # (all of it, or all but its last byte until we have the whole answer)
        return data.startswith(begins) and len(data) > 0 and acked in (len(body), len(body) - 1), g


def upto(c, g):
    """how many bytes of ours the client has, by these segments"""
    return max((((q - c.iss - 1) & M) + len(d) for _, q, _, d in g if d), default=0)


def gone(c, ack, seq, body):
    """Is a segment of the client's now told that there is no such connection (a RST and nothing else)?"""
    c.send(0x18, ack, body, seq=seq)
    g = c.got(0.3)
    return bool(g) and all(f & 4 and not d for f, _, _, d in g), g


def show(g):
    return "; ".join("flags %02x seq %d ack %d, %d bytes" % (f, q, a, len(d)) for f, q, a, d in g) or "nothing"


def framewise(s, mac):
    req = b"GET / HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n\r\n"
    for port in (80, 443):
        got = [Raw(s, mac, port, mss) for mss in (215, 88, 1, 0, 216)]
        check(f"port {port}: a SYN whose client takes less in a segment than our smallest (215, 88, 1, 0 bytes) is refused, with a RST for its number",
              all(len(c.first) == 1 and c.first[0][0] == 0x14 and c.first[0][2] == c.seq and not c.first[0][3] for c in got[:4]),
              "; ".join(show(c.first) for c in got[:4]))
        check("  and one that takes 216 is answered", got[4].iss is not None, show(got[4].first))
    for what, by in (("for what we never sent (by one byte)", 1), ("for what we never sent (by 2^28)", 1 << 28),
                     ("older than anything can be (by 2^19)", -FAR), ("older than anything can be (by 2^31 - 1)", -(1 << 31) + 1)):
        c = Raw(s, mac, 80)
        if c.iss is None:
            return check("port 80 answers a SYN of our own making", False)
        ok, g = c.refused(0x18, c.iss + 1 + by, req)
        check(f"port 80: a request whose ack is {what} gets an ack and nothing else", ok, show(g))
        ok, g = c.taken(req, begins=b"HTTP/1.1 ")
        check("  and the request with the client's ack then gets its response: nothing had been taken", ok, show(g))
    c = Raw(s, mac, 80)
    ok, g = c.taken(req, ack=c.iss + 1 - FAR + 1, begins=b"HTTP/1.1 ")
    check("port 80: one whose ack is old by less than can have been on its way (2^19 - 1) is a packet that was overtaken: answered", ok, show(g))
    c = Raw(s, mac, 80)
    ok, g = c.refused(0x11, c.iss + 1 + 5000)
    check("port 80: a FIN whose ack is not the client's gets an ack and nothing else", ok, show(g))
    ok, g = c.taken(req, begins=b"HTTP/1.1 ")
    check("  and the connection is still there: the request gets its response", ok, show(g))
    # after a SYN for a connection we have: a new one may take its place, but only with the cookie of that SYN's answer
    c = Raw(s, mac, 80)
    c.send(0x02, 0, opts=b"\x02\x04\x05\xb4", seq=c.seq + 77777)
    c.got(0.1)
    ok, g = c.refused(0x18, c.iss + 1 + 5000, req)
    check("port 80: after a SYN has come again for it, a request whose ack is neither the client's nor that SYN's answer gets an ack and nothing else", ok, show(g))
    ok, g = c.taken(req, begins=b"HTTP/1.1 ")
    check("  and the connection is as it was: the request gets its response", ok, show(g))
    # the client comes again from the same port, while we have its connection: a new one in its place
    for what, by in (("far from where its sequence numbers were", 1 << 28), ("among its old sequence numbers", 5)):
        c = Raw(s, mac, 80)
        ok, g = c.taken(req, begins=b"HTTP/1.1 ")
        old = c.iss
        if ok:                                          # (it has the answer and says so: nothing of the old connection is on its way)
            c.send(0x10, c.iss + 1 + max(((q - c.iss - 1) & M) + len(d) for _, q, _, d in g if d), seq=c.seq + len(req))
            c.got(0.05)
        if not (ok and c.again(by)):
            check(f"port 80: a SYN for a connection we have, {what}, gets its answer", False)
            continue
        ok, g = c.taken(req, begins=b"HTTP/1.1 ")
        first = min(((q - c.iss) & M for _, q, _, d in g if d), default=None)   # (a new connection's answer begins right behind its SYN-ACK)
        check(f"port 80: a client that comes again from the same port, {what}, is a new connection in the old one's place",
              ok and c.iss != old and first == 1, show(g))
    # where the client's sequence numbers are not, with the right ack: its ack must not count
    c = Raw(s, mac, 80)
    c.send(0x18, c.iss + 1, b"\n\n" * 600)              # 600 requests: 4 KiB of answers go, the rest wait for an ack
    g = c.got(0.3)
    n = sum(len(d) for _, _, _, d in g)
    if not 0 < n <= 4096:
        return check("port 80 sends up to 4 KiB of answers and waits for an ack", False, show(g))
    ours, sent = c.iss + 1 + n, c.seq + 1200            # (what the client has of us; what it has sent)
    for what, seq in (("a megabyte further on than the client is", sent + (1 << 20)), ("a megabyte before", sent - (1 << 20)),
                      ("half the numbers there are away", sent + (1 << 31))):
        c.send(0x10, ours, seq=seq)
        g = c.got(0.3)
        check(f"port 80: an ack for all we sent, with a sequence number {what}, lets nothing go (an ack comes back)",
              bool(g) and all(f == 0x10 and not d for f, _, _, d in g), show(g))
    for what, seq in (("from a little before what we expect (a byte sent again)", c.seq), ("from where the client is", sent)):
        c.send(0x10, ours, seq=seq)
        g = c.got(0.3)
        more = sum(len(d) for _, _, _, d in g)
        check(f"  the client's ack, {what}, lets the next 4 KiB go", 0 < more <= 4096, show(g))
        ours += more
    # a RST: one number ends a connection
    c = Raw(s, mac, 80)
    ok, g = c.taken(req, begins=b"HTTP/1.1 ")
    if ok:
        ours = c.iss + 1 + upto(c, g)
        c.seq += len(req)
        for by in (-1, 1, 1 << 31):
            c.send(0x04, 0, seq=c.seq + by)
        c.got(0.05)
        ok, g = c.taken(req, ack=ours, begins=b"HTTP/1.1 ")
        check("port 80: a RST a byte before what we expect, a byte behind it, or half the numbers there are away is not taken: the next request "
              "gets its response", ok, show(g))
        ours = c.iss + 1 + upto(c, g)
        c.seq += len(req)
        c.send(0x04, 0)
        c.got(0.05)
        ok, g = gone(c, ours, c.seq, req)
        check("port 80: a RST at what we expect is the connection's end: the next request is told that there is none", ok, show(g))
    else:
        check("port 80 answers a request (before the RSTs)", False, show(g))
    for what, rsts, stays in (("where the client's own numbers are (a byte behind what our acks say), or two bytes before", (0, 1, -2, 1 << 31), True),
                              ("where our acks say we are", (-1,), False)):
        c = Raw(s, mac, 80)
        c.send(0x18, c.iss + 1, b"\n\n" * 600)          # an answer of several segments: 4 KiB of it go
        g = c.got(0.2)
        n = upto(c, g)
        if not (0 < n <= 4096 and len({a for _, _, a, _ in g}) == 1):
            check("port 80 sends up to 4 KiB of answers, in segments that all acknowledge the same", False, show(g))
            continue
        sent = g[0][2] + 1                              # (what we have taken: a byte more than those acks say)
        for by in rsts:
            c.send(0x14 if by == 0 else 0x04, c.iss + 1 + n, seq=sent + by)
        c.got(0.05)
        if stays:
            c.send(0x10, c.iss + 1 + n, seq=sent)
            g = c.got(0.3)
            check(f"port 80: while our acks hold the client's last byte back, a RST {what}, is not taken: the client's ack lets the next 4 KiB go",
                  0 < sum(len(d) for _, _, _, d in g) and not any(f & 4 for f, _, _, _ in g), show(g))
        else:
            ok, g = gone(c, c.iss + 1 + n, sent, b"\n")
            check(f"port 80: while our acks hold the client's last byte back, a RST {what} is the connection's end", ok, show(g))
    c = Raw(s, mac, 80)
    ok, g = c.taken(req, begins=b"HTTP/1.1 ")
    first = b"".join(d for _, _, _, d in g)
    single = ok and len(g) == 1 and 0 < len(first) <= 1460
    if single:
        ours = c.iss + 1 + upto(c, g)
        c.seq += len(req)
        second_seq = c.seq
        c.send(0x18, c.iss + 1, req, seq=second_seq)
        c.got(0.05)
        c.send(0x10, ours, seq=second_seq)
        resumed = c.got(0.3)
        body = b"".join(d for _, _, _, d in resumed)
        check("port 80: a pipelined request resumes as soon as the one-segment response is acknowledged",
              body.startswith(b"HTTP/1.1 "), show(resumed))
    else:
        check("port 80: pipeline setup gets a one-segment first response", False, show(g))
    c = Raw(s, mac, 443)
    ok, g = c.refused(0x18, c.iss + 1 + 5000, bytes([22, 3, 1, 0, 200]) + bytes(60))
    check("port 443: bytes whose ack is not the client's get an ack and nothing else", ok, show(g))
    ok, g = c.taken(hello_record(), begins=b"\x16\x03\x03")
    check("  and the ClientHello that follows gets its flight", ok, show(g))


def real_client(s, mac):
    src = "10.0.2.34"
    t = context().wrap_socket(socket.create_connection((HOST, 443), timeout=5, source_address=(src, 0)), server_hostname=NAME)
    sport = t.getsockname()[1]

    def fetch():
        got = b""
        try:
            t.sendall(b"GET / HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n\r\n")
            while b"\r\n\r\n" not in got:
                more = t.recv(65536)
                if not more:
                    break
                got += more
            head, _, body = got.partition(b"\r\n\r\n")
            n = int(dict(line.lower().split(b": ", 1) for line in head.split(b"\r\n")[1:])[b"content-length"])
            while len(body) < n:
                more = t.recv(65536)
                if not more:
                    break
                body += more
            return got.startswith(b"HTTP/1.1 200") and len(body) == n
        except (OSError, ValueError, KeyError):
            return False

    # where the connection is: its last frames, either way, as they pass the tap
    s.settimeout(0.01)
    try:
        while True:
            s.recv(65536)
    except TimeoutError:
        pass
    check("a real client fetches the page", fetch())
    cnext = snext = guest = None
    end = time.time() + 0.3
    while time.time() < end:
        s.settimeout(max(end - time.time(), 0.001))
        try:
            f = s.recv(65536)
        except TimeoutError:
            break
        p = parse(f)
        if not p:
            continue
        if p[0] == socket.inet_aton(src) and p[2] == sport:
            cnext, guest = (p[5] + len(p[7])) & M, f[0:6]
        elif p[1] == socket.inet_aton(src) and p[3] == sport:
            snext = (p[5] + len(p[7])) & M
    if cnext is None or snext is None:
        return check("  (its frames were seen on the tap)", False)
    eth = guest + mac + b"\x08\x00"
    n = 0
    for flags, body in ((0x18, bytes([23, 3, 3, 0, 35]) + bytes(35)), (0x11, b""), (0x18, b"x" * 700)):
        for seq, ack in ((cnext, snext + 1), (cnext, snext + 70000), (cnext, snext - FAR), (cnext, snext + (1 << 31)),
                         (cnext + (1 << 20), snext), (cnext - (1 << 20), snext), (cnext + (1 << 31), snext)):
            s.send(frame(eth, socket.inet_aton(src), sport, 443, flags, seq, ack, body))
            n += 1
    time.sleep(0.2)
    check(f"  and again on the same connection, after {n} segments in its name that are not its own (data and FINs: its sequence numbers "
          "with acks made up, its ack with sequence numbers made up)", fetch())
    t.close()


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((TAP, 0))
    mac = s.getsockname()[4]
    framewise(s, mac)
    Raw(s, mac, 443, sack=True)
    Raw(s, mac, 443, sack=True, wscale=True)
    real_client(s, mac)
    check("the machine is there", alive())
    print("all ok" if not failed else f"FAILED: {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
