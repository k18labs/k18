#!/usr/bin/env python3
"""rawtest.py [SEED]: frames that no router would pass on, put on the wire next to the guest.

What a client's TCP sends is well-formed below TCP, and a router drops what is not. A
sender on the same link is held to nothing. So: frames whose IP header says a total
length of less than itself (0 to 39 bytes, where 40 is the least there can be: with a TCP
header behind them, with bytes drawn at random, and, for the lengths where the image once
went on to sum a few bytes, with a source address that makes those sum right), frames
that end in the middle of their headers, total lengths beyond the frame, IP headers with
options, TCP headers that say they are shorter than 20 bytes or longer than what is
there, and frames of every such kind with the rest drawn at random.

What must hold: the machine is still there (a fault is its end: QEMU, which tap.sh
starts with -no-reboot, is then gone) and serves a real client as before.

    unshare -Urn ./tap.sh python3 tools/rawtest.py        (the suite's `rawframes`; seconds)

(Until 2026-11-14 a total length below 20 passed for 4 GiB: its length less 20 was
compared, not it. The first such frame was the machine's end.)
"""
import os
import random
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hellofuzz import alive, real, HOST  # noqa: E402

SEED = int(sys.argv[1]) if len(sys.argv) > 1 else 1
TAP = os.environ.get("TAP", "k2t")
OURS = socket.inet_aton(HOST)


def ip(total, src, ihl=0x45, proto=6, frag=0):
    return struct.pack(">BBHHHBBH4s4s", ihl, 0, total & 0xFFFF, 0, frag, 64, proto, 0, src, OURS)


def tcp(sport, flags=0x02, off=0x50, seq=1, ack=0):
    return struct.pack(">HHIIBBHHH", sport, 443, seq, ack, off, flags, 65535, 0, 0)


def sums_right(total):
    """A source address with which the bytes the image summed for such a length (the
    pseudo header's first total - 8, in words) came to nothing: the way past its check."""
    n = (total - 8 + 1) // 2
    for low in range(65536):
        src = bytes([10, 0, low >> 8, low & 255])
        head = bytes([0, 6]) + struct.pack(">H", (total - 20) & 0xFFFF) + src + OURS
        s = sum(struct.unpack("<%dH" % n, head[:2 * n]))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        if s == 0xFFFF:
            return src
    return None


def csum(b):
    if len(b) & 1:
        b += b"\0"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def seg80(eth, src, sport, flags, seq, ack, body=b"", opts=b""):
    th = struct.pack(">HHIIBBHHH", sport, 80, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    th = th[:16] + struct.pack(">H", csum(src + OURS + struct.pack(">BBH", 0, 6, len(th) + len(body)) + th + body)) + th[18:]
    ih = ip(20 + len(th) + len(body), src)
    ih = ih[:10] + struct.pack(">H", csum(ih)) + ih[12:]
    return eth + ih + th + body


def plain_bound(s, eth):
    """600 empty lines in one segment to port 80, then duplicate 54-byte acks: neither may
    draw more than 4 KiB (before 2026-11-14 each drew up to 256 KiB)."""
    src, sport = socket.inet_aton("10.64.0.1"), 51000

    def drain(wait=0.1):
        s.settimeout(wait)
        got, gseq, gack = 0, None, None
        while True:
            try:
                f = s.recv(65536)
            except TimeoutError:
                break
            if len(f) >= 54 and f[12:14] == b"\x08\x00" and f[23] == 6 and f[26:30] == OURS and f[30:34] == src:
                ihl = 14 + (f[14] & 15) * 4
                if int.from_bytes(f[ihl + 2:ihl + 4], "big") == sport:
                    off = (f[ihl + 12] >> 4) * 4
                    tot = 14 + int.from_bytes(f[16:18], "big")
                    got += max(0, min(len(f), tot) - ihl - off)
                    gseq = int.from_bytes(f[ihl + 4:ihl + 8], "big")
                    gack = int.from_bytes(f[ihl + 8:ihl + 12], "big")
        s.settimeout(None)
        return got, gseq, gack

    s.send(seg80(eth, src, sport, 0x02, 1000, 0, opts=b"\x02\x04\x05\xb4"))
    _, iss, _ = drain(0.5)
    if iss is None:
        return "port 80 did not answer a raw SYN"
    s.send(seg80(eth, src, sport, 0x18, 1001, (iss + 1) & 0xFFFFFFFF, b"\n\n" * 600))
    first, _, gack = drain(0.15)
    if not (0 < first <= 4096):
        return "port 80 sent %d bytes unacknowledged (expected 1..4096)" % first
    # Duplicate 54-byte acks at the guest's C_NXT (F_DEFER withheld 1 byte from gack)
    for _ in range(2):
        s.send(seg80(eth, src, sport, 0x10, (gack + 1) & 0xFFFFFFFF, (iss + 1) & 0xFFFFFFFF))
        again, _, _ = drain(0.15)
        if not (0 < again <= 4096):
            return "port 80 resent %d bytes on duplicate ack (expected 1..4096)" % again
    return None


def arp_whole(s, mac):
    """An ARP request for our address gets its reply; one cut short gets none, whatever the
    frame before it left behind it (before 2026-11-21 the 14 bytes of an ARP frame's
    Ethernet header, sent after a whole request, were answered as that request)."""
    whole = b"\xff" * 6 + mac + b"\x08\x06" + bytes.fromhex("0001080006040001") + mac + socket.inet_aton("10.0.2.2") + bytes(6) + OURS

    def replies(frame):
        s.send(whole)
        s.send(frame)
        s.settimeout(0.3)
        n = 0
        while True:
            try:
                f = s.recv(65536)
            except TimeoutError:
                break
            n += f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02" and f[28:32] == OURS
        s.settimeout(None)
        return n

    if replies(whole) != 2:
        return "a whole ARP request for our address was not answered"
    for n in range(14, 42):
        if replies(whole[:n]) != 1:
            return "an ARP frame of %d bytes was answered" % n
    return None


def main():
    rng = random.Random(SEED)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((TAP, 0))
    eth = b"\xff" * 6 + s.getsockname()[4] + b"\x08\x00"
    src = socket.inet_aton("10.0.2.34")
    frames = []
    for total in range(40):                             # a total length that is too short
        frames.append(eth + ip(total, src) + tcp(40000 + total) + bytes(6))
        frames.append(eth + ip(total, src) + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))))
        if 13 <= total <= 19 and sums_right(total):
            for flags in (0x02, 0x10, 0x18, 0x11, 0x04):
                frames.append(eth + ip(total, sums_right(total)) + tcp(41000 + total, flags) + bytes(64))
    whole = eth + ip(60, src) + tcp(42000) + bytes(20)
    frames += [whole[:n] for n in range(14, len(whole))]  # frames that end in their headers
    for total in (41, 60, 61, 100, 1500, 2000, 4000, 65535):    # total lengths beyond the frame
        frames.append(eth + ip(total, src) + tcp(43000) + bytes(8))
    for ihl in (0x40, 0x44, 0x46, 0x4F, 0x55, 0x65):    # other headers than ours
        frames.append(eth + ip(60, src, ihl=ihl) + tcp(44000) + bytes(40))
    for off in (0x00, 0x10, 0x40, 0x60, 0xA0, 0xF0):    # TCP headers of other lengths than they have
        frames.append(eth + ip(40, src) + tcp(45000, off=off))
        frames.append(eth + ip(44, src) + tcp(45001, off=off) + bytes(4))
    for _ in range(3000):                               # and all of it with the rest at random
        f = bytearray(rng.choice(frames))
        for _ in range(rng.choice((1, 2, 4, 16))):
            if len(f) > 14:
                f[rng.randrange(14, len(f))] = rng.randrange(256)
        if rng.random() < 0.5:
            f[16:18] = rng.choice((b"\0\0", b"\0\x13", b"\0\x14", b"\0\x27", b"\0\x28", bytes([rng.randrange(256), rng.randrange(256)])))
        frames.append(bytes(f))
    print("seed %d, %d frames" % (SEED, len(frames)), flush=True)
    for i, f in enumerate(frames):
        s.send(f)
        if i % 200 == 199:
            time.sleep(0.05)
            if not alive():
                print("FAIL: the machine was gone after frame %d: %s" % (i, f[:54].hex()))
                return 1
    time.sleep(0.3)
    why = arp_whole(s, eth[6:12]) or plain_bound(s, eth)
    if why:
        print("FAIL:", why)
        return 1
    ok = alive() and real()
    print("ok: the machine is there, a short ARP frame gets no answer, port 80 is bounded, and it serves as before" if ok else "FAIL: the machine no longer serves (seed %d)" % SEED)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
