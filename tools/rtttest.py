#!/usr/bin/env python3
"""The timer for what we sent goes by the connection's round trip:

    B=build-site DELAY=300 unshare -Urn ./tap.sh python3 tools/rtttest.py     (half a minute)

With a round trip of 300 ms (what goes to the guest is held that long), nothing is lost,
and so nothing may be sent twice: not a page of one segment whose ack the client holds
back for a while (a connection that stays, asked four times), not the first segments of a
file of a hundred. A timer of a quarter of a second, which is what there was whatever the
round trip, sends the segment at the client's ack again before that ack can have come,
and halves what may be on its way for the rest of the connection. (What is sent again
when something is lost is the lossy runs' to see. What the handshake does is not looked
at here: a SYN-ACK is sent again after a quarter of a second, to a client of which
nothing is known yet; this client then acknowledges twice, and that looks like a loss
to the flight, which goes twice as well.)
"""
import json
import os
import socket
import struct
import sys
import threading
import time

os.environ.setdefault("B", "build-site")
from tlsclient import B, NAME, context  # noqa: E402

GUEST, SRC = "10.0.2.15", "10.0.2.32"
SITE = json.load(open(f"{B}/site.json"))["paths"]
again = {}          # the client's port -> segments of ours that came a second time
top = {}            # the client's port -> the sequence number behind the furthest byte seen
stop = False


def sniff():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind((os.environ.get("TAP", "k2t"), 0))
    s.settimeout(0.2)
    g = socket.inet_aton(GUEST)
    while not stop:
        try:
            f = s.recv(70000)
        except socket.timeout:
            continue
        if len(f) < 54 or f[23] != 6 or f[26:30] != g or f[14] != 0x45:
            continue
        total, = struct.unpack_from(">H", f, 16)
        port, seq = struct.unpack_from(">HI", f, 36)
        n = total - 20 - (f[46] >> 4) * 4
        if n <= 0 or f[47] & 2 or f[14 + total - n:][:3] == b"\x16\x03\x03":   # (a flight is not looked at: below)
            continue
        if port in top and ((seq - top[port]) & 0xFFFFFFFF) >= 1 << 31:    # (it begins before what we have seen)
            again[port] = again.get(port, 0) + 1
        if port not in top or ((seq + n - top[port]) & 0xFFFFFFFF) < 1 << 31:
            top[port] = (seq + n) & 0xFFFFFFFF


def connect():
    raw = socket.socket()
    raw.bind((SRC, 0))
    raw.settimeout(20)
    raw.connect((GUEST, 443))
    return context().wrap_socket(raw, server_hostname=NAME)


def get(c, path):
    c.sendall(f"GET {path} HTTP/1.1\r\nHost: {NAME}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += c.recv(65536)
    head, body = buf.split(b"\r\n\r\n", 1)
    want = int([line for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")][0].split(b":")[1])
    while len(body) < want:
        body += c.recv(65536)
    return len(body)


t = threading.Thread(target=sniff, daemon=True)
t.start()
time.sleep(0.3)
small = min((p for p in SITE if SITE[p]["status"] == 200 and 0 < SITE[p]["length"] < 1000), key=lambda p: SITE[p]["length"])
large = max((p for p in SITE if SITE[p]["status"] == 200 and SITE[p]["length"] < 400000), key=lambda p: SITE[p]["length"])
bad = 0
t0 = time.time()
c = connect()
hs = time.time() - t0
for _ in range(4):
    get(c, small)
    time.sleep(0.7)
c.close()
t0 = time.time()
c = connect()
n = get(c, large)
took = time.time() - t0
c.close()
for _ in range(3):
    c = connect()
    get(c, small)
    c.close()
time.sleep(1.2)
stop = True
t.join()
print(f"a handshake took {hs:.2f} s; {large} ({n} bytes) took {took:.2f} s with it")
if hs < 0.5:
    print("FAIL: that is no round trip of 300 ms: DELAY=300 in front of tap.sh")
    bad = 1
total = sum(again.values())
print(("ok   " if not total else "FAIL ") + f"nothing was lost, and of {len(top)} connections' segments {total} were sent twice")
sys.exit(1 if bad or total else 0)
