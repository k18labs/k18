#!/usr/bin/env python3
"""Do connections that end give their slots back? Run against an image with small tables
(`make B=build-small CAP=1024`: 1024 slots each), over tap:

    B=build-small unshare -Urn ./tap.sh python3 tools/churn.py [HELD] [LOOPS]

Opens HELD connections (default 64) and fetches the page over each. Then LOOPS times
(default 4000, several times the table) a connection comes and goes: in turn a fetch and a
clean close, a fetch and a reset, a handshake only, a TCP connection that says nothing, and
one that sends junk. Then fetches again over the HELD ones. If ended connections kept
their slots, the table would fill and the new ones would be refused (this then stops with
a connection error). With FLOOD=N, tools/flood.py sends N SYNs, N acks and N data segments
from made-up clients before that last round: none of them may get a slot either.
"""
import os
import socket
import struct
import sys
import time

from tlsclient import B as BUILD, NAME, context

DST = (os.environ.get("DST", "10.0.2.15"), int(os.environ.get("DPORT", "443")))
SRC = os.environ.get("SRC", "10.0.2.32")
EXPECT = open(os.path.join(BUILD, "..", "www", "index.html"), "rb").read()
REQ = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
CTX = context()
KINDS = [int(k) for k in os.environ.get("KINDS", "01234")]  # which of the five ways to go


def tcp():
    s = socket.socket()
    s.settimeout(10)
    s.bind((SRC, 0))
    s.connect(DST)
    return s


def tls():
    return CTX.wrap_socket(tcp(), server_hostname=NAME)


def fetch(c):
    c.sendall(REQ)
    buf = b""
    while not buf.endswith(EXPECT):
        got = c.recv(4096)
        if not got:
            raise ConnectionError("closed")
        buf += got


def reset(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def main():
    held_n = int(sys.argv[1]) if len(sys.argv) > 1 else 64
    loops = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
    held = [tls() for _ in range(held_n)]
    for c in held:
        fetch(c)
    t = time.time()
    for i in range(loops):
        kind = KINDS[i % len(KINDS)]
        if kind == 0:
            c = tls()
            fetch(c)
            c.close()
        elif kind == 1:
            c = tls()
            fetch(c)
            reset(c)
        elif kind == 2:
            tls().close()
        elif kind == 3:
            s = tcp()
            time.sleep(0.001)   # (so that its ack is out before its FIN)
            s.close()
        else:
            s = tcp()
            s.sendall(os.urandom(100))
            s.close()
    dt = time.time() - t
    if os.environ.get("FLOOD"):
        import flood
        n = int(os.environ["FLOOD"])
        print(f"flood: {3 * n} packets from clients that don't exist in {flood.flood(n):.1f} s")
        fetch(tls())            # (and it still takes new connections)
    bad = 0
    for c in held:
        try:
            fetch(c)
        except (OSError, ssl.SSLError):
            bad += 1
    print(f"{loops} connections came and went in {dt:.0f} s; {held_n - bad} of {held_n} held connections still served")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
