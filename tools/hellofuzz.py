#!/usr/bin/env python3
"""hellofuzz.py [N] [SEED]: ClientHellos with something wrong in them, N of them (20,000).

What a client sends before it has proved anything is what `handshake` walks: the
ClientHello's lengths, its session id, its suites, its extensions and the key shares in
them. Every length there is the client's. tlsfuzzer asks about the mistakes people make
(tools/tlsfuzz.sh); this asks about the ones nobody would think of: a real ClientHello,
as OpenSSL makes it, with bytes changed at random, lengths set to what they are not, cut
short, grown, parts of it copied over other parts; the record's own length and the
message's are put right again most of the time, so that what is wrong lies further in.

What must hold: the server answers every one with something or with nothing, and goes on
serving. After every 500, a real client makes a connection and gets the page (chain and
name verified), and the machine has not been reset (a fault is its end: QEMU, started
with -no-reboot by tap.sh, is then gone).

    unshare -Urn ./tap.sh python3 tools/hellofuzz.py        (the suite's `hellofuzz`; a minute)

SEED (default: the time) is printed, and with it a run can be had again.
"""
import collections
import os
import random
import socket
import sys
import time

from tlsclient import HRR, NAME, context, hello_record

HOST = os.environ.get("HOST", "10.0.2.15")
PORT = int(os.environ.get("PORT", "443"))
SRC = os.environ.get("SRC", "10.0.2.33")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else int(time.time())


def hello(groups=None):
    return bytearray(hello_record(groups=groups))


def wrong(rng, rec):
    """The record with something wrong in it."""
    m = bytearray(rec[5:])
    for _ in range(rng.choice((1, 1, 1, 2, 3))):
        how = rng.randrange(8)
        at = rng.randrange(len(m)) if m else 0
        if how == 0 and m:                              # some bits
            for _ in range(rng.choice((1, 1, 2, 8))):
                m[rng.randrange(len(m))] ^= 1 << rng.randrange(8)
        elif how == 1 and m:                            # a byte
            m[at] = rng.choice((0, 1, 0x7F, 0x80, 0xFF, rng.randrange(256)))
        elif how == 2 and len(m) > 1:                   # two bytes that may be a length
            at = rng.randrange(len(m) - 1)
            m[at:at + 2] = rng.choice((b"\0\0", b"\0\1", b"\xff\xff", b"\x7f\xff", b"\x80\0", bytes([rng.randrange(256), rng.randrange(256)]),
                                       (len(m) - at).to_bytes(2, "big"), (len(m) - at - 2).to_bytes(2, "big")))
        elif how == 3:                                  # cut short
            del m[at:]
        elif how == 4:                                  # grown
            m += bytes(rng.randrange(256) for _ in range(rng.choice((1, 2, 4, 40, 300, 2000))))
        elif how == 5 and m:                            # a part of it over another part
            n = rng.randrange(1, 40)
            src = rng.randrange(len(m))
            m[at:at + n] = m[src:src + n]
        elif how == 6 and m:                            # a part of it twice
            n = rng.randrange(1, 60)
            m[at:at] = m[at:at + n]
        elif m:                                         # a part of it gone
            del m[at:at + rng.randrange(1, 60)]
    if len(m) >= 4 and rng.random() < 0.8:              # (the message's own length, right again)
        m[1:4] = (len(m) - 4).to_bytes(3, "big")
    head = bytearray(rec[:5])
    if rng.random() < 0.85:                             # (and the record's)
        head[3:5] = (len(m) & 0xFFFF).to_bytes(2, "big")
    elif rng.random() < 0.5:
        head[rng.randrange(5)] = rng.randrange(256)
    return bytes(head + m)


def real():
    """A real client: a connection, the page."""
    s = socket.create_connection((HOST, PORT), timeout=10, source_address=(SRC, 0))
    t = context().wrap_socket(s, server_hostname=NAME)
    t.sendall(b"GET / HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n\r\n")
    got = b""
    while b"\r\n\r\n" not in got:
        more = t.recv(65536)
        if not more:
            break
        got += more
    t.close()
    return got.startswith(b"HTTP/1.1 200")


def wrong_extension_vector(rec, delta):
    """Change only the ClientHello extensions vector length, leaving message lengths intact."""
    packet = bytearray(rec)
    msg = packet[5:]
    if len(msg) < 44 or msg[0] != 1:
        raise ValueError("not a complete ClientHello")
    at = 4 + 2 + 32
    at += 1 + msg[at]                         # session ID
    suites = int.from_bytes(msg[at:at + 2], "big")
    at += 2 + suites
    at += 1 + msg[at]                         # compression methods
    if at + 2 > len(msg):
        raise ValueError("ClientHello has no extensions length")
    length = int.from_bytes(msg[at:at + 2], "big")
    if at + 2 + length != len(msg) or not 0 <= length + delta <= 0xFFFF:
        raise ValueError("unexpected ClientHello layout")
    packet[5 + at:7 + at] = (length + delta).to_bytes(2, "big")
    return bytes(packet)


def accepts_bad_extension_vector(rec, delta):
    """Whether the server sends a ServerHello for a malformed extension vector."""
    s = socket.create_connection((HOST, PORT), timeout=5, source_address=(SRC, 0))
    s.settimeout(1)
    try:
        s.sendall(wrong_extension_vector(rec, delta))
        try:
            reply = s.recv(8192)
        except socket.timeout:
            reply = b""
        return reply.startswith(b"\x16"), reply
    finally:
        s.close()


def alive():
    pid = os.environ.get("QEMU_PID")
    return not pid or os.path.exists("/proc/%s" % pid)


def main():
    rng = random.Random(SEED)
    print("seed %d, %d ClientHellos" % (SEED, N), flush=True)
    base = [hello(), hello("X25519"), hello("prime256v1")]      # (two key shares, ours alone, one that is not ours)
    for delta in (-1, 1):
        accepted, reply = accepts_bad_extension_vector(base[0], delta)
        if accepted:
            print("FAIL: accepted a ClientHello whose extensions length differs by %+d byte(s)" % delta)
            return 1
        print("ok: extensions length %+d byte(s): no ServerHello (%s)" %
              (delta, "alert" if reply.startswith(b"\x15") else "closed or ignored"), flush=True)
    said = collections.Counter()
    t0 = time.time()
    for i in range(N):
        if i % 500 == 0 and not (alive() and real()):
            print("FAIL: after %d of them the server no longer serves (seed %d)" % (i, SEED))
            return 1
        rec = wrong(rng, rng.choice(base))
        try:
            s = socket.create_connection((HOST, PORT), timeout=5, source_address=(SRC, 0))
        except OSError as e:
            said["no connection: %s" % type(e).__name__] += 1
            continue
        try:
            s.sendall(rec)
            if rng.random() < 0.1:                      # (and sometimes more behind it)
                s.sendall(wrong(rng, rng.choice(base)))
            s.settimeout(0.02 if rng.random() < 0.9 else 0.3)
            got = s.recv(8192)
            if not got:
                said["closed"] += 1
            elif got[0] == 21:
                said["alert %d" % got[6]] += 1
            elif got[0] == 22 and len(got) > 43 and got[11:43] == HRR:
                said["asked for a key share"] += 1
            elif got[0] == 22:
                said["a ServerHello"] += 1
            else:
                said["something else (%d)" % got[0]] += 1
        except socket.timeout:
            said["nothing"] += 1
        except OSError:
            said["reset"] += 1
        finally:
            s.close()
    ok = alive() and real()
    print("%d in %.0f s. The answers: %s" % (N, time.time() - t0, ", ".join("%s: %d" % kv for kv in said.most_common())))
    print("ok: and the server serves as before" if ok else "FAIL: the server no longer serves (seed %d)" % SEED)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
