#!/usr/bin/env python3
"""racetest.py N: a slot that changes hands while its connection's timer has it in hand.

A connection that waits for an ack is looked at by its processor's timer (`tqrun`), not
only when a packet of its client's comes. And a slot whose connection has long been quiet
is another processor's to take when there is no room (`find`). Both at once must leave
one of the two with nothing: the timer, if the slot was taken before it said "in use"
(N = 1), or the taker, if it comes after (N = 2). In a real machine the two meet within
nanoseconds, if ever; an image built with RACE=N holds the timer still at that point for
up to 30 s (see RACEWAIT in src/os.asm), so that they do meet. Run by tools/racetest.sh:

    unshare -Urn tools/racetest.sh 1        (and 2; three to four minutes each; 3 is
                                            another matter: see `gone` below)

The table for TLS has 32 slots. One is X's, which asks for the large file and vanishes in
the middle of it (what it sends from then on is dropped on its way out); 31 are held by
connections that say something every 5 s. Once X has been quiet for two units of 64 s it
may be taken, and the timer, which looks at X every 16 s, stops when it sees that. Then
new connections are tried until one gets in.
  N = 1: it gets in at once, in X's place. The timer finds that out when it goes on.
  N = 2: none gets in while the timer has X: its slot says "in use". The timer then gives
         X up (a reset, seen on the wire), and after that one gets in.
Either way: from the moment the server answers the SYN of the one that gets in, nothing
more may be sent to X (the timer going on with a slot that is another's by then sends
that one's records, or a reset with its numbers, to X); the one that got in gets the
large file, whole, and the page after it; and the 31 are all still there.
"""
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time

os.environ.setdefault("HOST", "10.0.2.15")
os.environ.setdefault("PORT", "443")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sitecheck  # noqa: E402 (after the environment it reads)
from sitecheck import Conn, same, SITE, HOST  # noqa: E402

N = sys.argv[1] if len(sys.argv) > 1 else "1"
X_SRC, Y_SRC, K_SRC = "10.0.2.40", "10.0.2.36", ["10.0.2.33", "10.0.2.34"]
UNIT = 64


def guest_zero():
    """When the guest's clock was 0: when its QEMU was started, to a few tenths of a second."""
    stat = open("/proc/%s/stat" % os.environ["QEMU_PID"]).read().rsplit(")", 1)[1].split()
    up = float(open("/proc/uptime").read().split()[0])
    return time.time() - (up - int(stat[19]) / os.sysconf("SC_CLK_TCK"))


def keeper(i):
    s = socket.socket()
    s.bind((K_SRC[i % len(K_SRC)], 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 30)
    s.settimeout(3)
    try:
        s.connect((HOST, 443))
    except OSError:                     # (refused: no room)
        s.close()
        return None
    return s


def there(socks):
    """How many of these connections the server still has: each says a byte, which is the
    start of a record to a connection, and gets a reset where there is none."""
    for s in socks:
        try:
            s.send(b"\x16")
        except OSError:
            pass
    time.sleep(1)
    n = 0
    for s in socks:
        s.setblocking(False)
        try:
            s.recv(1)
        except BlockingIOError:
            n += 1
        except OSError:
            pass
    return n


def main():
    paths = SITE["paths"]
    big = max(paths, key=lambda p: paths[p]["length"])
    to_x = []                           # (when, flags, bytes) of every segment the server sends X
    synack = {}                         # when the server first answered a SYN from Y's port

    def watch():
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        a, b, c = socket.inet_aton(HOST), socket.inet_aton(X_SRC), socket.inet_aton(Y_SRC)
        while True:
            f = s.recv(65536 + 64)
            if f[23] != 6 or f[26:30] != a:
                continue
            ip = 14 + (f[14] & 15) * 4
            if f[30:34] == b:
                to_x.append((time.time(), f[ip + 13], len(f) - ip - (f[ip + 12] >> 4) * 4))
            elif f[30:34] == c and f[ip + 13] & 0x12 == 0x12:
                synack.setdefault(int.from_bytes(f[ip + 2:ip + 4], "big"), time.time())

    threading.Thread(target=watch, daemon=True).start()
    t0 = guest_zero()
    x = Conn(src=X_SRC)
    keepers, refused, i = [], 0, 0
    while refused < 12 and i < 400:     # until a dozen in a row find no room
        s = keeper(i)
        i += 1
        if s:
            keepers.append(s)
            refused = 0
        else:
            refused += 1
    print("X and %d others hold the table, then no room" % len(keepers), flush=True)
    if len(keepers) != 31:
        return "the table should hold 32"
    while not 20 <= (time.time() - t0) % UNIT <= 40:    # (well inside a unit of the guest's clock)
        time.sleep(0.5)
    x.get(big)
    time.sleep(0.15)                    # (in the middle of it, over a round trip of 20 ms)
    subprocess.run(["ip", "rule", "add", "blackhole", "from", X_SRC], check=True)
    gone = time.time()
    takeable = t0 + UNIT * ((gone - t0) // UNIT + 2)
    time.sleep(5)
    again = [e for e in to_x if e[0] > gone + 0.2 and e[2]]
    print("X vanished %.0f s into a unit; sent to again %d times in 5 s; to be taken %.0f s on"
          % ((gone - t0) % UNIT, len(again), takeable - gone), flush=True)
    if len(again) < 3:
        return "X was owed nothing when it vanished (the timer does not have it)"
    time.sleep(max(0, takeable + 20 - time.time()))     # (the timer has stopped by now)
    sitecheck.T = 1.5
    y, tries = None, 0
    while y is None and time.time() < takeable + 20 + 45:
        tries += 1
        try:
            y = Conn(src=Y_SRC)
        except (OSError, ssl.SSLError):
            time.sleep(0.3)
    if y is None:
        return "no new connection got in (%d tried)" % tries
    # From when the server answered its SYN, the slot it was to get was no longer X's to
    # be sent to (a SYN is answered only if there is a slot for the connection, and it
    # may have waited in a processor's ring while that processor's timer stood still).
    begun = synack.get(y.sock.getsockname()[1])
    if begun is None:
        return "the SYN-ACK of the one that got in was not seen"
    sitecheck.T = 20
    resets = [e[0] for e in to_x if e[1] & 4]
    print("the %dth new connection got in, %.0f s after X could be taken; X %s"
          % (tries, begun - takeable, "was reset %.1f s before" % (begun - resets[0]) if resets else "has not been reset"),
          flush=True)
    try:
        y.get(big)
        if not same(y.response(), paths[big]):
            return "the one that got in did not get the large file as it is"
        time.sleep(3)
        y.get("/")
        if not same(y.response(), paths["/"]):
            return "the one that got in did not get the page after the file"
    except (OSError, ssl.SSLError) as e:    # (its records came with another's numbers, say)
        return "the connection of the one that got in broke: %s" % e
    time.sleep(3)
    late = [e for e in to_x if e[0] >= begun]
    if late:
        return "%d segments (%d bytes; flags of the first %#x) were sent to X after its slot was another's" \
            % (len(late), sum(e[2] for e in late), late[0][1])
    if N == "1" and resets:
        return "X was given up before anybody took its slot: nothing was tried"
    if N == "2" and not resets:
        return "X's slot was taken while the timer had it in use"
    n = there(keepers)
    if n != len(keepers):
        return "only %d of the %d that kept talking are still there" % (n, len(keepers))
    return None


def until_prompt(mon):
    got = b""
    while not got.endswith(b"(qemu) "):
        got += mon.recv(65536)
    return got


def mon_qwords(mon, addr, count):
    mon.sendall(("x /%dgx 0x%x\n" % (count, addr)).encode())
    got = until_prompt(mon)
    return [int(v, 16) for ln in got.decode(errors="replace").splitlines()
            if ":" in ln for v in re.findall(r"0x[0-9a-fA-F]+", ln.split(":", 1)[1])]


def gone():
    """N = 3. A new connection goes into the first free slot of the bucket that has more of
    them (`find`), and how many each has is counted before. If the last one is another
    processor's by the time it is looked for, there is none: the walk must end with the
    bucket, not find "a free slot" in the next bucket or behind the table. An image built
    RACE=3 does that to itself: the one free slot that was counted becomes a made-up
    connection's before the walk. With CAP=16 each table is one bucket, and behind the
    table for TLS lies the one for port 80: there seven connections are made, and the
    first of them ended, so that its slot, the table's first 24 bytes, is free and the
    six behind it are held (while all seven sit there, QEMU's monitor also checks that the
    slots are 24 bytes apart on a 64-byte line, so none has its first 8 bytes across two
    lines). Then connections to 443 until the bucket's last slot is counted. A walk that
    leaves the bucket takes "a slot" of 128 bytes where the table for port 80 begins,
    over five of the six: they must all still be answered."""
    plain = []
    for _ in range(7):
        s = socket.create_connection((HOST, 80), timeout=5, source_address=(K_SRC[0], 0))
        s.sendall(b"GET / HTTP/1.1\r\n\r\n")
        if not s.recv(4096).startswith(b"HTTP/1.1 "):
            return "port 80 does not answer"
        plain.append(s)
    if os.environ.get("MON"):
        site_len = os.path.getsize(os.path.join(os.environ.get("B", "build"), "site.bin"))
        pt_ptr = ((0x110000 + site_len + 0x1FFFFF) >> 21 << 21) + 0x0F220
        mon = socket.socket(socket.AF_UNIX)
        mon.settimeout(5)
        mon.connect(os.environ["MON"])
        until_prompt(mon)
        pt = mon_qwords(mon, pt_ptr, 1)[0]
        words = mon_qwords(mon, pt, 48)
        mon.close()
        want_ip = int.from_bytes(socket.inet_aton(K_SRC[0]), "little")
        if pt % 64 or any((pt + 24 * k) // 64 != (pt + 24 * k + 7) // 64 for k in range(16)):
            return "a port-80 slot's first 8 bytes straddle a cache line (PT = %#x)" % pt
        if [words[3 * k] & 0xFFFFFFFF for k in range(7)] != [want_ip] * 7 or words[21] & 0xFFFFFFFF:
            return "port-80 slots are not 24 bytes apart in PT"
    plain.pop(0).close()
    time.sleep(0.5)
    made, why = [], "none"
    for _ in range(20):
        s = socket.socket()
        s.bind((K_SRC[1], 0))
        s.settimeout(3)
        try:
            s.connect((HOST, 443))
        except OSError as e:            # (refused: the bucket is full now)
            why = type(e).__name__
            s.close()
            break
        made.append(s)
        time.sleep(0.05)
    time.sleep(0.5)
    ok = 0
    for s in plain:
        try:
            s.sendall(b"GET / HTTP/1.1\r\n\r\n")
            ok += s.recv(4096).startswith(b"HTTP/1.1 ")
        except OSError:
            pass
    print("%d connections to 443 until there was no room (%s); %d of the 6 on port 80 are still answered" % (len(made), why, ok))
    if len(made) not in (15, 16):       # (the 16th is reset as soon as it is made: before `connect` is back, or after)
        return "the bucket's last slot should have been counted with the 16th"
    return None if ok == 6 else "a connection was made outside its bucket, over the table for port 80"


if __name__ == "__main__":
    why = gone() if N == "3" else main()
    print("FAIL: " + why if why else "ok: a free slot that is gone is not looked for outside its bucket" if N == "3"
          else "ok: a slot that changes hands under the timer is the taker's or the timer's, not both's")
    sys.exit(1 if why else 0)
