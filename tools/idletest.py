#!/usr/bin/env python3
"""Does a connection that has long been quiet give way when there is no room, and only then?
Run against an image with small tables in which "long" is two minutes (`make
B=build-small-idle1 CAP=1024 IDLE=1`: 1024 slots; quiet for more than one unit of 64 s),
over tap:

    B=build-small-idle1 unshare -Urn ./tap.sh python3 tools/idletest.py

The table for port 80 is filled with connections that fetch the page once and say nothing
more, until new ones are refused; and refused they stay: nobody has been quiet for long.
32 of those held go on saying something every 10 s. After 140 s, 200 new connections must
all be taken, each in the place of a quiet one, and the 32 must all still be there and be
answered. (The processors take each other's slots here: a slot is whoever's connection
hashes to it. And the fetch is there so that a connection that gave way stays away: one
that has never been sent anything but its SYN-ACK is made again by its next packet, as
the SYN cookie has it.) Three minutes.
"""
import os
import socket
import sys
import time

DST = (os.environ.get("DST", "10.0.2.15"), 80)
SRCS = ["10.0.2.33", "10.0.2.34"]
QUIET = float(os.environ.get("QUIET", "140"))


def connect(i, fetch=False):
    s = socket.socket()
    s.bind((SRCS[i % len(SRCS)], 0))
    s.settimeout(5)
    try:
        s.connect(DST)
        if fetch:
            s.sendall(b"GET / HTTP/1.1\r\n\r\n")
            if not s.recv(4096).startswith(b"HTTP/1.1 "):
                raise ConnectionError
    except OSError:                     # (refused: no room)
        s.close()
        return None
    return s


def there(socks):
    """Which of these connections does the server still have? Each says a byte (no line end:
    that is no request yet); for a connection it does not have, the server answers that with
    a reset (but for one in 256, which it takes for the start of a new one and passes over)."""
    for s in socks:
        try:
            s.send(b"x")
        except OSError:
            pass
    time.sleep(0.5)
    yes = []
    for s in socks:
        s.setblocking(False)
        try:
            s.recv(1)
        except BlockingIOError:
            yes.append(s)
        except OSError:
            pass
        s.setblocking(True)
    return yes


def main():
    held, refused, i = [], 0, 0
    while refused < 100 and i < 4000:   # until a hundred in a row find no room
        s = connect(i, fetch=True)
        i += 1
        if s:
            held.append(s)
            refused = 0
        else:
            refused += 1
    print("%d connections held, then no room" % len(held))
    if not 900 <= len(held) <= 1024:
        return "the table should hold about 1024"
    fresh = [s for s in (connect(i) for i in range(100)) if s]
    if len(there(fresh)) > 2:
        return "%d new connections were taken while nobody had been quiet for long" % len(fresh)
    lively, quiet = held[::len(held) // 32][:32], None
    quiet = [s for s in held if s not in lively]
    t0 = time.time()
    while time.time() - t0 < QUIET:
        time.sleep(10)
        for s in lively:
            s.send(b"x")
    new = [connect(i) for i in range(200)]
    taken = there([s for s in new if s])
    print("%d of 200 new connections taken after %d s" % (len(taken), time.time() - t0))
    if len(taken) != 200:
        return "all 200 should have found a quiet connection's place"
    answered = 0
    for s in lively:
        s.settimeout(5)
        try:
            s.sendall(b"\r\n\r\n")
            answered += s.recv(4096).startswith(b"HTTP/1.1 ")
        except OSError:
            pass
    gone = len(quiet) - len(there(quiet))
    print("%d of 32 that kept talking are still answered; %d quiet ones have given way" % (answered, gone))
    if answered != 32:
        return "a connection that was not quiet was replaced"
    if not 190 <= gone <= 200:
        return "200 should have given way (but for the few whose reset is not sent)"
    return None


if __name__ == "__main__":
    why = main()
    print("FAIL: " + why if why else "ok: quiet connections give way when there is no room, and only they")
    sys.exit(1 if why else 0)
