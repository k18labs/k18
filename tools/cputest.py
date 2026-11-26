#!/usr/bin/env python3
"""cputest.py: which of the machine's processors are at work, by QEMU's word.

Frames go to a power of two of the processors (`drain`), up to four. One that gets none
(the third of three; the fifth and on) must be at rest: halted, not going round the
polling loop, where its turn at the SYNs of late would be at another processor's.

    SMP=3 MON=/tmp/k18mon unshare -Urn ./tap.sh python3 tools/cputest.py     (the suite's `cpus3`)

MON is where tap.sh puts QEMU's monitor; SMP how many processors the machine has.
"""
import os
import re
import socket
import sys

n = int(os.environ.get("SMP", "2"))
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ["MON"])
s.settimeout(5)


def until_prompt():
    got = b""
    while not got.endswith(b"(qemu) "):
        got += s.recv(65536)
    return got.decode(errors="replace")


until_prompt()
s.sendall(b"info registers -a\n")
text = until_prompt()
halted = sorted(int(cpu) for cpu, hlt in re.findall(r"CPU#(\d+)\r?\n.*?HLT=(\d)", text, re.S) if hlt == "1")
seen = len(re.findall(r"CPU#\d+", text))
takers = 1
while takers * 2 <= min(n, 4):
    takers *= 2
print("%d processors, %d of them take frames; at rest: %s" % (seen, takers, halted or "none"))
ok = seen == n and len(halted) == n - takers and 0 not in halted    # (which, is a matter of who started first)
print("ok: the others are at rest, and only they" if ok else "FAIL: %d should be at rest, and not the first" % (n - takers))
sys.exit(0 if ok else 1)
