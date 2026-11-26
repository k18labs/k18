#!/usr/bin/env python3
"""tl.py PCAP [BIN]: a timeline of a download captured at the client: per BIN seconds (0.25),
new bytes that arrived, segments that came again, the client's acks, and how many of those said
what it has beyond a hole (SACK)."""
import re
import subprocess
import sys

step = float(sys.argv[2]) if len(sys.argv) > 2 else 0.25
t0 = hi = None
bins = {}
for line in subprocess.run(["tcpdump", "-n", "-tt", "-r", sys.argv[1]], capture_output=True, text=True).stdout.splitlines():
    f = line.split()
    try:
        t = float(f[0])
    except (ValueError, IndexError):
        continue
    if t0 is None:
        t0 = t
    d = bins.setdefault(int((t - t0) / step), [0, 0, 0, 0])
    m = re.search(r"seq (\d+):(\d+)", line)
    if f[2].startswith("10.0.2.15"):
        if m:
            a, e = int(m.group(1)), int(m.group(2))
            if hi is None or e > hi:
                d[0] += e - (hi if hi and hi > a else a)
                hi = e
            else:
                d[1] += 1
    else:
        d[2] += 1
        d[3] += "sack" in line
for b in sorted(bins):
    d = bins[b]
    print("%5.2f s: %7d new bytes, %3d again, %4d acks (%d with sack)" % (b * step, *d))
