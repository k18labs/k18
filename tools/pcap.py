#!/usr/bin/env python3
"""One TCP connection out of a capture, a line per packet, sequence numbers relative.
Usage: pcap.py FILE CLIENT_IP CLIENT_PORT     (FILE: what `tcpdump -w` wrote, Ethernet)
With no port: the ports of CLIENT_IP that never saw a FIN from the server."""
import socket
import struct
import sys


def packets(path):
    with open(path, "rb") as f:
        magic = f.read(24)[:4]
        end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        while len(hdr := f.read(16)) == 16:
            sec, frac, n, _ = struct.unpack(end + "IIII", hdr)
            data = f.read(n)
            if data[12:14] != b"\x08\x00" or data[23] != 6:
                continue
            ihl = (data[14] & 15) * 4
            total = struct.unpack(">H", data[16:18])[0]
            tcp = data[14 + ihl:14 + total]
            sport, dport, seq, ack, off, flags = struct.unpack(">HHIIBB", tcp[:14])
            yield (sec + frac / (1e9 if nano else 1e6), socket.inet_ntoa(data[26:30]), sport,
                   socket.inet_ntoa(data[30:34]), dport, seq, ack, flags, len(tcp) - (off >> 4) * 4)


def main():
    path, ip = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else None
    if port is None:
        seen, done = set(), set()
        for _, src, sport, dst, dport, _, _, flags, _ in packets(path):
            if src == ip:
                seen.add(sport)
            elif dst == ip and flags & 1:
                done.add(dport)
        print(*sorted(seen - done))
        return
    t0 = c0 = s0 = None
    for t, src, sport, dst, dport, seq, ack, flags, n in packets(path):
        out = src == ip and sport == port
        if not out and not (dst == ip and dport == port):
            continue
        if t0 is None:
            t0 = t
        if flags & 2:
            if out:
                c0 = seq
            else:
                s0 = seq
        mine, theirs = (c0, s0) if out else (s0, c0)
        names = "".join(c for i, c in enumerate("FSRPAU") if flags >> i & 1)
        rel = lambda v, base: (v - base) & 0xFFFFFFFF if base is not None else v
        print(f"{t - t0:9.4f} {'->' if out else '<-'} {names:5} seq {rel(seq, mine):6} ack {rel(ack, theirs):6} len {n}")


if __name__ == "__main__":
    main()
