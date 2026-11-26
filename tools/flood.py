#!/usr/bin/env python3
"""Packets from clients that don't exist, straight onto the tap (inside ./tap.sh):

    flood.py [N]    N SYNs from random addresses and ports (each gets a SYN-ACK, and must not
                    get a slot), then N acks and N data segments with made-up sequence
                    numbers (must not get one either)

tools/churn.py runs this between its two rounds of fetches when FLOOD=N is set.
"""
import os
import random
import socket
import struct
import subprocess
import sys
import time

TAP = os.environ.get("TAP", "k2t")
DST = os.environ.get("DST", "10.0.2.15")


def csum(data):
    if len(data) & 1:
        data += b"\0"
    s = sum(struct.unpack(f">{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(mac_dst, mac_src, src, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    pseudo = src + socket.inet_aton(DST) + struct.pack(">HH", 6, len(tcp))
    tcp = tcp[:16] + struct.pack(">H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0) + src + socket.inet_aton(DST)
    ip = ip[:10] + struct.pack(">H", csum(ip)) + ip[12:]
    return mac_dst + mac_src + b"\x08\x00" + ip + tcp


def flood(n, dport=443):
    neigh = subprocess.run(["ip", "neigh", "show", DST], capture_output=True, text=True).stdout.split()
    mac_dst = bytes.fromhex(neigh[neigh.index("lladdr") + 1].replace(":", ""))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((TAP, 0))
    mac_src = s.getsockname()[4]
    rnd = random.Random(1)
    t = time.time()
    for flags, payload in ((0x02, b""), (0x10, b""), (0x18, bytes(100))):
        for _ in range(n):
            src = bytes([rnd.randrange(11, 200), rnd.randrange(256), rnd.randrange(256), rnd.randrange(1, 255)])
            s.send(frame(mac_dst, mac_src, src, rnd.randrange(1024, 65536), dport, rnd.getrandbits(32),
                         rnd.getrandbits(32), flags, payload))
    return time.time() - t


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    print(f"{3 * n} packets in {flood(n):.1f} s")
