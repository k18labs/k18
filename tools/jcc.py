#!/usr/bin/env python3
"""jcc.py LISTING [ROUTINE...]: jumps that cross or end on a 32-byte boundary.

On Intel processors from Skylake to Cascade Lake (the cloud server's is one), a jump, call
or return whose bytes cross a 32-byte boundary, or whose last byte is the last of such a
block, is not kept in the decoded-instruction cache since the microcode update for the
"jump conditional code" erratum; nor is a compare or test fused with such a jump. A loop
with one of those is decoded again on every turn: several percent of a handshake when it
is in the field arithmetic. This lists them per routine from a NASM listing (nasm -l), so
that the routines that matter can be kept free of them (`HOT` in src/os.asm puts each
where it has none).

  jcc.py LISTING                    every routine that has such jumps
  jcc.py LISTING ROUTINE...         those of these routines, and exit 1 if there are any
                                    (the build asks this)
  jcc.py LISTING fit ROUTINE...     what would lie on a boundary if the routine began K
                                    bytes behind one, for every K, and the K that leave
                                    nothing there as the mask that `HOT` takes
  jcc.py LISTING mask ROUTINE...    only the masks

ROUTINE:loops counts only the jumps inside the routine's loops (between a jump backwards
and where it goes): for a routine that is called once a handshake or once a record, the
others are met once a call, and that is no loop.
"""
import re
import sys

FUSE = re.compile(r"^(?:3[89AB]|8[0135]|8[45]|A[89]|F[67]|4[0-9A-F](?:3[89AB]|8[0135]|8[45]|F[67]|FF)|FF|0[0-3]|2[0-389AB])")


def is_jump(b):
    if not b:
        return False
    if b[0] in (0xE8, 0xE9, 0xEB, 0xC3) or 0x70 <= b[0] <= 0x7F or 0xE0 <= b[0] <= 0xE3:
        return True
    if b[0] == 0x0F and len(b) > 1 and 0x80 <= b[1] <= 0x8F:
        return True
    if b[0] == 0xFF and len(b) > 1 and (b[1] >> 3) & 7 in (2, 4):
        return True
    return False


def goes_to(b, after):
    """Where a jump (not a call) goes, if its bytes say so."""
    if b[0] == 0xEB or 0x70 <= b[0] <= 0x7F or 0xE0 <= b[0] <= 0xE3:
        return after + int.from_bytes(b[1:2], "little", signed=True)
    if b[0] == 0xE9 and len(b) == 5:
        return after + int.from_bytes(b[1:5], "little", signed=True)
    if b[0] == 0x0F and len(b) == 6:
        return after + int.from_bytes(b[2:6], "little", signed=True)
    return None


def routines(path):
    """name -> where it begins and its jumps: (first byte, last byte, where it goes or
    None, source); the first byte is that of a compare or test that fuses with it."""
    routine, prev, out = "?", None, {}
    for line in open(path, errors="replace"):
        m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+([0-9A-F\[\]\(\)]+)-?\s+(?:<\d+>\s*)?(.*)", line)
        lab = re.match(r"\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?(?:<\d+>\s*)?([A-Za-z_]\w*):", line)
        if lab:
            routine = lab.group(1)
        if not m:
            continue
        addr, code, src = int(m.group(1), 16), re.sub(r"[^0-9A-F]", "", m.group(2)), m.group(3)
        if len(code) % 2 or not code:
            prev = None
            continue
        b = bytes.fromhex(code)
        r = out.setdefault(routine, {"at": addr, "j": []})
        if is_jump(b):
            start = addr
            if prev and prev[0] + prev[1] == addr and FUSE.match(prev[2]) and (0x70 <= b[0] <= 0x7F or b[0] == 0x0F):
                start = prev[0]             # (a compare or test that fuses with the jump)
            r["j"].append((start, addr + len(b) - 1, goes_to(b, addr + len(b)), src.split(";")[0].strip()))
        prev = (addr, len(b), code)
    return out


def jumps(r, loops):
    if not loops:
        return r["j"]
    spans = [(to, end) for start, end, to, _ in r["j"] if to is not None and r["at"] <= to <= start]
    return [j for j in r["j"] if any(a <= j[0] <= b for a, b in spans)]


def on_boundary(j, k=0):
    return (j[0] + k) // 32 != (j[1] + k) // 32 or (j[1] + k) % 32 == 31


def main(path, args):
    all_ = routines(path)
    if not args:
        for name, r in sorted(all_.items(), key=lambda kv: -sum(map(on_boundary, kv[1]["j"]))):
            bad = [j[3] for j in r["j"] if on_boundary(j)]
            if bad:
                print(f"{len(bad):3d}  {name}: " + ", ".join(bad[:4]))
        return 0
    how = args.pop(0) if args[0] in ("fit", "mask") else None
    found = 0
    for arg in args:
        name, _, loops = arg.partition(":")
        r = all_[name]
        js = jumps(r, loops)
        if not how:
            for j in js:
                if on_boundary(j):
                    print(f"{name}: {j[0]:#x} {j[3]}")
                    found = 1
            continue
        print(f"{arg} (begins {r['at'] % 32} behind a boundary now, {len(js)} jumps{' in loops' if loops else ''}):")
        mask = 0
        for k in range(32):
            bad = [j[3] for j in js if on_boundary(j, k - r["at"] % 32)]
            mask |= (not bad) << k
            if how == "fit":
                print(f"  {k:2d}: {len(bad)}  {'; '.join(bad[:6])}")
        print(f"  HOT {mask:#010x}    (bit k: nothing on a boundary if it begins k bytes behind one)")
    return found


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
