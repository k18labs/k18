#!/usr/bin/env python3
"""mkdisk.py BOOT EFI OS OUT: the disk image, which a BIOS boots and UEFI firmware too.

Its first sector is the boot sector (src/boot.asm), with a partition table of one
partition: the rest of the disk, a FAT16 file system with two files in it, os.bin (the
image) and EFI/BOOT/BOOTX64.EFI (src/efi.asm: where UEFI firmware looks for what to
start, in a partition of this type, 0xEF). The boot sector reads the image by its
sectors, which lie one after the other, and knows of no file system; the EFI
application asks the firmware for the file. So the image is on the disk once.

Both are told what the image's multiboot header says (where it is loaded: 1 MiB and a
few bytes, so that its code ends where a page does; and where it is entered) and how
long it is: the boot sector in the twenty bytes before its partition table (the sector
the image begins at first, and its length in sectors: src/boot.asm reads the sectors in
pieces of 64), the EFI application in the first twelve of its code.

No GPT: its second copy would have to lie at the end of whatever disk the image is
written to, where `k18` keeps who a machine is; and firmware has to know a partition
table of this kind as well. The disk is 8 MiB at least (sparse): SeaBIOS won't boot one
of a few KiB. Nothing in it says when or where it was made."""
import struct
import sys

boot, efi, osbin = (open(p, "rb").read() for p in sys.argv[1:4])
assert len(boot) == 512 and boot[510:] == b"\x55\xaa" and boot[420:510] == bytes(90), "boot sector"
assert efi[:2] == b"MZ" and len(efi) % 512 == 0 and efi[512:524] == bytes(12), "EFI application"
magic, flags, check, header, load, _, _, entry = struct.unpack("<8I", osbin[:32])
assert magic == 0x1BADB002 and (magic + flags + check) & 0xFFFFFFFF == 0 and flags & 0x10000, "the image's multiboot header"
assert header == load and 0x100000 <= load < 0x101000 and load <= entry < load + len(osbin), "where the image says it goes"
sectors = -(-len(osbin) // 512)
pieces = -(-sectors // 64) * 64                 # (it reads whole pieces: they must be there)
efi = efi[:512] + struct.pack("<3I", load, entry, len(osbin)) + efi[524:]

# The file system, in sectors from where the partition begins (sector 1): its own first
# sector, two tables of clusters, the first directory (512 entries), then the clusters,
# numbered from 2: one each for the directories EFI and EFI/BOOT, then the two files.
# A cluster is as many sectors (a power of two) as it takes for there to be fewer than
# 65,525 of them, and FAT16 is what a file system with 4,085 or more of them is.
ROOT, DIRS = 32, 2
for spc in (1, 2, 4, 8, 16, 32, 64):
    need = DIRS + -(-len(efi) // (512 * spc)) + -(-pieces // spc)
    size = max(8 << 20, -(-512 * (2 + 2 * 256 + ROOT + need * spc) >> 20) << 20)
    total = size // 512 - 1
    fat = 1
    while (clusters := (total - 1 - 2 * fat - ROOT) // spc) + 2 > fat * 256:
        fat += 1
    if clusters <= 65524:
        break
assert 4085 <= clusters <= 65524 and clusters >= need, "an image of this length does not fit a FAT16 file system"
data = 1 + 1 + 2 * fat + ROOT                    # the disk's sector that cluster 2 begins at
at_efi = 2 + DIRS
at_os = at_efi + -(-len(efi) // (512 * spc))
first = data + (at_os - 2) * spc                 # the image's first sector

table = [0xFFF8, 0xFFFF, 0xFFFF, 0xFFFF]


def chain(start, length):
    n = -(-length // (512 * spc))
    assert len(table) == start
    table.extend(list(range(start + 1, start + n)) + [0xFFFF])


chain(at_efi, len(efi))
chain(at_os, len(osbin))


def entry_of(name, cluster, length=None):       # (a directory has no length; the date: 1 January 1980)
    return struct.pack("<11sB2xHHH2xHHHI", name, 0x10 if length is None else 0x20, 0, 0x21, 0x21, 0, 0x21, cluster, length or 0)


vbr = bytearray(512)
struct.pack_into("<3s8sHBHBHHBHHHII", vbr, 0, b"\xEB\x3C\x90", b"k18     ", 512, spc, 1, 2, ROOT * 16,
                 total if total < 65536 else 0, 0xF8, fat, 63, 255, 1, total if total >= 65536 else 0)
struct.pack_into("<BBBI11s8s", vbr, 36, 0x80, 0, 0x29, 0, b"NO NAME    ", b"FAT16   ")
vbr[510:] = b"\x55\xaa"
part = struct.pack("<B3sB3sII", 0x80, b"\x00\x02\x00", 0xEF, b"\xFE\xFF\xFF", 1, total)
boot = boot[:420] + struct.pack("<Q3I", first, load, entry, sectors) + boot[440:446] + part + boot[462:]
fats = struct.pack("<%dH" % len(table), *table).ljust(fat * 512, b"\0")

with open(sys.argv[4], "wb") as f:
    f.write(boot + vbr + fats + fats + entry_of(b"EFI        ", 2) + entry_of(b"OS      BIN", at_os, len(osbin)))
    for cluster, what in ((2, entry_of(b".          ", 2) + entry_of(b"..         ", 0) + entry_of(b"BOOT       ", 3)),
                          (3, entry_of(b".          ", 3) + entry_of(b"..         ", 2) + entry_of(b"BOOTX64 EFI", at_efi, len(efi))),
                          (at_efi, efi), (at_os, osbin)):
        f.seek((data + (cluster - 2) * spc) * 512)
        f.write(what)
    f.truncate(size)
