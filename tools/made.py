#!/usr/bin/env python3
"""made.py OUT [NASM DEFINES]: how the image in OUT was made, and what it is without its key.

Writes OUT/made (what `make` runs after it has assembled OUT/os.bin): the commit, the
assembler and what else had a hand in it, what the assembler was told (the defines, the
numbers of site.inc, the certificate chain's hash), how the site was packed (from the
environment, as tools/pack.py had it), and three hashes of the image with the 32 bytes
of its private key set to zero: of its system part, of the site, of both.

An image holds its key, so nobody else can be given it; but everything else in it is
made of things anybody can have (the source, the certificate chain the server shows, the
site), and without the key it is the same bytes for whoever makes it: `make KEYLESS=1`
makes that image from the certificate alone, and tools/repro.sh compares. The system
part depends on the site only by the ten numbers of site.inc, which are in OUT/made:
so it can be made again without the site, and without the programs that compressed it.
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zlib

out = sys.argv[1]
defines = " ".join(sys.argv[2:]).split()
image = bytearray(open(f"{out}/os.bin", "rb").read())
site = open(f"{out}/site.bin", "rb").read()
# where the key is: 64 bytes behind the label EDC (tools/gen.py: regs.inc), says the listing
at = None
for line in open(f"{out}/os.lst", errors="replace"):
    m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+\S+\s+(?:<\d+>\s*)?EDC:", line)
    if m:
        at = int(m.group(1), 16) + 64
        break
if at is None:
    sys.exit("made.py: the listing has no EDC (where the key is)")
keyless = not any(image[at:at + 32])
image[at:at + 32] = bytes(32)
system = image[:len(image) - len(site)]
assert image[len(system):] == site, "the image does not end with the site"


def said(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().split("\n")[0]
    except OSError:
        return "?"


def brotli():
    """The encoder tools/pack.py takes (brotli_encoder there: the same three, in its order)."""
    try:
        import brotli
        return "the Python module " + getattr(brotli, "__version__", "?")
    except ImportError:
        pass
    import ctypes
    import ctypes.util
    lib = ctypes.util.find_library("brotlienc")
    if lib and ctypes.util.find_library("brotlidec"):
        v = ctypes.CDLL(lib).BrotliEncoderVersion()
        return f"libbrotlienc {v >> 24}.{(v >> 12) & 0xFFF}.{v & 0xFFF}"
    if shutil.which("brotli"):
        return "the command, " + (said("brotli", "--version") or "?")
    return "none"


here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
commit = said("git", "-C", here, "rev-parse", "HEAD") or "?"
if said("git", "-C", here, "status", "--porcelain", "--untracked-files=no"):
    commit += " and changes that are not committed"
numbers = " ".join(f"{k}={v}" for k, v in re.findall(r"^(?:%assign\s+)?(\w+)\s+(?:equ\s+)?(\d+)\s*$", open(f"{out}/site.inc").read(), re.M))
with open(f"{out}/made", "w") as f:
    f.write(f"""commit: {commit}
assembler: {said("nasm", "-v")}
defines: {" ".join(defines)}
site.inc: {numbers}
chain: {hashlib.sha256(open(f"{out}/gen.inc", "rb").read()).hexdigest()}
site: NAME={open(f"{out}/name").read().strip()} P80={os.environ.get("P80", "page")} HSTS={os.environ.get("HSTS", "")} CACHE={os.environ.get("CACHE", "600")} COMPRESS={os.environ.get("COMPRESS", "1")} HEADERS={os.environ.get("HEADERS", "")}
packed with: Python {sys.version.split()[0]}, zlib {zlib.ZLIB_RUNTIME_VERSION}, brotli: {brotli()}
key: {"none (an image for comparing: it cannot sign)" if keyless else "its 32 bytes"} at {at}
without its key, sha256 of
  the system ({len(system)} bytes): {hashlib.sha256(system).hexdigest()}
  the site ({len(site)} bytes): {hashlib.sha256(site).hexdigest()}
  the image ({len(image)} bytes): {hashlib.sha256(image).hexdigest()}
""")
