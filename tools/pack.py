#!/usr/bin/env python3
"""pack.py SITE_DIR OUT_DIR: a folder of files becomes what the image serves.

Every file is turned into the complete HTTP response it will be sent as (status line,
headers, body), so the server has nothing to compose: it looks a request's path up and
sends the bytes it finds (for HEAD, their first part). The paths are found through a
hash table. What the server knows of all this is in OUT_DIR/site.bin, which ends the image:

  the path table   2^k slots of (FNV-1a hash of the path, where its record is; 0: empty),
                   probed linearly from hash & (2^k - 1); at most half full
  the responses    16 bytes each: where its bytes are, how many, how many of them are the
                   head, flags (1: the connection is closed after it; 8: the next response
                   is the "not modified" for this one; 2, 4: two and four responses on are
                   this one compressed, with gzip and with brotli)
  path records     which response (a word), the path's length (a word), the path
  the bytes

A file can be there in several forms, and the server picks by the request's headers. As it
is; compressed (gzip, and brotli if this machine has an encoder for it), for clients whose
Accept-Encoding names the way: a form is kept if the response then takes at least one
record (one segment) less to send and is a tenth shorter. And for every form of a file
that is longer than such an answer, a 304 "not modified", for clients whose If-None-Match
names the form's ETag: that is a hash of the whole response, so it changes with any
header as with the file. The 304 begins with its ETag, at a place the code knows.

(all offsets from the start of site.bin) and in OUT_DIR/site.inc, the handful of numbers
the code is assembled with. Paths are what a browser sends: percent-encoded where a URL
must be, compared byte for byte, without the query. A directory with an index.html is
served at its name with a slash, and without the slash it redirects there. 404.html, if
there is one, is what unknown paths get (with status 404).

For the tests OUT_DIR/site.json says what each path must return, and OUT_DIR/page80.bin
is what port 80 says to every request.

Environment: P80 = page (port 80 answers every request with the response for "/", the
default) or redirect (with a redirect to https://NAME/, NAME from OUT_DIR/name);
CACHE = seconds a browser may keep a file (default 600, empty: no such header);
HSTS = seconds for Strict-Transport-Security (default: no such header);
HEADERS = further header lines for every file, separated by newlines or by ";;";
COMPRESS = 0: no compressed forms.
The page for unknown paths has every header a file has but Cache-Control; the answers
without a body (a folder's redirect, the "no" to other methods) have the HSTS one. Port
80 has none of them: a browser may not believe that header there.
"""
import ctypes
import ctypes.util
import gzip
import hashlib
import json
import mimetypes
import os
import shutil
import stat
import subprocess
import sys
from urllib.parse import quote

TYPES = {
    ".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8", ".json": "application/json",
    ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
    ".xml": "application/xml", ".svg": "image/svg+xml", ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
    ".avif": "image/avif", ".ico": "image/x-icon", ".woff2": "font/woff2", ".woff": "font/woff",
    ".ttf": "font/ttf", ".pdf": "application/pdf", ".wasm": "application/wasm",
    ".webmanifest": "application/manifest+json", ".mp4": "video/mp4", ".webm": "video/webm",
    ".mp3": "audio/mpeg", ".zip": "application/zip", ".gz": "application/gzip",
}
MAX_FILE = 1 << 30      # a response's bytes on the wire are counted in 31 bits
MAX_SITE = 768 << 20    # the image, and all that boot puts behind it, lies in the first GiB
OBMAX = 0x40000         # where the answer to one packet is built (src/os.asm): port 80's has to fit
RECORD = 1418           # a response's bytes in a record, where a segment is 1440 bytes
PACKED = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".woff", ".woff2", ".mp4", ".webm", ".mp3",
          ".zip", ".gz", ".br", ".zst", ".xz", ".bz2", ".7z"}   # compressed as they are: not tried
NOT_MODIFIED = b"HTTP/1.1 304 Not Modified\r\nETag: "
ETAG_AT, ETAG_LEN = len(NOT_MODIFIED), 18   # where a 304 has its ETag, quotes and all


def brotli_encoder():
    """A function that compresses with brotli, from wherever this machine has one: the
    Python module, the library every curl is linked with, or the command. Or None."""
    try:
        import brotli
        return lambda data: brotli.compress(data, quality=11)
    except ImportError:
        pass
    enc, dec = ctypes.util.find_library("brotlienc"), ctypes.util.find_library("brotlidec")
    if enc and dec:
        enc, dec = ctypes.CDLL(enc), ctypes.CDLL(dec)
        size = ctypes.c_size_t
        enc.BrotliEncoderCompress.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, size, ctypes.c_char_p,
                                              ctypes.POINTER(size), ctypes.c_char_p]
        dec.BrotliDecoderDecompress.argtypes = [size, ctypes.c_char_p, ctypes.POINTER(size), ctypes.c_char_p]

        def compress(data):
            n = size(len(data) + (len(data) >> 2) + 1024)
            out = ctypes.create_string_buffer(n.value)
            if not enc.BrotliEncoderCompress(11, 22, 0, len(data), data, ctypes.byref(n), out):
                sys.exit("pack.py: the brotli encoder failed")
            packed = out.raw[:n.value]
            n = size(len(data) + 1)             # (and back, to be sure of it)
            back = ctypes.create_string_buffer(n.value)
            if dec.BrotliDecoderDecompress(len(packed), packed, ctypes.byref(n), back) != 1 or back.raw[:n.value] != data:
                sys.exit("pack.py: what the brotli encoder made does not decode to the file")
            return packed
        return compress
    if shutil.which("brotli"):
        return lambda data: subprocess.run(["brotli", "-q", "11", "-c"], input=data, capture_output=True, check=True).stdout
    return None


def fnv(path):
    h = 0x811C9DC5
    for b in path:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


mimetypes.init([])      # (Python's own table, not this machine's /etc/mime.types: the same site packs the same everywhere)


def content_type(name):
    ext = os.path.splitext(name)[1].lower()
    return TYPES.get(ext) or mimetypes.guess_type(name)[0] or "application/octet-stream"


def site_files(site):
    """List regular site files, refusing links before the packer can follow them."""
    site = os.path.normpath(site)
    try:
        root_mode = os.lstat(site).st_mode
    except OSError as exc:
        sys.exit(f"pack.py: cannot inspect site directory: {exc.strerror}")
    if stat.S_ISLNK(root_mode):
        sys.exit("pack.py: site directory must not be a symlink")
    if not stat.S_ISDIR(root_mode):
        sys.exit("pack.py: site path is not a directory")
    files = []
    for root, dirs, names in os.walk(site, followlinks=False):
        for name in dirs + names:
            path = os.path.join(root, name)
            if os.path.islink(path):
                rel = os.path.relpath(path, site).replace(os.sep, "/")
                sys.exit(f"pack.py: {rel} must not be a symlink")
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") or d == ".well-known")
        for name in sorted(names):
            if not name.startswith("."):
                files.append(os.path.join(root, name))
    return files


def read_site_file(path, rel):
    """Open only regular files and do not follow a final-component symlink."""
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        sys.exit(f"pack.py: cannot inspect {rel}: {exc.strerror}")
    if not stat.S_ISREG(mode):
        sys.exit(f"pack.py: {rel} is not a regular file")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        sys.exit(f"pack.py: cannot safely open {rel}: {exc.strerror}")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            sys.exit(f"pack.py: {rel} is not a regular file")
        with os.fdopen(fd, "rb") as f:
            fd = -1
            return f.read()
    finally:
        if fd >= 0:
            os.close(fd)


def main(site, out):
    env = os.environ.get
    cache, hsts = env("CACHE", "600"), env("HSTS", "")
    common = [b"Server: k18"]
    if cache:
        common.append(b"Cache-Control: max-age=%d" % int(cache))
    if hsts:
        common.append(b"Strict-Transport-Security: max-age=%d" % int(hsts))
    common.append(b"X-Content-Type-Options: nosniff")
    common += [line.strip().encode() for line in env("HEADERS", "").replace(";;", "\n").split("\n") if line.strip()]
    kept = [h for h in common[1:] if not h.startswith(b"Cache-Control:")]      # for the page that says 404
    strict = [h for h in common if h.startswith(b"Strict-Transport-Security:")]  # for answers without a body

    def response(status, headers, body):
        head = b"\r\n".join([b"HTTP/1.1 " + status] + headers + [b"Content-Length: %d" % len(body)]) + b"\r\n\r\n"
        return head, body

    def page(status, ctype, body, more=()):
        return response(status, [b"Server: k18", b"Content-Type: " + ctype.encode()] + common[1:] + list(more), body)

    responses = []      # (head, body, flags)
    index = {}          # (head, body, flags) -> its number

    def add(head, body, flags=0):
        key = (head, body, flags)
        if key not in index:
            index[key] = len(responses)
            responses.append(key)
        return index[key]

    add(b"", b"")       # number 0: nothing (what a connection has in hand before its first request)

    # A file's forms: as it is, then with gzip, then with brotli, each followed by its 304.
    brotli = brotli_encoder() if env("COMPRESS", "1") != "0" else None
    records = lambda head, body: -(-(len(head) + len(body)) // RECORD)
    groups = {}         # (type, body) -> the number of its first response
    forms = {}          # that number -> {"gzip": ..., "br": ..., "etag": ...} for the tests
    saved = [0, 0, 0]   # files with compressed forms, their bytes as they are, and as the shortest form

    def add_file(rel, ctype, body):
        if (ctype, body) in groups:
            return groups[(ctype, body)]
        made = []                           # (encoding, body)
        plain = page(b"200 OK", ctype, body)
        if env("COMPRESS", "1") != "0" and os.path.splitext(rel)[1].lower() not in PACKED and records(*plain) > 1:
            def wire_records(coding, packed):
                head, _ = page(b"200 OK", ctype, packed, [b"Content-Encoding: " + coding,
                                                            b"Vary: Accept-Encoding",
                                                            b"ETag: " + b"x" * ETAG_LEN])
                return records(head, packed)

            def worth(coding, packed):
                return 10 * len(packed) <= 9 * len(body) and wire_records(coding, packed) < records(*plain)

            packed = gzip.compress(body, compresslevel=9, mtime=0)
            if worth(b"gzip", packed):
                made.append((b"gzip", packed))
            if brotli:
                packed = brotli(body)
                previous_records = wire_records(*made[-1]) if made else records(*plain)
                if worth(b"br", packed) and wire_records(b"br", packed) < previous_records:
                    made.append((b"br", packed))
        vary = [b"Vary: Accept-Encoding"] if made else []
        entries, info = [], {}
        for coding, data in [(None, body)] + made:
            more = ([b"Content-Encoding: " + coding] if coding else []) + vary
            head, _ = page(b"200 OK", ctype, data, more)
            etag = b'"' + hashlib.sha256(head + data).hexdigest()[:ETAG_LEN - 2].encode() + b'"'
            not_modified = NOT_MODIFIED + etag + b"\r\n" + b"\r\n".join(common + vary) + b"\r\n\r\n"
            if made or len(body) > len(not_modified):
                head, _ = page(b"200 OK", ctype, data, more + [b"ETag: " + etag])
                entries += [(head, data, 8), (not_modified, b"", 0)]
                info[coding.decode() if coding else "plain"] = {
                    "head": head.decode("latin-1"), "length": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                    "etag": etag.decode(), "not_modified": not_modified.decode("latin-1")}
            else:
                entries.append((head, data, 0))
        flags = (2 if made else 0) | (4 if len(made) > 1 else 0)
        entries[0] = entries[0][:2] + (entries[0][2] | flags,)
        n = len(responses)
        responses.extend(entries)           # (side by side, whatever else is the same as one of them)
        groups[(ctype, body)] = n
        forms[n] = info
        if made:
            saved[0] += 1
            saved[1] += len(body)
            saved[2] += min(len(data) for _, data in made)
        return n
    paths = {}          # request path -> response number
    files = site_files(site)
    not_found = front = None
    for path in files:
        rel = os.path.relpath(path, site).replace(os.sep, "/")
        body = read_site_file(path, rel)
        if len(body) >= MAX_FILE:
            sys.exit(f"pack.py: {rel} is too large (the limit is 1 GiB)")
        url = "/" + quote(rel, safe="/~!$&'()*+,;=:@-._")
        ctype = content_type(rel)
        n = add_file(rel, ctype, body)
        paths[url.encode()] = n
        if rel == "index.html":
            front = (ctype, body)
        if rel == "404.html":
            not_found = (ctype, body)
        if os.path.basename(rel) == "index.html":
            folder = url[:-len("index.html")]               # "/" or "/a/b/"
            paths[folder.encode()] = n
            if folder != "/":
                head, _ = response(b"301 Moved Permanently", [b"Server: k18", b"Location: " + folder.encode()] + strict, b"")
                paths.setdefault(folder[:-1].encode(), add(head, b""))
    ctype, body = not_found or ("text/plain; charset=utf-8", b"404 Not Found\n")
    a404 = add(*response(b"404 Not Found", [b"Server: k18", b"Content-Type: " + ctype.encode()] + kept, body))
    head, _ = response(b"405 Method Not Allowed", [b"Server: k18", b"Allow: GET, HEAD", b"Connection: close"] + strict, b"")
    a405 = add(head, b"", 1)
    head, _ = response(b"400 Bad Request", [b"Server: k18", b"Connection: close"] + strict, b"")
    a400 = add(head, b"", 1)

    # port 80: one response for every request
    name = open(os.path.join(out, "name")).read().strip() if os.path.exists(os.path.join(out, "name")) else ""
    if env("P80", "page") == "redirect":
        host = f"[{name}]" if ":" in name else name
        head, body = response(b"301 Moved Permanently", [b"Server: k18", b"Location: https://" + host.encode() + b"/"], b"")
        p80 = head + body
    elif front:                             # (the front page, with no word about forms of it)
        head, body = page(b"200 OK", *front)
        p80 = head + body
    else:
        head, body, _ = responses[a404]
        p80 = head + body

    # the layout
    slots = 2
    while slots < 2 * len(paths):
        slots *= 2
    at = slots * 8
    recs_at = at + 16 * len(responses)
    recs, rec_off = b"", {}
    for path, n in sorted(paths.items()):
        if len(path) > 0xFFFF:
            sys.exit("pack.py: a path of over 64 KB")
        rec_off[path] = recs_at + len(recs)
        recs += n.to_bytes(2, "little") + len(path).to_bytes(2, "little") + path
    blobs_at = recs_at + len(recs)
    blobs, table = b"", b""
    for head, body, flags in responses:
        table += (blobs_at + len(blobs)).to_bytes(4, "little") + (len(head) + len(body)).to_bytes(4, "little") \
            + len(head).to_bytes(4, "little") + flags.to_bytes(4, "little")
        blobs += head + body
    p80_at = blobs_at + len(blobs)
    blobs += p80
    hashed = [(0, 0)] * slots
    for path, off in rec_off.items():
        h = fnv(path)
        i = h & (slots - 1)
        while hashed[i][1]:
            i = (i + 1) & (slots - 1)
        hashed[i] = (h, off)
    data = b"".join(h.to_bytes(4, "little") + off.to_bytes(4, "little") for h, off in hashed) + table + recs + blobs
    if len(responses) > 0x7FFF:
        sys.exit("pack.py: more than 32,767 different responses")
    if len(data) > MAX_SITE:
        sys.exit(f"pack.py: the site is {len(data) >> 20} MiB; the limit is {MAX_SITE >> 20} MiB")
    if len(p80) > OBMAX:
        sys.exit(f"pack.py: what port 80 says is {len(p80) >> 10} KiB, and the answer to a packet is built in "
                 f"{OBMAX >> 10} KiB: it would never be said (P80=redirect, or a smaller page)")

    with open(os.path.join(out, "site.bin"), "wb") as f:
        f.write(data)
    with open(os.path.join(out, "site.inc"), "w") as f:
        f.write("; generated by tools/pack.py: what os.asm needs to know of site.bin\n"
                f"%assign SITE_LEN {len(data)}\n"
                f"PT_MASK equ {slots - 1}\nAT_OFF equ {at}\nA_404 equ {a404}\nA_405 equ {a405}\nA_400 equ {a400}\n"
                f"P80_OFF equ {p80_at}\nP80_LEN equ {len(p80)}\nETAG_AT equ {ETAG_AT}\nETAG_LEN equ {ETAG_LEN}\n")
    with open(os.path.join(out, "page80.bin"), "wb") as f:
        f.write(p80)
    want = {}
    for path, n in paths.items():
        head, body, _ = responses[n]
        want[path.decode()] = {"status": int(head.split()[1]), "head": head.decode("latin-1"),
                               "length": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        if forms.get(n):                    # (what the same path returns to a client that says more)
            want[path.decode()]["forms"] = forms[n]
    head, body, _ = responses[a404]
    meta = {"paths": want, "not_found": {"head": head.decode("latin-1"), "length": len(body),
                                         "sha256": hashlib.sha256(body).hexdigest()},
            "not_allowed": responses[a405][0].decode("latin-1"),
            "bad_request": responses[a400][0].decode("latin-1"), "files": len(files), "bytes": len(data)}
    with open(os.path.join(out, "site.json"), "w") as f:
        json.dump(meta, f, indent=1)
    note = ""
    if saved[0]:
        note = f"; {saved[0]} of the files also compressed ({saved[1]} bytes as {saved[2]}" + \
            ("" if brotli else "; gzip only: no brotli encoder on this machine") + ")"
    print(f"site: {len(files)} files, {len(paths)} paths, {len(data)} bytes{note}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
