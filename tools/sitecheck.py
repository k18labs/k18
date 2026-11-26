#!/usr/bin/env python3
"""sitecheck.py [quick]: the site an image was built with comes back as tools/pack.py made it.

Every path of $B/site.json is fetched over TLS (chain and name verified) and compared byte
for byte, head and body: on one connection, on fresh ones, with GET and with HEAD, from
clients that take small segments (so that the server cuts its records smaller), from one
that reads slowly (so that its window closes), from one that stops reading and reads
again, from many at once. Then what is not a file:
unknown paths, queries, other methods (told no, and the connection closed), requests that
come in pieces or are too large, two requests at once, a client that closes its side or
goes away in the middle. And what a request's headers change: a file that was packed
compressed too comes that way to a client whose Accept-Encoding names the way, and one
whose If-None-Match names what it would get is told "not modified". Exit 0 if all of it
holds.

Environment: B (build directory, default build), HOST and PORT (default 127.0.0.1:8443;
over tap: HOST=10.0.2.15 PORT=443; over IPv6: HOST=fd00:15::15), SRC (address to connect from), T (seconds to wait
for anything, default 20). With "quick" as argument: fewer fetches of the large file.
GONE=1 (over tap only): also a client that vanishes, which takes three minutes.
"""
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import zlib

from tlsclient import B, NAME, BioClient

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8443"))
SRC = os.environ.get("SRC")
T = float(os.environ.get("T", "20"))
SITE = json.load(open(os.path.join(B, "site.json")))
QUICK = "quick" in sys.argv[1:]


class Conn(BioClient):
    """A TLS client over a TCP socket we also hold: so a record can be sent in pieces."""

    def __init__(self, mss=None, rcvbuf=None, src=None):
        sock = socket.socket(socket.AF_INET6 if ":" in HOST else socket.AF_INET)
        if mss:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        if rcvbuf:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        if src or SRC:
            sock.bind((src or SRC, 0))
        sock.settimeout(T)
        sock.connect((HOST, PORT))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        super().__init__(sock, eof_ok=True)
        self.buf = b""
        self.handshake()

    def send(self, raw, pieces=None, gap=0.05):
        """One record with these bytes; in several TCP segments if pieces says where to cut."""
        self.tls.write(raw)
        data = self.out.read()
        at = 0
        for cut in list(pieces or []) + [len(data)]:
            self.sock.sendall(data[at:cut])
            at = cut
            if at < len(data):
                time.sleep(gap)
        return len(data)

    def get(self, path, method="GET", extra=b""):
        self.send(method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n" + extra + b"\r\n")

    def more(self, pause=0):
        if pause:
            time.sleep(pause)
        got = self.pump(lambda: self.tls.read(65536))
        self.buf += got
        return bool(got)

    def response(self, head_only=False, pause=0):
        while b"\r\n\r\n" not in self.buf:
            if not self.more():
                raise ConnectionError("closed before a response's head was there: %r" % self.buf[:60])
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        head += b"\r\n\r\n"
        n = 0 if head_only or head.startswith(b"HTTP/1.1 304") else int(head.split(b"Content-Length: ")[1].split(b"\r\n")[0])
        while len(self.buf) < n:
            if not self.more(pause):
                raise ConnectionError("closed in a body: %d of %d" % (len(self.buf), n))
        body, self.buf = self.buf[:n], self.buf[n:]
        return head, body

    def closed(self, wait=3):
        """True if the server ends the connection (and sends nothing more) within wait seconds."""
        self.sock.settimeout(wait)
        try:
            while self.more():
                pass
        except (OSError, ssl.SSLError) as e:
            return isinstance(e, ConnectionError)
        return not self.buf

    def close(self):
        self.sock.close()


def same(got, want):
    head, body = got
    return head == want["head"].encode("latin-1") and len(body) == want["length"] and \
        hashlib.sha256(body).hexdigest() == want["sha256"]


FAILED = []
ONLY = os.environ.get("ONLY")       # (for chasing one thing: only the checks whose name has this in it)


def check(name, fn):
    if ONLY and ONLY not in name:
        return
    t0 = time.time()
    try:
        ok = fn()
        why = ""
    except Exception as e:  # noqa: BLE001 (whatever goes wrong is a failure of this check)
        ok, why = False, " (%s: %s)" % (type(e).__name__, e)
    print("%s %s%s  [%.1f s]" % ("ok  " if ok else "FAIL", name, why, time.time() - t0), flush=True)
    if not ok:
        FAILED.append(name)


def main():
    paths = SITE["paths"]
    big = max(paths, key=lambda p: paths[p]["length"])
    small = [p for p in paths if paths[p]["length"] < 20000]
    nf = SITE["not_found"]

    def all_on_one(method):
        c = Conn()
        for p, want in paths.items():
            c.get(p, method)
            got = c.response(head_only=method == "HEAD")
            if method == "HEAD":
                if got[0] != want["head"].encode("latin-1"):
                    raise AssertionError("HEAD " + p)
            elif not same(got, want):
                raise AssertionError(p)
        c.get("/")                      # (and nothing was left over from the HEADs)
        ok = same(c.response(), paths["/"])
        c.close()
        return ok

    check(f"all {len(paths)} paths on one connection", lambda: all_on_one("GET"))
    check("the head of each, for HEAD", lambda: all_on_one("HEAD"))

    def fresh():
        for p in small:
            c = Conn()
            c.get(p)
            if not same(c.response(), paths[p]):
                raise AssertionError(p)
            c.close()
        return True

    check(f"{len(small)} of them on a connection each", fresh)

    def with_mss(mss):
        c = Conn(mss=mss)
        for p in small + ([] if QUICK and mss < 1000 else [big]):
            c.get(p)
            if not same(c.response(), paths[p]):
                raise AssertionError(p)
        c.close()
        return True

    for mss in (1300, 600, 300):
        check(f"to a client that takes segments of {mss} bytes", lambda mss=mss: with_mss(mss))

    def slow():
        c = Conn(rcvbuf=4096)
        c.get("/mid.bin" if "/mid.bin" in paths else big)
        time.sleep(1.5)                 # (its window closes; then it opens a little at a time)
        ok = same(c.response(pause=0.002), paths["/mid.bin" if "/mid.bin" in paths else big])
        c.get("/")
        ok &= same(c.response(), paths["/"])
        c.close()
        return ok

    check("to a client that reads slowly", slow)

    # A client that stops reading: its window shuts, and from then on we ask now and then
    # what it takes (`tqrun`), twice as long apart each time. When it reads again it says
    # so, and the rest must come then, not when we next ask. (Over tap: QEMU's own network
    # takes a file of this size whole, whatever the client does.) And with a request that
    # came in two pieces meanwhile: that one waits until the response before it is
    # acknowledged (`tcp.busyc`) and the client's TCP has sent it again, and is answered.
    def reads_again(meanwhile):
        mid = "/mid.bin" if "/mid.bin" in paths else big
        c = Conn(rcvbuf=4096)
        c.get(mid)
        time.sleep(0.3)
        if meanwhile:
            c.tls.write(b"GET / HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n\r\n")
            data = c.out.read()
            c.sock.sendall(data[:5])
            time.sleep(0.1)
            c.sock.sendall(data[5:])
        time.sleep(1.9 if meanwhile else 2.0)   # (2.3 s in all: we asked last at 2 s, and next at 4 s)
        t0 = time.time()
        ok = same(c.response(), paths[mid])
        took = time.time() - t0
        if meanwhile:
            ok &= same(c.response(), paths["/"])
        c.close()
        if took > 1 and not (os.environ.get("LOSS") or os.environ.get("REORDER")):
            raise AssertionError("the rest came %.1f s after it read again" % took)
        return ok

    check("a client that stops reading gets the rest as soon as it reads again", lambda: reads_again(False))
    check("and a request it sent in two pieces meanwhile is answered after that", lambda: reads_again(True))

    # What a request's headers change (tools/pack.py: a file's forms)
    formed = {p: w["forms"] for p, w in paths.items() if "forms" in w}
    packed = [p for p in formed if len(formed[p]) > 1]

    def encodings():
        c = Conn()
        for p in packed:
            f = formed[p]
            best = "br" if "br" in f else "gzip"
            for said, coding in ((b"Accept-Encoding: gzip\r\n", "gzip"), (b"Accept-Encoding: gzip, deflate, br, zstd\r\n", best),
                                 (b"accept-encoding: br\r\n", "br" if "br" in f else "plain"),
                                 (b"ACCEPT-ENCODING: deflate, gzip;q=1.0, *;q=0.5\r\n", "gzip"),
                                 (b"Accept-Encoding: br;q=0, gzip\r\n", "gzip"), (b"Accept-Encoding: gzip;q=0\r\n", "plain"),
                                 (b"Accept-Encoding: identity\r\n", "plain"), (b"Accept-Language: br, gzip\r\n", "plain"),
                                 (b"X-Accept-Encoding: gzip\r\nUser-Agent: Not?A_Brand gzip\r\n", "plain")):
                c.get(p, extra=said)
                if not same(c.response(), f[coding]):
                    raise AssertionError("%s with %r" % (p, said))
            c.get(p, extra=b"Accept-Encoding: gzip\r\n")       # what is packed is the file
            if hashlib.sha256(zlib.decompress(c.response()[1], 31)).hexdigest() != paths[p]["sha256"]:
                raise AssertionError("%s: gzip does not hold the file" % p)
            c.get(p, "HEAD", b"Accept-Encoding: br, gzip\r\n")
            if c.response(head_only=True)[0] != f[best]["head"].encode("latin-1"):
                raise AssertionError("HEAD " + p)
        c.get("/")
        ok = same(c.response(), paths["/"])
        c.close()
        return ok

    if packed:
        check(f"{len(packed)} files that were packed compressed too, to clients that take that", encodings)

    def conditional():
        c = Conn()
        for p in list(formed)[:40]:
            f = formed[p]
            for coding, form in f.items():
                said = b"" if coding == "plain" else b"Accept-Encoding: " + coding.encode() + b"\r\n"
                tag = form["etag"].encode()
                other = [g["etag"].encode() for k, g in f.items() if k != coding]
                for inm, want in ((tag, 304), (b"W/" + tag, 304), (b'"x", ' + tag, 304), (b'"0123456789abcdef"', 200),
                                  (tag[:-2] + b'"', 200), (other[0] if other else b'"x"', 200)):
                    c.get(p, extra=said + (b"if-none-match: " if want == 304 and inm == tag else b"If-None-Match: ") + inm + b"\r\n")
                    head, body = c.response()
                    if want == 304 and (head != form["not_modified"].encode("latin-1") or body):
                        raise AssertionError("%s (%s) with If-None-Match: %r: %r" % (p, coding, inm, head[:40]))
                    if want == 200 and not same((head, body), form):
                        raise AssertionError("%s (%s) with If-None-Match: %r" % (p, coding, inm))
                c.get(p, "HEAD", said + b"If-None-Match: " + tag + b"\r\n")
                if c.response(head_only=True)[0] != form["not_modified"].encode("latin-1"):
                    raise AssertionError("HEAD %s (%s) with its ETag" % (p, coding))
                c.get(p, extra=said + b"If-Match: " + tag + b"\r\nIf-Range: " + tag + b"\r\n")    # (other headers with it in)
                if not same(c.response(), form):
                    raise AssertionError("%s (%s) with If-Range" % (p, coding))
        c.get("/nope", extra=b"If-None-Match: " + next(iter(formed.values()))["plain"]["etag"].encode() + b"\r\n")
        ok = same(c.response(), nf)
        c.close()
        return ok

    if formed:
        check("a client that has a file already is told so (If-None-Match), each form by its own ETag", conditional)

    def many(n):
        res = []

        def one():
            try:
                c = Conn()
                for _ in range(2):
                    c.get(big)
                    res.append(same(c.response(), paths[big]))
                c.close()
            except Exception as e:  # noqa: BLE001
                res.append(repr(e))

        th = [threading.Thread(target=one) for _ in range(n)]
        for t in th:
            t.start()
        for t in th:
            t.join()
        if res != [True] * (2 * n):
            raise AssertionError([r for r in res if r is not True][:3])
        return True

    n = 4 if QUICK else 16
    for _ in range(int(os.environ.get("REPEAT", "1"))):
        check(f"the largest file ({paths[big]['length']} bytes) to {n} clients at once, twice each", lambda: many(n))

    def curl(suite):
        cmd = ["curl", "-s", "--max-time", str(int(4 * T)), "--connect-to", f"{NAME}:{PORT}:{'[' + HOST + ']' if ':' in HOST else HOST}:{PORT}", "--tls13-ciphers", suite]
        if SRC:
            cmd += ["--interface", SRC]
        ca = os.path.join(B, "ca.pem")
        if os.path.getsize(ca):
            cmd += ["--cacert", ca]
        out = subprocess.run(cmd + [f"https://{NAME}:{PORT}{big}"], capture_output=True).stdout
        return hashlib.sha256(out).hexdigest() == paths[big]["sha256"]

    check("the largest file to curl with TLS_AES_128_GCM_SHA256", lambda: curl("TLS_AES_128_GCM_SHA256"))

    def unknown():
        c = Conn()
        ok = True
        for p in ("/nope", "/index.htm", "/docs/index.html/", "//", "/" + "x" * 300, "/.hidden", "/size"):
            c.get(p)
            ok &= same(c.response(), nf)
        c.get("/nope", "HEAD")
        ok &= c.response(head_only=True)[0] == nf["head"].encode("latin-1")
        c.get("/?a=1&b=2")
        ok &= same(c.response(), paths["/"])
        c.send(b"GET /\r\nHost: x\r\n\r\n")  # (no version: the path ends at the line's end)
        ok &= same(c.response(), paths["/"])
        if "/docs" in paths:            # a folder without its slash is sent to the one with
            c.get("/docs")
            head, _ = c.response()
            ok &= head.startswith(b"HTTP/1.1 301") and b"\r\nLocation: /docs/\r\n" in head
        c.close()
        return ok

    check("unknown paths, a query, a folder without its slash", unknown)

    def refused(method):
        c = Conn()
        c.get("/", method, b"Content-Length: 3\r\n")
        head, _ = c.response()
        ok = head == SITE["not_allowed"].encode("latin-1")
        c.send(b"abc")
        ok &= c.closed()
        c.close()
        return ok

    for method in ("POST", "OPTIONS", "DELETE", "PROPFIND", "M-SEARCH", "get", "Head"):  # (a method is any word)
        check(f"{method} is told no, and the connection ends", lambda method=method: refused(method))

    def no_host(req):
        c = Conn()
        c.send(req)
        head, _ = c.response()
        ok = head == SITE["bad_request"].encode("latin-1")
        ok &= c.closed()
        c.close()
        return ok

    for req in (b"GET / HTTP/1.1\r\n\r\n", b"HEAD / HTTP/1.1\r\n\r\n", b"GET /nothing HTTP/1.1\r\n\r\n",
                b"GET / HTTP/1.1\r\nX-Host: x\r\nHostname: x\r\n\r\n"):
        first = req.split(b"\r")[0].decode() + (" with X-Host and Hostname" if b"X-Host" in req else "")
        check(f"{first} without a Host line gets the 400, and the connection ends", lambda req=req: no_host(req))

    def host_any_case():
        c = Conn()
        ok = True
        for line in (b"host: x", b"HOST: x", b"Accept: */*\r\nhOsT:x"):
            c.send(b"GET / HTTP/1.1\r\n" + line + b"\r\n\r\n")
            ok &= same(c.response(), paths["/"])
        c.close()
        return ok

    check("a Host line counts in any letters and after others", host_any_case)

    def not_requests():
        c = Conn()
        for junk in (b"\r\n", b"Host: x\r\n\r\n", b"get/\r\n\r\n", b" GET / HTTP/1.1\r\n\r\n", b"\x00" * 40, b"G"):
            c.send(junk)
        c.get("/")
        ok = same(c.response(), paths["/"])
        c.close()
        return ok

    check("records that are no requests get no answer and do no harm", not_requests)

    # (two paths these ask for: the test site's, or on another site what there is)
    pg = "/docs/" if "/docs/" in paths else "/"
    fl = "/size/2500.bin" if "/size/2500.bin" in paths else big

    def pieces():
        c = Conn()
        req = b"GET " + pg.encode() + b" HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n\r\n"
        ok = True
        for cuts in ([3], [5], [6], [20], [1, 2, 3, 4, 5, 6, 7], [len(req) + 21]):
            c.tls.write(req)
            data = c.out.read()
            at = 0
            for cut in cuts + [len(data)]:
                c.sock.sendall(data[at:cut])
                at = cut
                time.sleep(0.03)
            ok &= same(c.response(), paths[pg])
        pad = b"X-Pad: " + b"p" * 2900 + b"\r\n"      # one that takes three segments
        c.get("/", extra=pad)
        ok &= same(c.response(), paths["/"])
        c.get(pg)
        ok &= same(c.response(), paths[pg])
        c.close()
        return ok

    check("a request that comes in pieces, and one of 3 KB", pieces)

    def too_large():
        c = Conn()
        c.get("/", extra=b"X-Pad: " + b"p" * 6000 + b"\r\n")
        return c.closed()

    check("a request of over 4 KB ends the connection", too_large)

    def two_at_once():
        c = Conn()
        c.tls.write(b"GET " + fl.encode() + b" HTTP/1.1\r\nHost: x\r\n\r\n")
        c.tls.write(b"GET " + pg.encode() + b" HTTP/1.1\r\nHost: x\r\n\r\n")
        c.sock.sendall(c.out.read())
        ok = same(c.response(), paths[fl]) and same(c.response(), paths[pg])
        c.close()
        return ok

    check("two requests at once are answered one after the other", two_at_once)

    def half_close():
        c = Conn()
        c.get(big)
        c.sock.shutdown(socket.SHUT_WR)
        ok = same(c.response(), paths[big])
        ok &= c.closed()
        c.close()
        return ok

    check("a client that closes its side after its request gets the file, then the end", half_close)

    def goes_away():
        for _ in range(8):
            c = Conn()
            c.get(big)
            c.more()
            c.close()                   # (with data unread: the client's side resets)
        c = Conn()
        c.get("/")
        return same(c.response(), paths["/"])

    check("clients that go away in the middle of a file", goes_away)

    # In an image built with KEYLIFE=n a connection's key seals 2^n records and no more
    # than one response beyond; with STLIFE=n a client sends 2^n records and no more (in a
    # real image n is 24 and 32: too many to wait for here)
    if os.environ.get("KEYLIFE"):
        def key_life():
            c = Conn()
            c.get(big)                  # (1,110 records at least)
            ok = same(c.response(), paths[big])
            c.get(big)                  # this one is still answered, in full,
            ok &= same(c.response(), paths[big])
            ok &= c.closed()            # and then the server ends the connection
            c2 = Conn()
            c2.get("/")
            return ok and same(c2.response(), paths["/"])

        check("a connection whose key has sealed its share of records is ended after the response in hand", key_life)

    if os.environ.get("STLIFE"):
        def st_life():
            lim = 1 << int(os.environ["STLIFE"])
            c = Conn()
            for _ in range(lim - 2):
                c.send(b"\0")
            c.get("/")                  # the (lim - 1)th record: connection stays open
            ok = same(c.response(), paths["/"])
            c.get("/")                  # the lim-th record: answered, then closed
            ok &= same(c.response(), paths["/"]) and c.closed()
            c.close()
            c2 = Conn()                 # and two records in one segment across the limit:
            for _ in range(lim - 1):    # the one after the limit is not taken
                c2.send(b"\0")
            req = b"GET / HTTP/1.1\r\nHost: " + NAME.encode() + b"\r\n\r\n"
            c2.tls.write(req)
            c2.tls.write(req)
            c2.sock.sendall(c2.out.read())
            ok &= same(c2.response(), paths["/"]) and c2.closed()
            c2.close()
            c3 = Conn()
            c3.get("/")
            ok &= same(c3.response(), paths["/"])
            c3.close()
            return ok

        check("a connection whose client has sent its share of records is ended after that record", st_life)

    # A client that vanishes in the middle of a file, and one that only stops reading (GONE=1:
    # over tap, as root in tap.sh's namespace; two or three minutes). What the first sends
    # from then on is dropped on its way out, so the server hears nothing more of it, while
    # what the server sends still arrives: it is sent to again for a while and then given
    # up, with a reset. That reset is watched for on the wire: the client's own TCP need not
    # take it (its number is the last one the server got to, which is the client's next only
    # if all of that arrived). The second client takes nothing more either, but says so
    # whenever it is sent to: it must still be there afterwards, and get its file.
    if os.environ.get("GONE"):
        def vanish():
            src, held = "10.0.2.40", "/size/70000.bin"
            resets = []                 # (when the server reset the one that vanished)

            def watch():
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
                a, b = socket.inet_aton(HOST), socket.inet_aton(src)
                while not resets:
                    f = s.recv(2048)
                    if f[23] == 6 and f[26:30] == a and f[30:34] == b and f[14 + (f[14] & 15) * 4 + 13] & 4:
                        resets.append(time.time())

            threading.Thread(target=watch, daemon=True).start()
            stays = Conn(rcvbuf=4096)
            stays.get(held)
            c = Conn(rcvbuf=4096, src=src)
            c.get(big)
            time.sleep(1)               # (the window of each is shut by now)
            subprocess.run(["ip", "rule", "add", "blackhole", "from", src], check=True)
            t0 = time.time()
            while not resets and time.time() - t0 < 170:
                time.sleep(0.5)
            subprocess.run(["ip", "rule", "del", "blackhole", "from", src])
            if not resets or resets[0] - t0 < 50:
                raise AssertionError("given up after %.0f s" % (resets[0] - t0) if resets else "not given up in 170 s")
            ok = same(stays.response(), paths[held])    # (it has waited all that time)
            c2 = Conn()
            c2.get("/")
            return ok and same(c2.response(), paths["/"])

        check("a client that vanishes is given up after a minute or two, one that only stops reading is not", vanish)
    check("and after all that, the page", lambda: fresh() or True)
    print("FAILED: " + "; ".join(FAILED) if FAILED else "all ok")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
