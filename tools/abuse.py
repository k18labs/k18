#!/usr/bin/env python3
"""Hostile-client checks. QEMU must be serving on 127.0.0.1:$PORT. Exit 0 if all hold:

  1. forged, truncated and replayed records inside a real TLS connection are ignored, and
     the connection still serves the next real request (so they moved no sequence number)
  2. a ClientHello without an x25519 key share gets no working session, and one with bytes
     that look like the start of one in another extension is served all the same; a
     client that can't be served (no TLS 1.3, not our cipher suite, no x25519, no
     share for it after being asked, a share of small order, a session id of more
     than 32 bytes, a first message that is no ClientHello or not as long as it says,
     compression methods other than the one that is none) gets a fatal alert that
     says why, and the end of the connection: nothing that only looks like an answer;
     and a ServerHello's version is 03 03 whatever the client's legacy_version is
  3. junk instead of a ClientHello, an oversized "ClientHello", and a real one cut short
     anywhere or with any of its lengths gone wrong, do no harm
  4. after all of that a normal client is still served
  6. what is not GET or HEAD but begins like a request, whatever its letters, gets the
     405 and the end of the connection; a record whose inside is zeros to its last byte
     (no content type) is the connection's end
  5. plain HTTP on port 80 (127.0.0.1:$HPORT): a request in pieces gets one response, two
     or 200 in one segment get them all, bytes without an empty line get none

Uses Python's ssl with memory BIOs, so that raw bytes can be slipped into the TCP stream
between TLS records.
"""
import os
import socket
import ssl
import sys
import tempfile
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tlsclient import B as BUILD, HRR, BioClient, context, hello_record

HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8443"))
HPORT = int(os.environ.get("HPORT", PORT + 1000))
EXPECT = open(os.path.join(BUILD, "..", "www", "index.html"), "rb").read()
P80 = open(os.path.join(BUILD, "page80.bin"), "rb").read()      # what port 80 says to every request
REQ = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


class Client(BioClient):
    """A TLS client whose TCP stream we can also write to directly."""

    def __init__(self, ctx):
        super().__init__(socket.create_connection((HOST, PORT), timeout=5), ctx)

    def fetch(self):
        self.pump(lambda: self.tls.write(REQ))
        buf = b""
        while not buf.endswith(EXPECT):
            buf += self.pump(lambda: self.tls.read(4096))
        return True

    def last_record(self):
        """Encrypt one request and return the record instead of sending it."""
        self.tls.write(REQ)
        return self.out.read()


def served(ctx=None):
    try:
        c = Client(ctx or context())
        c.handshake()
        ok = c.fetch()
        c.close()
        return ok
    except (OSError, ssl.SSLError):
        return False


def client_hello():
    """The ClientHello this machine's TLS sends (the handshake message, without the record header)."""
    rec = hello_record()
    assert rec[0] == 22 and rec[5] == 1 and int.from_bytes(rec[3:5], "big") == len(rec) - 5, "one record with a ClientHello"
    return rec[5:]


def lengths(hello):
    """(offset, size) of every length field in a ClientHello: the message's own, session id,
    cipher suites, compression methods, extensions, each extension, and inside the key
    share extension the list and each share."""
    out = [(1, 3)]
    p = 38
    out.append((p, 1))
    p += 1 + hello[p]
    out.append((p, 2))
    p += 2 + int.from_bytes(hello[p:p + 2], "big")
    out.append((p, 1))
    p += 1 + hello[p]
    out.append((p, 2))
    p += 2
    while p + 4 <= len(hello):
        kind, n = int.from_bytes(hello[p:p + 2], "big"), int.from_bytes(hello[p + 2:p + 4], "big")
        out.append((p + 2, 2))
        if kind == 51:
            out.append((p + 4, 2))
            q = p + 6
            while q + 4 <= p + 4 + n:
                out.append((q + 2, 2))
                q += 4 + int.from_bytes(hello[q + 2:q + 4], "big")
        p += 4 + n
    assert p == len(hello), "a ClientHello as we know them"
    return out


def check(name, ok):
    print(("ok  " if ok else "FAIL"), name)
    return ok


def main():
    good = True
    good &= check("a normal client is served", served())

    # 1. junk records inside a real connection
    c = Client(context())
    c.handshake()
    good &= check("first request", c.fetch())
    c.sock.sendall(bytes([23, 3, 3, 0, 5]) + os.urandom(5))            # shorter than a tag
    c.sock.sendall(bytes([23, 3, 3, 0, 16]) + os.urandom(16))          # a tag and nothing else
    c.sock.sendall(bytes([23, 3, 3, 0, 60]) + os.urandom(60))          # forged request
    c.sock.sendall(bytes([21, 3, 3, 0, 2, 2, 40]))                     # plaintext alert
    good &= check("request after forged records", c.fetch())
    rec = c.last_record()
    # The replay goes out with the next real request behind it, in one segment (the server
    # can't take requests pipelined over several: our seq = their ack). No waiting for an
    # answer that must not come: the server answers in order and closes after our FIN, so
    # all it sends must be exactly two responses that decrypt in sequence.
    buf = b""
    try:
        c.sock.sendall(rec + rec + c.last_record())
        while buf.count(EXPECT) < 2:
            buf += c.pump(lambda: c.tls.read(4096))
        c.sock.shutdown(socket.SHUT_WR)
        while True:
            buf += c.pump(lambda: c.tls.read(4096))
    except ConnectionError:
        pass
    except (OSError, ssl.SSLError) as e:
        buf = b"error %r" % e
    good &= check("a replayed record gets no answer, the request after it does",
                  buf.count(EXPECT) == 2)
    c.close()

    # 2. no x25519 share
    good &= check("a client offering only P-256 gets no session", not served(context("prime256v1")))

    # 2b. The four bytes that introduce an x25519 key share (group 29, 32 bytes long) in an
    # extension that comes before the key shares. The share was once looked for by those
    # bytes alone; a client's other key shares are a kilobyte of random-looking bytes these
    # days, and had them once in two million handshakes (the server then took the wrong
    # 32 bytes for the key, and the client could not read the answer).
    decoy = context()
    decoy.set_alpn_protocols(["\x00\x1d\x00 " + "k" * 32])
    good &= check("the key share is found behind an extension that looks like its start", served(decoy))

    # 2c. A ClientHello without an x25519 share is asked for another one (HelloRetryRequest).
    # What comes instead must do no harm: the same again, junk, nothing but the
    # ChangeCipherSpec records clients put in front of a second ClientHello.
    hello = client_hello()
    p = 38
    p += 1 + hello[p]
    p += 2 + int.from_bytes(hello[p:p + 2], "big")
    p += 1 + hello[p] + 2
    shareless = bytearray(hello)
    share_at = None
    while p + 4 <= len(hello):
        kind, n = int.from_bytes(hello[p:p + 2], "big"), int.from_bytes(hello[p + 2:p + 4], "big")
        if kind == 51:
            q = p + 6
            while q + 4 <= p + 4 + n:
                if hello[q:q + 2] == b"\x00\x1d":
                    share_at = q + 4
                    shareless[q:q + 2] = b"\x01\x00"        # (a group we don't have)
                q += 4 + int.from_bytes(hello[q + 2:q + 4], "big")
        p += 4 + n
    assert share_at is not None, "an x25519 share in ClientHello"
    shareless = bytes([22, 3, 1]) + len(shareless).to_bytes(2, "big") + bytes(shareless)
    ccs = bytes([20, 3, 3, 0, 1, 1])
    asked = True
    for second in (shareless, ccs + shareless, os.urandom(600), ccs * 500, bytes([22, 3, 3, 0, 0]), b""):
        s = socket.create_connection((HOST, PORT), timeout=5)
        try:
            s.sendall(shareless)
            got = s.recv(4096)
            asked &= got[:1] == b"\x16" and got[11:43] == HRR
            s.sendall(second)
            s.shutdown(socket.SHUT_WR)
            s.settimeout(1)
            while s.recv(4096):
                pass
        except OSError:
            pass
        s.close()
    good &= check("a ClientHello without an x25519 share is asked for another", asked)
    good &= check("still serving after six that sent something else instead", served())

    # 2d. Clients we can't serve: each gets seven bytes, a fatal alert with the reason, and
    # then the connection's end.
    def said(first, second=None):
        """What the server sends for these records, up to its closing the connection."""
        s = socket.create_connection((HOST, PORT), timeout=5)
        got = b""
        try:
            s.sendall(first)
            if second is not None:
                got = s.recv(4096)                  # (the HelloRetryRequest)
                s.sendall(second)
                got = b""
            while True:
                more = s.recv(4096)
                if not more:
                    break
                got += more
        except OSError as e:
            got += b" %r" % e
        s.close()
        return got

    def record(body):
        return bytes([22, 3, 1]) + len(body).to_bytes(2, "big") + bytes(body)

    PROTOCOL_VERSION = bytes.fromhex("15030300020246")
    HANDSHAKE_FAILURE = bytes.fromhex("15030300020228")
    ILLEGAL_PARAMETER = bytes.fromhex("1503030002022f")
    old = context()
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    good &= check("a client without TLS 1.3 is told \"protocol version\", and that is all",
                  said(hello_record(old)) == PROTOCOL_VERSION)
    other = bytearray(hello)                    # our cipher suite becomes one we don't have
    p = 38
    p += 1 + hello[p]
    for q in range(p + 2, p + 2 + int.from_bytes(hello[p:p + 2], "big"), 2):
        if hello[q:q + 2] == b"\x13\x01":
            other[q:q + 2] = b"\x13\x02"
    good &= check("one that does not name our cipher suite is told \"handshake failure\"",
                  said(record(other)) == HANDSHAKE_FAILURE)

    # A client gets AES-128-GCM (13 01) wherever it names it, and nothing else: ChaCha20-
    # Poly1305 (13 03) first, or alone, is a suite like any we don't have. What else stands
    # in its list (a made-up suite in front, as browsers put one: GREASE; suites of TLS
    # 1.2) is passed over.
    def chosen(suites):
        """The cipher suite in the ServerHello for this machine's ClientHello with these suites."""
        p = 38 + 1 + hello[38]
        body = hello[:p] + len(suites).to_bytes(2, "big") + suites + hello[p + 2 + int.from_bytes(hello[p:p + 2], "big"):]
        body = body[:1] + (len(body) - 4).to_bytes(3, "big") + body[4:]
        s = socket.create_connection((HOST, PORT), timeout=5)
        got = b""
        try:
            s.sendall(record(body))
            while len(got) < 5 + 4 + 2 + 32 + 1 + hello[38] + 2:
                more = s.recv(4096)
                if not more:
                    break
                got += more
        except OSError:
            pass
        s.close()
        at = 5 + 4 + 2 + 32 + 1 + hello[38]
        return got[at:at + 2].hex() if got[:1] == b"\x16" and got[5:6] == b"\x02" else got[:7].hex()

    for name, suites, want in (
            ("OpenSSL's order (AES-256, ChaCha20, AES-128)", "130213031301", "1301"),
            ("a browser's (a made-up suite, AES-128, AES-256, ChaCha20)", "0a0a130113021303", "1301"),
            ("ChaCha20 first, then AES-128", "13031301", "1301"),
            ("suites of TLS 1.2 and a made-up one, then ChaCha20, then AES-128", "c02bcca9fafa13031301", "1301"),
            ("AES-128 last of many", "c02bc02fcca9cca8130213041305009c1301", "1301"),
            ("ChaCha20 alone", "1303", HANDSHAKE_FAILURE.hex()),
            ("AES-256 and ChaCha20, no AES-128", "13021303", HANDSHAKE_FAILURE.hex()),
            ("AES-128's two bytes across two suites, 01 13 01 00", "01130100", HANDSHAKE_FAILURE.hex())):
        told = "gets AES-128-GCM" if want == "1301" else 'is told "handshake failure"'
        good &= check(f"a client that names {name} {told}",
                      chosen(bytes.fromhex(suites)) == want)
    groupless = bytearray(shareless[5:])        # x25519 is not among its groups either
    p = 38
    p += 1 + hello[p]
    p += 2 + int.from_bytes(hello[p:p + 2], "big")
    p += 1 + hello[p] + 2
    while p + 4 <= len(hello):
        kind, n = int.from_bytes(hello[p:p + 2], "big"), int.from_bytes(hello[p + 2:p + 4], "big")
        if kind == 10:
            for q in range(p + 6, p + 4 + n, 2):
                if hello[q:q + 2] == b"\x00\x1d":
                    groupless[q:q + 2] = b"\x01\x00"
        p += 4 + n
    good &= check("one that has no x25519 is told \"handshake failure\"",
                  said(record(groupless)) == HANDSHAKE_FAILURE)
    good &= check("one that was asked for an x25519 share and sent none is told \"handshake failure\"",
                  said(shareless, ccs + shareless) == HANDSHAKE_FAILURE)

    def with_share(u):
        return record(hello[:share_at] + u + hello[share_at + 32:])

    good &= check("an all-zero x25519 key share is told \"illegal parameter\"",
                  said(with_share(bytes(32))) == ILLEGAL_PARAMETER)
    good &= check("an x25519 key share of 1 (order 4 on the twist) is told \"illegal parameter\"",
                  said(with_share(b"\x01" + bytes(31))) == ILLEGAL_PARAMETER)
    good &= check("and so is one sent after being asked",
                  said(shareless, ccs + with_share(b"\x01" + bytes(31))) == ILLEGAL_PARAMETER)
    # (a session id is 32 bytes at most: the ServerHello that had a longer one's had lengths
    # that did not say what followed them, until 2026-11-21)
    def with_sid(n):
        return record(hello[:1] + (len(hello) - 4 + n - hello[38]).to_bytes(3, "big") + hello[4:38]
                      + bytes([n]) + os.urandom(n) + hello[39 + hello[38]:])

    DECODE_ERROR = bytes.fromhex("15030300020232")
    good &= check("a session id of 33 bytes is told \"decode error\", and so is one of 255",
                  said(with_sid(33)) == DECODE_ERROR and said(with_sid(255)) == DECODE_ERROR)
    s = socket.create_connection((HOST, PORT), timeout=1)
    s.sendall(with_sid(32))
    flight = b""
    try:
        while len(flight) < 138 or len(flight) < 138 + int.from_bytes(flight[136:138], "big"):
            flight += s.recv(4096) or b"x" * 4096
    except OSError:
        pass
    s.close()
    good &= check("one of 32 bytes gets a ServerHello whose lengths are right, then a ChangeCipherSpec",
                  flight[:5] == bytes([22, 3, 3, 0, 122]) and flight[5:9] == bytes([2, 0, 0, 118])
                  and flight[127:133] == bytes([20, 3, 3, 0, 1, 1])
                  and flight[133] == 23 and int.from_bytes(flight[136:138], "big") == len(flight) - 138)
    good &= check("junk in a handshake record that begins like a ClientHello (01) is told \"protocol version\"",
                  said(record(b"\x01" + os.urandom(299))) == PROTOCOL_VERSION)
    # What a ClientHello has to be besides (RFC 8446, 4 and 4.1.2; until 2026-11-22 each of
    # these got our flight): the first message, type 1; as long as its three bytes say,
    # which is what the record holds; and with one way of compressing, none.
    UNEXPECTED_MESSAGE = bytes.fromhex("1503030002020a")
    good &= check("a first message that is not a ClientHello (a ClientHello with type 2, 0 or 255) is told \"unexpected message\"",
                  all(said(record(bytes([t]) + hello[1:])) == UNEXPECTED_MESSAGE for t in (2, 0, 255)))

    def says(n):
        return hello[:1] + (len(hello) - 4 + n).to_bytes(3, "big") + hello[4:]

    good &= check("a ClientHello that says it is a byte longer than it is, or a byte shorter, or 64 KiB longer, or has a byte "
                  "behind it in its record, is told \"decode error\"",
                  all(said(record(body)) == DECODE_ERROR for body in (says(1), says(-1), says(1 << 16), hello + b"\0")))
    cm = 38 + 1 + hello[38]
    cm += 2 + int.from_bytes(hello[cm:cm + 2], "big")
    assert hello[cm:cm + 2] == b"\x01\x00", "one compression method, none"

    def compressing(methods):
        body = hello[:cm] + bytes([len(methods)]) + methods + hello[cm + 2:]
        return record(body[:1] + (len(body) - 4).to_bytes(3, "big") + body[4:])

    good &= check("compression methods that are not the one that is none (01; 00 01; 01 00; none at all) are told \"illegal parameter\"",
                  all(said(compressing(m)) == ILLEGAL_PARAMETER for m in (b"\x01", b"\x00\x01", b"\x01\x00", b"")))
    # (a ServerHello's legacy_version is 03 03, RFC 8446, 4.1.3: ours was the client's)
    def version_back(first):
        s = socket.create_connection((HOST, PORT), timeout=5)
        got = b""
        try:
            s.sendall(first)
            while len(got) < 11:
                got += s.recv(4096) or b"x" * 11
        except OSError:
            pass
        s.close()
        return got[:3] + got[5:6] + got[9:11]

    old1 = record(hello[:4] + b"\x03\x01" + hello[6:])
    old2 = shareless[:9] + b"\x02\x00" + shareless[11:]
    good &= check("a ClientHello whose legacy_version is 03 01 gets a ServerHello that says 03 03, and so does one that is asked again",
                  version_back(old1) == bytes.fromhex("160303020303") and version_back(old2) == bytes.fromhex("160303020303"))
    good &= check("and a normal client is served after them", served())

    # 3. junk and oversized hellos
    for name, data in (("random bytes", os.urandom(3000)),
                       ("a 16 KB ClientHello record", bytes([22, 3, 1, 0x40, 0]) + os.urandom(9000)),
                       ("a ClientHello of zeros", bytes([22, 3, 1, 2, 0]) + bytes(512))):
        s = socket.create_connection((HOST, PORT), timeout=5)
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)      # the server answers a FIN with a FIN: once that
            s.settimeout(1)                 # is here, it has been through all of the junk
            while s.recv(4096):
                pass
        except OSError:
            pass
        s.close()
        good &= check(f"still serving after {name}", served())

    # 3b. A real ClientHello, cut short at every length, and with each of its lengths in
    # turn at its largest: the server walks it to find the key share, and must not walk
    # out of it. (A fault resets the machine: nothing would be served after that.)
    hello = client_hello()
    variants = [hello[:n] for n in range(1, len(hello))]
    for at, size in lengths(hello):
        variants.append(hello[:at] + b"\xff" * size + hello[at + size:])
        variants.append(hello[:at] + b"\x00" * size + hello[at + size:])
    for body in variants:
        s = socket.create_connection((HOST, PORT), timeout=5)
        try:
            s.sendall(bytes([22, 3, 1]) + len(body).to_bytes(2, "big") + body)
        except OSError:
            pass
        s.close()
        time.sleep(0.002)   # (QEMU takes connections one at a time: faster than this, one in 20 waits a second)
    good &= check(f"still serving after {len(variants)} ClientHellos cut short or with a length gone wrong", served())
    good &= check("and the one they were made from is served", served())

    # 6. What begins like a request and is none we answer: a method is any word (RFC 9110,
    # 9.1; until 2026-11-22 only one of up to seven capitals was told no, and "get /" waited
    # for ever). What does not begin like one is passed over, and the next request served.
    def answer(request):
        c = Client(context())
        c.sock.settimeout(2)
        buf = b""
        try:
            c.handshake()
            c.pump(lambda: c.tls.write(request))
            while True:
                buf += c.pump(lambda: c.tls.read(4096))
        except ConnectionError:
            buf += b"[closed]"
        except (OSError, ssl.SSLError) as e:
            buf += b"[%r]" % e
        c.close()
        return buf

    for line in (b"POST / HTTP/1.1", b"get / HTTP/1.1", b"Get / HTTP/1.1", b"PROPFIND / HTTP/1.1", b"M-SEARCH * HTTP/1.1",
                 b"x / HTTP/1.1", b"VERSION-CONTROL /a HTTP/1.1", b"head / HTTP/1.1"):
        got = answer(line + b"\r\nHost: x\r\n\r\n")
        good &= check(f"\"{line.decode()}\" gets the 405 and the connection's end",
                      got.startswith(b"HTTP/1.1 405 ") and got.endswith(b"\r\n\r\n[closed]"))
    c = Client(context())
    c.handshake()
    for none in (b"Host: x\r\n", b"\r\n", b" / HTTP/1.1\r\n", b"Accept: a b c\r\n\r\n", b"word\r\nand more", b"word", b"\x00GET / "):
        c.pump(lambda: c.tls.write(none))
    good &= check("a header's line in a record of its own, an empty line, a word with no space behind it are passed over: "
                  "the request after them is served", c.fetch())
    c.close()

    # 6b. A record under the client's key whose inside is zeros and nothing else has no
    # content type: nobody's record, and the connection's end (RFC 8446, 5.4; until
    # 2026-11-22 it counted like an alert). Python's TLS makes no such record: it is
    # sealed here, with the key OpenSSL writes out. Zeros behind a request are padding.
    def sealed(secret, number, inside):
        def label(name, n):
            info = n.to_bytes(2, "big") + bytes([6 + len(name)]) + b"tls13 " + name + b"\0"
            return HKDFExpand(hashes.SHA256(), n, info).derive(secret)
        iv = (int.from_bytes(label(b"iv", 12), "big") ^ number).to_bytes(12, "big")
        head = bytes([23, 3, 3]) + (len(inside) + 16).to_bytes(2, "big")
        return head + AESGCM(label(b"key", 16)).encrypt(iv, inside, head)

    def keyed():
        """A connection that has fetched the page once, and its client's key (which has sealed one record)."""
        log = tempfile.NamedTemporaryFile()
        ctx = context()
        ctx.keylog_filename = log.name
        c = Client(ctx)
        c.sock.settimeout(2)
        c.handshake()
        c.fetch()
        secret = next(bytes.fromhex(line.split()[2]) for line in open(log.name) if line.startswith("CLIENT_TRAFFIC_SECRET_0 "))
        return c, secret

    def after(records):
        """What comes back for these records, as far as the client's TLS reads it."""
        buf = b""
        try:
            c.sock.sendall(records)
            while True:
                buf += c.pump(lambda: c.tls.read(4096))
        except ConnectionError:
            buf += b"[closed]"
        except (OSError, ssl.SSLError):
            buf += b"[nothing more]"
        c.close()
        return buf

    c, secret = keyed()
    good &= check("a request sealed here, with zeros behind its content type, is answered (so the next check's record is one of the client's)",
                  after(sealed(secret, 1, REQ + b"\x17" + bytes(40))).endswith(EXPECT + b"[nothing more]"))
    for what, inside in (("one zero", bytes(1)), ("300 zeros", bytes(300))):
        c, secret = keyed()
        good &= check(f"a record of the client's whose inside is {what} and no content type is the connection's end",
                      after(sealed(secret, 1, inside) + sealed(secret, 2, REQ + b"\x17")) == b"[closed]")

    # 5. port 80
    def plain(pieces, want):
        """Send the pieces one by one, then FIN; count the responses until the server's FIN."""
        s = socket.create_connection((HOST, HPORT), timeout=5)
        buf = b""
        try:
            for piece in pieces:
                s.sendall(piece)
                time.sleep(0.05)
            s.shutdown(socket.SHUT_WR)
            while got := s.recv(4096):
                buf += got
        except OSError as e:
            buf = b"error %r" % e
        s.close()
        return buf == P80 * want

    good &= check("port 80: a request gets a response", plain([REQ], 1))
    good &= check("port 80: a request in three pieces gets one", plain([REQ[:5], REQ[5:-2], REQ[-2:]], 1))
    good &= check("port 80: two requests at once get two", plain([REQ + REQ], 2))
    good &= check("port 80: 200 requests in one segment all get their responses", plain([b"\n\n" * 200], 200))
    good &= check("port 80: bytes without an empty line get none", plain([os.urandom(64).replace(b"\n", b"x") * 40], 0))
    good &= check("port 80: still serving", plain([REQ], 1))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
