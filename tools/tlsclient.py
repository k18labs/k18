"""Shared TLS test client pieces: an SSLContext against $B/ca.pem, a ClientHello record as
OpenSSL makes it, and a TLS connection over a MemoryBIO pair so a caller can also read or
write the underlying TCP socket directly."""
import os
import ssl

B = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", os.environ.get("B", "build"))
NAME = open(os.path.join(B, "name")).read()
# SHA-256("HelloRetryRequest"): what a ServerHello has for its random when it is one
HRR = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def context(groups=None):
    """Every test connection verifies the server's chain (against our private CA, or the
    system's roots if $B/ca.pem is empty) and name."""
    ca = os.path.join(B, "ca.pem")
    ctx = ssl.create_default_context(cafile=ca if os.path.getsize(ca) else None)
    # (Python >= 3.13 turns on OpenSSL's RFC 5280 strictness, which wants an authority key
    # identifier in the leaf: 14+ bytes that curl, Chrome and Firefox don't ask for.)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if os.environ.get("SSLKEYLOGFILE"):
        ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
    if groups:
        ctx.set_ecdh_curve(groups)
    return ctx


def hello_record(ctx=None, groups=None):
    """One ClientHello record as OpenSSL makes it."""
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = (ctx or context(groups)).wrap_bio(inc, out, server_hostname=NAME)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


class BioClient:
    """A TLS client over a TCP socket we also hold: raw bytes can be slipped in or cut into pieces."""

    def __init__(self, sock, ctx=None, eof_ok=False):
        self.sock = sock
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = (ctx or context()).wrap_bio(self.inc, self.out, server_hostname=NAME)
        self.eof_ok = eof_ok

    def pump(self, op):
        while True:
            try:
                res = op()
            except ssl.SSLWantReadError:
                res = None
            except ssl.SSLZeroReturnError:
                if not self.eof_ok:
                    raise
                return b""
            data = self.out.read()
            if data:
                self.sock.sendall(data)
            if res is not None:
                return res
            got = self.sock.recv(65536)
            if not got:
                if not self.eof_ok:
                    raise ConnectionError("closed")
                return b""
            self.inc.write(got)

    def handshake(self):
        self.pump(lambda: self.tls.do_handshake() or True)

    def close(self):
        self.sock.close()
