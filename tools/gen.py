#!/usr/bin/env python3
"""Build-time generator: certificate chain, signing key, curve programs. (What is served
is tools/pack.py's business.)

Usage: gen.py build/

The server's identity comes from cert/ (or the directory $CERT names):
  cert/server.key   its private key (PEM, must be ECDSA P-256)
  cert/server.pem   its certificate, followed by any intermediates (PEM)
  cert/ca.pem       the root to trust in tests, if it is not a public one
If they are missing, a private CA (cert/ca.pem: there is no CA key, see make_identity) and
the smallest leaf we found that curl, Chrome and Firefox accept are made, for NAME (default
127.0.0.1; an IP address or a DNS name) and the further names of SAN (blanks between
them). To serve with a real certificate instead, drop its two files into cert/.
Nothing here ever renews: the certificate is baked into the image.

Outputs: build/gen.inc (TLS blobs), build/ec.inc (curve programs), build/step.inc (the ladder's step), build/regs.inc
(curve constants and the private key: the image is a secret), build/ca.pem (what clients must trust; empty if the
chain is a real one) and build/name (the host name to test with, and what port 80 sends
everybody to: NAME if the certificate is for it, else the first name the certificate has).
"""
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ec as curve  # noqa: E402

CERT = os.environ.get("CERT", "cert")


def tlv(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + body


def put(path, data, secret=False):
    """Write a file; one that holds the private key for its owner's eyes only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if secret else 0o666)
    if secret:
        os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def ec_add(P, Q):
    """P-256 points in affine coordinates (None = infinity)."""
    p = curve.P256
    if P is None or Q is None:
        return P or Q
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] - 3) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return x, (lam * (P[0] - x) - P[1]) % p


def ec_mul(k, P):
    acc = None
    while k:
        if k & 1:
            acc = ec_add(acc, P)
        P, k = ec_add(P, P), k >> 1
    return acc


ECDSA_SHA256 = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040302")))
EC_P256 = tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d0201")) + tlv(0x06, bytes.fromhex("2a8648ce3d030107")))
VALIDITY = tlv(0x30, tlv(0x17, b"260101000000Z") + tlv(0x17, b"491231000000Z"))


def general_name(name):
    try:
        return tlv(0x87, ipaddress.ip_address(name).packed)
    except ValueError:
        return tlv(0x82, name.encode())


def covers(pattern, name):
    """Is a certificate's name (maybe *.something) good for this one?"""
    pattern, name = pattern.lower().rstrip("."), name.lower().rstrip(".")
    if pattern.startswith("*."):
        return "." in name and name.split(".", 1)[1] == pattern[2:]
    return pattern == name


def make_identity(names):
    """A leaf certificate for `names` and the CA that signed it: cert/server.key, .pem, ca.pem.

    The leaf is the smallest X.509 we found that curl, Chrome and Firefox accept under a
    trusted CA: v3 (the subjectAltName needs it), empty subject, one extension, and an 8-byte
    signature. The last works because the CA signs nothing else, so we may pick the signature
    first and the CA's key second: take the curve point R with the smallest x coordinate as
    the nonce point, so r = x(R) is tiny, set s = 1, and solve the verification equation
    R = (z G + r Q) / s for the CA's public key Q = (R - z G) / r. That is a perfectly valid
    ECDSA signature under Q. Nobody knows log R, so nobody (us included) knows Q's private
    key: this CA can never sign a second certificate, which makes it harmless to trust.
    (Its own self-signature is a dummy for the same reason; no client checks a trust
    anchor's.)
    """
    key = ec.generate_private_key(ec.SECP256R1())
    # (a compressed point would save 32 bytes: curl takes it, Firefox says
    # SEC_ERROR_UNSUPPORTED_EC_POINT_FORM once the chain is trusted)
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    spki = tlv(0x30, EC_P256 + tlv(0x03, b"\x00" + point))
    gn = b"".join(general_name(n) for n in names)
    # critical, as RFC 5280 wants with an empty subject (Chrome: INVALID otherwise)
    san = tlv(0x30, tlv(0x06, b"\x55\x1d\x11") + tlv(0x01, b"\xff") + tlv(0x04, tlv(0x30, gn)))
    # The CA's name: one attribute, OID 2.5.4 = "". (An empty name: curl and Firefox refuse,
    # MOZILLA_PKIX_ERROR_EMPTY_ISSUER_NAME. Firefox calls a 1-byte OID bad DER.)
    ca_name = tlv(0x30, tlv(0x31, tlv(0x30, tlv(0x06, b"\x55\x04") + tlv(0x13, b""))))
    tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01") + ECDSA_SHA256
              + ca_name + VALIDITY + tlv(0x30, b"") + spki + tlv(0xa3, tlv(0x30, san)))

    p, n = curve.P256, curve.N256
    h = hashes.Hash(hashes.SHA256())
    h.update(tbs)
    z = int.from_bytes(h.finalize(), "big")
    r = 1
    while pow((r ** 3 - 3 * r + curve.B256) % p, (p - 1) // 2, p) != 1:
        r += 1
    R = (r, pow((r ** 3 - 3 * r + curve.B256) % p, (p + 1) // 4, p))
    Q = ec_mul(pow(r, -1, n), ec_add(R, ec_mul(n - z % n, (curve.GX256, curve.GY256))))
    sig = tlv(0x30, tlv(0x02, bytes([r])) + tlv(0x02, b"\x01"))
    ca_pub = ec.EllipticCurvePublicNumbers(Q[0], Q[1], ec.SECP256R1()).public_key()
    ca_pub.verify(sig, tbs, ec.ECDSA(hashes.SHA256()))  # raises if the trick went wrong
    leaf = tlv(0x30, tbs + ECDSA_SHA256 + tlv(0x03, b"\x00" + sig))

    # the CA: an ordinary root certificate around Q
    ca_spki = tlv(0x30, EC_P256 + tlv(0x03, b"\x00" + ca_pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)))
    ca_ext = (tlv(0x30, tlv(0x06, b"\x55\x1d\x13") + tlv(0x01, b"\xff") + tlv(0x04, tlv(0x30, tlv(0x01, b"\xff"))))
              + tlv(0x30, tlv(0x06, b"\x55\x1d\x0f") + tlv(0x01, b"\xff") + tlv(0x04, tlv(0x03, b"\x01\x06"))))
    ca_tbs = tlv(0x30, tlv(0xa0, tlv(0x02, b"\x02")) + tlv(0x02, os.urandom(8).hex().encode()[:8]) + ECDSA_SHA256
                 + ca_name + VALIDITY + ca_name + ca_spki + tlv(0xa3, tlv(0x30, ca_ext)))
    ca = tlv(0x30, ca_tbs + ECDSA_SHA256 + tlv(0x03, b"\x00" + tlv(0x30, tlv(0x02, b"\x01") + tlv(0x02, b"\x01"))))

    os.makedirs(CERT, exist_ok=True)
    put(f"{CERT}/server.key", private_pem(key), secret=True)
    for path, der in ((f"{CERT}/server.pem", leaf), (f"{CERT}/ca.pem", ca)):
        put(path, x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM))


def db(name, data):
    return f"global {name}\n{name}: db {','.join(str(b) for b in data)}\n{name}_LEN equ $ - {name}\n"


def le(v, n=32):
    return v.to_bytes(n, "little")


def main(out):
    # KEYLESS=1: an image without its key, from the certificates alone. It is what anybody
    # can make who has no key, and the same bytes as the image that has it, but for the
    # key's 32: for comparing (tools/repro.sh), not for running: it cannot sign.
    if os.environ.get("KEYLESS"):
        if not os.path.exists(f"{CERT}/server.pem"):
            sys.exit(f"gen.py: KEYLESS=1 makes an image from the certificates in {CERT}/server.pem, and there are none")
        chain = x509.load_pem_x509_certificates(open(f"{CERT}/server.pem", "rb").read())
        d = 0
    else:
        if not (os.path.exists(f"{CERT}/server.key") and os.path.exists(f"{CERT}/server.pem")):
            make_identity([os.environ.get("NAME") or "127.0.0.1"] + os.environ.get("SAN", "").split())
        key = serialization.load_pem_private_key(open(f"{CERT}/server.key", "rb").read(), None)
        chain = x509.load_pem_x509_certificates(open(f"{CERT}/server.pem", "rb").read())
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            sys.exit("gen.py: cert/server.key must be an ECDSA P-256 key")
        if key.public_key().public_numbers() != chain[0].public_key().public_numbers():
            sys.exit("gen.py: cert/server.key does not match the first certificate in cert/server.pem")
        d = key.private_numbers().private_value

    # what to trust and what to call the server when testing
    private = os.path.exists(f"{CERT}/ca.pem") and chain[-1].issuer == x509.load_pem_x509_certificate(
        open(f"{CERT}/ca.pem", "rb").read()).subject
    put(f"{out}/ca.pem", open(f"{CERT}/ca.pem", "rb").read() if private else b"")
    san = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = [str(n.value) for n in san]
    # (a certificate from elsewhere has its names in an order of its own: Let's Encrypt's
    # are sorted. The one that was asked for is the one, if it is among them.)
    asked = os.environ.get("NAME", "")
    first = asked if asked and any(covers(n, asked) for n in names) else names[0] if names else ""
    put(f"{out}/name", first.encode())

    # EncryptedExtensions (empty) + Certificate message, as one constant blob
    ee = bytes([8, 0, 0, 2, 0, 0])
    entries = b""
    for c in chain:
        der = c.public_bytes(serialization.Encoding.DER)
        entries += len(der).to_bytes(3, "big") + der + b"\0\0"
    body = b"\0" + len(entries).to_bytes(3, "big") + entries
    certmsg = bytes([11]) + len(body).to_bytes(3, "big") + body

    with open(f"{out}/conf.inc", "w") as f:  # what the code needs to know before it is assembled
        f.write(f"; generated by tools/gen.py\n%assign CHAIN_LEN {len(ee + certmsg)}\n")
    with open(f"{out}/gen.inc", "w") as f:
        f.write("; generated by tools/gen.py\n")
        f.write(db("EECERT", ee + certmsg))

    R = curve.R
    with open(f"{out}/ec.inc", "w") as f:
        f.write("; generated by tools/gen.py from tools/ec.py: curve programs\n")
        at = 0  # (the asm runs XPOST on from XPRE, and unpacks
        for name, prog in curve.PROGRAMS.items():  # them all in one go: keep them together)
            f.write(db(name, prog) + f"global X_{name}\nX_{name} equ XP + {at}\n")
            at += 8 * (len(prog) - 1) + 4          # unpacked: 16 bytes for 2, and 4 at the end
        f.write(f"NPROG equ {len(curve.PROGRAMS)}\n" + db("NSQ", bytes(curve.NSQ)))
    with open(f"{out}/step.inc", "w") as f:
        f.write("; generated by tools/gen.py from tools/ec.py: the ladder's step (STEP25519) as calls\n"
                + curve.straight(curve.STEP25519))
    # What boot (`ecinit`) reads, in this order: P-256's G, times R; what it can't compute of
    # the group order n (its low half, and -1/n mod 2^64); the base point of edwards25519;
    # our private key d, times R mod n; and 2 d of edwards25519 (the two fill registers D, C)
    put(f"{out}/regs.inc", ("; generated by tools/gen.py: SECRET (holds the private key)\n"
                            + db("REGC", le(curve.GX256 * R % curve.P256) + le(curve.GY256 * R % curve.P256))
                            + db("NLOW", le(curve.N256 % (1 << 128), 16) + le(curve.FN256.minv, 8))
                            + db("EDC", le(curve.BX25519) + le(curve.BY25519) + le(d * R % curve.N256)
                                 + le(2 * curve.D25519 % curve.P25519))).encode(), secret=True)


if __name__ == "__main__":
    main(sys.argv[-1])
