#!/usr/bin/env python3
"""Check the asm crypto (run via build/test_asm) against pyca/cryptography."""
import hashlib
import os
import hmac
import subprocess
import sys

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

m = bytes((i * 7 + 3) & 255 for i in range(2000))
exp = {}
for n in (0, 3, 55, 56, 63, 64, 119, 1000, 1999):
    exp[f"sha{n}"] = hashlib.sha256(m[:n]).digest()
exp["hmac"] = hmac.new(m[:32], m[32:82], hashlib.sha256).digest()
info = b"\x00\x20" + b"\x0dtls13 derived" + b"\x20" + m[100:132] + b"\x01"
exp["expand"] = hmac.new(m[:32], info, hashlib.sha256).digest()
sk = X25519PrivateKey.from_private_bytes(bytes(32))
key, iv = m[300:332], m[400:412]
for i, n in enumerate((1, 100, 1500, 15, 16, 17, 63, 64, 65, 128)):
    seq = i * 77
    nonce = iv[:4] + bytes(a ^ b for a, b in zip(iv[4:], seq.to_bytes(8, "big")))
    hdr = bytes([0x17, 3, 3]) + (n + 16).to_bytes(2, "big")
    exp[f"gcm{n}_{seq}"] = hdr + AESGCM(key[:16]).encrypt(nonce, m[:n], hdr)
    exp[f"ungcm{n}_{seq}"] = m[:n] + exp[f"gcm{n}_{seq}"][-16:]   # decrypted again, and its tag

got = {}
for line in subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True).stdout.splitlines():
    tag, val = line.split()
    got[tag] = bytes.fromhex(val)

bad = 0
for tag, want in exp.items():
    ok = got.get(tag) == want
    bad += not ok
    print(("ok  " if ok else "FAIL"), tag)

# the field arithmetic against the model in tools/ec.py: the same numbers as test_asm.c
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ec as curve  # noqa: E402
mach = curve.Machine()
fbad = 0
for f, field in enumerate((curve.F25519, curve.FP256, curve.FN256)):
    mach.f = field
    R, M = curve.R, field.M
    NM = R - M
    vals = [0, 1, 2, R - 1, R - 2, M, M - 1, (M + 1) % R if (M & (2**64 - 1)) != 2**64 - 1 else M - (2**64 - 1), NM, NM - 1, NM + 1,
            1 << 255, (1 << 255) - 1, (1 << 64) - 1, 1 << 192, ((M >> 192) << 192) | ((1 << 192) - 1), (M >> 192) << 192]
    vals += [int.from_bytes(m[100 + 40 * j + 7 * f:132 + 40 * j + 7 * f], "little") for j in range(5)]
    for j, x in enumerate(vals):
        mach.inv(x)
        if got.get(f"f{f}_inv_{j}") != mach.r[curve.REG["T1"]].to_bytes(32, "little"):
            fbad += 1
            if fbad < 5:
                print("FAIL", f"f{f}_inv_{j}", hex(x))
        if got.get(f"f{f}_sqr_{j}") != mach.mul(x, x).to_bytes(32, "little"):
            fbad += 1
            if fbad < 5:
                print("FAIL", f"f{f}_sqr_{j}", hex(x))
        for k, y in enumerate(vals):
            if got.get(f"f{f}_mul1_{j}_{k}") != mach.mul(x % curve.W, y).to_bytes(32, "little"):
                fbad += 1
                if fbad < 5:
                    print("FAIL", f"f{f}_mul1_{j}_{k}", hex(x), hex(y))
    for j, x in enumerate(vals):
        for k, y in enumerate(vals):
            for name, fn in (("as", mach.add), ("sub", mach.sub), ("mul", mach.mul)):
                if got.get(f"f{f}_{name}_{j}_{k}") != fn(x, y).to_bytes(32, "little"):
                    fbad += 1
                    if fbad < 5:
                        print("FAIL", f"f{f}_{name}_{j}_{k}", hex(x), hex(y))
bad += fbad
print(("ok  " if not fbad else "FAIL"), "field arithmetic as the model has it (3 fields, 22 x 22 numbers, 3 operations and the product with one limb; square and inverse of the 22)")

# X25519: our scalar is clamped as in RFC 7748, so both our share and the secret match
# OpenSSL's, and points of small order (u = 0 and u = 1) give an all-zero secret
for i in range(6):
    pub, shared = got[f"xpub{i}"], got[f"xshared{i}"]
    e_bytes = bytes([0xff]) * 32 if i == 1 else bytes(32) if i == 2 else m[500 + 40 * i:532 + 40 * i]
    if i >= 4:
        ok = shared == bytes(32)
    else:
        ours = X25519PrivateKey.from_private_bytes(e_bytes)
        ok = pub == ours.public_key().public_bytes_raw() and sk.exchange(X25519PublicKey.from_public_bytes(pub)) == shared
    bad += not ok
    print(("ok  " if ok else "FAIL"), f"x25519_{i}")

# ECDSA: (r, s) must verify under the certificate's key
pub = x509.load_pem_x509_certificates(open(os.path.join(os.environ.get("CERT", "cert"), "server.pem"), "rb").read())[0].public_key()
rs = set()
for i in range(70):
    sig = got[f"sig{i}"]
    z, r, s = sig[:32], int.from_bytes(sig[32:64], "little"), int.from_bytes(sig[64:], "little")
    try:
        pub.verify(utils.encode_dss_signature(r, s), z, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        ok = r not in rs            # (and no nonce twice)
        rs.add(r)
    except (InvalidSignature, ValueError):
        ok = False
    bad += not ok
    if not ok or i < 6:
        print(("ok  " if ok else "FAIL"), f"ecdsa{i}")
# the one whose nonce we chose: r = x(k G) for k = 1 is x(G)
ok = int.from_bytes(got["sig3"][32:64], "little") == curve.GX256
bad += not ok
print(("ok  " if ok else "FAIL"), "ecdsa: 70 signatures, 70 nonces; r of the nonce 1 is x(G)")
sys.exit(1 if bad else 0)
