#!/usr/bin/env python3
"""outside.py TEST_ASM WYCHEPROOF_DIR: the asm crypto against vectors made elsewhere.

test_crypto.py checks the asm against inputs written beside it. This asks it what others
ask every implementation: Project Wycheproof's test vectors (github.com/C2SP/wycheproof,
testvectors_v1: `tools/outside.sh fetch` gets them), which are made to sit on the edges
that hand-written arithmetic gets wrong (carries, non-canonical inputs, points of small
order, tags that differ in one bit), and RFC 6979's signatures.

  X25519                  x25519_test.json, all of it: `xdh` clamps our scalar as in RFC 7748,
                          so the shared secret must be the vector's, and our key share what
                          OpenSSL makes of that private key. (Where the secret is all zeros,
                          the client's point being one of small order, `xdh`'s shared division
                          is by zero, so our key share is zeros too; `handshake` refuses such a
                          client with "illegal parameter" before sending anything.)
  AES-128-GCM             aes_gcm_test.json: the vectors with a nonce of 12 bytes, a tag of
                          16, a key of 128 bits and no more than 16 bytes of associated data. `seal` makes its tag
                          over a record's header there; the host build can be given other
                          bytes (`haad` in src/curves.asm). Opened: the plaintext and the tag
                          must be the vector's (a vector that is to be refused: the tag we
                          would ask for is not the one it has). Sealed: the ciphertext and
                          the tag (`seal` wants a byte that says what the others are: the
                          last of the vector's)
  HMAC-SHA256             hmac_sha256_test.json: keys of 32 bytes and messages of up to 64,
                          which is what `hmac` takes
  SHA-256                 against hashlib, every length up to 300 and some longer ones
                          (Wycheproof has no vectors for a bare hash)
  ECDSA P-256             Wycheproof's vectors are for verifiers; we only sign. So: RFC
                          6979's A.2.5 (key, nonce, hash, r and s all given), and for nonces
                          and hashes on the edges (1, n - 1, n + 1, 2^256 - 1, 0, ...) under
                          the image's own key, r and s as OpenSSL's point multiplication and
                          plain arithmetic mod n make them; all of them verified by OpenSSL
Run it with `python3 -I` (the vectors are other people's files): make outside.
"""
import hashlib
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
BIN, VEC = sys.argv[1], sys.argv[2]
jobs = []       # (what, id, command, check(output bytes) -> bool)
skipped = {}


def h(b):
    return b.hex() or "-"


def load(name):
    with open(os.path.join(VEC, name)) as f:
        return json.load(f)["testGroups"]


def x25519():
    for g in load("x25519_test.json"):
        for t in g["tests"]:
            priv, pub, want = (bytes.fromhex(t[k]) for k in ("private", "public", "shared"))
            ours = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()
            jobs.append(("X25519 (Wycheproof)", "%d: %s" % (t["tcId"], t["comment"]), "xdh %s %s" % (h(priv), h(pub)),
                         lambda o, ours=ours, want=want: o[32:] == want and o[:32] == (ours if any(want) else bytes(32))))


def aead():
    what = "AES-128-GCM (Wycheproof)"
    for g in load("aes_gcm_test.json"):
        if g["ivSize"] != 96 or g["tagSize"] != 128 or g["keySize"] != 128:
            skipped[what] = skipped.get(what, 0) + len(g["tests"])
            continue
        for t in g["tests"]:
            key, iv, aad, msg, ct, tag = (bytes.fromhex(t[k]) for k in ("key", "iv", "aad", "msg", "ct", "tag"))
            if len(aad) > 16:
                skipped[what] = skipped.get(what, 0) + 1
                continue
            tid = "%d: %s" % (t["tcId"], t["comment"])
            args = "%s %s %s" % (h(key), h(iv), h(aad))
            if t["result"] == "invalid":
                jobs.append((what, tid, "open %s %s" % (args, h(ct)), lambda o, tag=tag: o[-16:] != tag))
                continue
            jobs.append((what, tid, "open %s %s" % (args, h(ct)), lambda o, msg=msg, tag=tag: o == msg + tag))
            if msg:
                jobs.append((what, tid + " (sealed)", "seal %s %s" % (args, h(msg)), lambda o, ct=ct, tag=tag: o == ct + tag))


def hmac_():
    what = "HMAC-SHA256 (Wycheproof)"
    for g in load("hmac_sha256_test.json"):
        for t in g["tests"]:
            key, msg, tag = (bytes.fromhex(t[k]) for k in ("key", "msg", "tag"))
            if len(key) != 32 or len(msg) > 64:
                skipped[what] = skipped.get(what, 0) + 1
                continue
            n = g["tagSize"] // 8
            good = t["result"] != "invalid"
            jobs.append((what, "%d: %s" % (t["tcId"], t["comment"]), "hmac %s %s" % (h(key), h(msg)),
                         lambda o, tag=tag, n=n, good=good: (o[:n] == tag) == good))


def sha():
    for n in list(range(301)) + [511, 512, 513, 1000, 4095, 4096, 4097, 9999]:
        m = hashlib.shake_128(b"k18 %d" % n).digest(n)
        jobs.append(("SHA-256 (hashlib)", "%d bytes" % n, "sha %s" % h(m), lambda o, m=m: o == hashlib.sha256(m).digest()))


def ecdsa():
    def expect(d, k, z):
        r = ec.derive_private_key(k % N256, ec.SECP256R1()).public_key().public_numbers().x % N256
        return r, (z + r * d) * pow(k, -1, N256) % N256

    def job(what, tid, d, k, z, own, want=None):
        pub = ec.derive_private_key(d, ec.SECP256R1()).public_key()
        want = want or expect(d, k, z)
        zb = z.to_bytes(32, "big")

        def check(o):
            r, s = int.from_bytes(o[:32], "little"), int.from_bytes(o[32:], "little")
            try:
                pub.verify(utils.encode_dss_signature(r, s), zb, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            except Exception:  # noqa: BLE001
                return False
            return (r, s) == want
        dr = "-" if own else h((d * (1 << 256) % N256).to_bytes(32, "little"))
        jobs.append((what, tid, "sign %s %s %s" % (dr, h(k.to_bytes(32, "little")), h(zb)), check))

    # RFC 6979, A.2.5: P-256, SHA-256
    x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    for msg, k, r, s in (
        (b"sample", 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
         0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
         0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8),
        (b"test", 0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
         0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
         0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083)):
        z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
        job("ECDSA P-256 (RFC 6979)", msg.decode(), x, k, z, False, (r, s))
    # the image's own key, nonces and hashes on the edges
    with open(os.path.join(os.environ.get("CERT", "cert"), "server.key"), "rb") as f:
        d = serialization.load_pem_private_key(f.read(), None).private_numbers().private_value
    top = (1 << 256) - 1
    koff = (1 << 255) + top // 15           # (what the table lookup takes off a nonce: tools/ec.py)
    ks = [1, 2, 3, 15, 16, 17, N256 - 1, N256 - 2, N256 + 1, N256 + 2, top, top - 1, 1 << 255, (1 << 255) - 1,
          (1 << 255) + 1, koff, koff + 1, koff - 1, (koff + 1) % N256, 2 * koff % N256, (N256 - 1) // 2, (N256 + 1) // 2,
          1 << 64, (1 << 64) - 1, 1 << 128, 1 << 192, (1 << 224) - 1, top // 15 * 15, int("f0" * 32, 16), int("0f" * 32, 16)]
    ks += [koff + (j << 4 * i) for i in (0, 1, 31, 62, 63) for j in (1, 15)]
    ks += [int.from_bytes(hashlib.sha256(b"nonce %d" % i).digest(), "big") for i in range(40)]
    zs = [0, 1, N256 - 1, N256, N256 + 1, top, 1 << 255, (1 << 255) - 1]
    zs += [int.from_bytes(hashlib.sha256(b"hash %d" % i).digest(), "big") for i in range(8)]
    for i, k in enumerate(k % (1 << 256) for k in ks):
        if k % N256:
            for z in ([zs[i % len(zs)], zs[(i + 3) % len(zs)]] if i >= 8 else zs):
                job("ECDSA P-256 (edges, as OpenSSL and arithmetic have it)", "k = %#x, z = %#x" % (k, z), d, k, z % (1 << 256), True)


x25519()
aead()
hmac_()
sha()
ecdsa()
out = subprocess.run([BIN, "cmd"], input="".join(j[2] + "\n" for j in jobs), capture_output=True, text=True, check=True).stdout.split("\n")
bad = 0
count = {}
for (what, tid, cmd, check), line in zip(jobs, out):
    ok = len(out) > len(jobs) and check(bytes.fromhex(line) if line != "-" else b"")
    c = count.setdefault(what, [0, 0])
    c[0] += 1
    if not ok:
        c[1] += 1
        bad += 1
        if c[1] <= 5:
            print("FAIL %s: %s\n     %s\n     -> %s" % (what, tid, cmd[:300], line[:300]))
for what, (n, f) in count.items():
    print("%s %s: %d checks%s%s" % ("FAIL" if f else "ok  ", what, n, ", %d failed" % f if f else "",
                                    " (%d vectors not for us: other sizes of key, nonce, tag or data)" % skipped[what] if what in skipped else ""))
sys.exit(1 if bad else 0)
