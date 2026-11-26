#!/usr/bin/env python3
"""The elliptic-curve side of the image, as data plus a bit-exact Python model of it.

The asm has one 256 x 256 -> 512 bit multiplication (four limbs of 64 bits, mulx/adcx/adox;
and the same product made shorter where a factor has one limb or the two are one number),
two ways to reduce its result (2^255 - 19 by folding, the other moduli Montgomery's way),
one add/subtract, and a tiny register machine on top: 16 registers of four limbs, five
operations (add, subtract, and the three multiplications). The curve formulas are programs for that machine, assembled here (2 bytes per
operation) and included in the image by gen.py. This file also runs them in Python, so
`python3 tools/ec.py` checks the formulas, the constants and the bounds below against
pyca/cryptography.

Values: every register holds a number below 2^256 that stands for its residue: "weakly
reduced". Nothing is ever compared with a modulus, so there are no data-dependent branches
or lengths anywhere:
  add(a, b)  = a + b, then twice: if that left 2^256, take M off again
  sub(a, b)  = a - b, then twice: if that went below 0, put M back
  mul(a, b)  = a b mod p               for 2^255 - 19 (M = 2 p = 2^256 - 38: what leaves
               2^256 comes back times 38)
             = a b / 2^256 mod M       for the Montgomery fields (p and n of P-256): below
               2^256 + M before one last conditional subtraction
(Twice, because a weakly reduced number may be anywhere up to 2^256: the first correction
can leave it just outside again.) Canonical values only appear where a result leaves the
machine: `freeze` for 2^255 - 19, mul(x, 1) for the Montgomery fields (which is <= M).

Montgomery form: a stored value s stands for s / R, R = 2^256. Products of stored values
are then stored values again; constants are baked in already multiplied by R. Inputs that
arrive raw (the hash to sign, the nonce) are used raw where the formulas are homogeneous
enough not to care, see the programs.

Scalar multiplications, the three a handshake needs:
  - our X25519 public key e B: B is fixed, so a table made at boot does it in 64 additions
    (one per nibble of e) on the Edwards form of the curve, whose addition law has no
    exceptions; the result goes back to Montgomery's u = (Z + Y) / (Z - Y)
  - the shared secret e U: U is the client's, so the Montgomery ladder, 255 steps
  - r = x(k G) for the signature: G is fixed, a table again (Jacobian coordinates, mixed
    additions). That addition law does have exceptions (a point plus itself, plus its
    negative, the point at infinity), so the table holds (d + 1) 16^i G, never infinity,
    the sum starts from a fixed point 2^255 G, and the nonce has the difference taken off
    first: no partial sum can then meet the point it is added to, except for a share of
    2^-240 or so of all nonces (see `sign`).
Table lookups read all 16 entries of a window and keep one (the asm: with masks).
One inversion a^(m-2) for all three moduli (mod 2^255 - 19 by an addition chain, CHAIN25519;
the others bit by bit). The two X25519 results share one; the
signatures' r and 1/k are made 64 at a time (the asm's `stock`), with two inversions for
all of them (`binv`: Montgomery's trick, which here gives exactly what `inv` gives).
"""
import os
import sys

R = 1 << 256
W = 1 << 64
P25519 = (1 << 255) - 19
P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
# edwards25519: -x^2 + y^2 = 1 + d x^2 y^2, base point B (which Montgomery's u = 9 comes from)
D25519 = -121665 * pow(121666, -1, P25519) % P25519
BY25519 = 4 * pow(5, -1, P25519) % P25519
BX25519 = 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
# what the nonce loses before its nibbles pick table entries: the starting point's 2^255 and
# the 1 that every entry has too many (the sum of 16^i)
KOFF = (1 << 255) + ((1 << 256) - 1) // 15

# Registers. E0-E2 are where a table entry lands (and the client's u, and the hash to
# sign); X-T are the point being worked on (the ladder's X2 Z2 X3 Z3); ZERO to D are
# constants, set at boot; C is 2 d of edwards25519 while its table is made and R mod p of
# P-256 after that. E0 comes first because register 0 must not be squared (see asm()).
REGS = "E0 E1 E2 X Y Z T T0 T1 T2 T3 ZERO ONE A24 D C".split()
REG = {n: i for i, n in enumerate(REGS)}
ADD, SUB, MUL, MUL1, SQR = 1, 2, 3, 4, 5


def asm(text):
    """'DST = A op B' lines -> bytes: a << 4 | b, then op << 4 | dst; a zero byte ends the
    program (no operation has register 0 as both operands). '1*' is a multiplication whose
    A has one limb (the asm then leaves out the other three rows); a register times itself
    becomes a squaring (six products fewer). Both give what '*' gives."""
    out = bytearray()
    for line in text.strip().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        dst, _, a, op, b = line.split()
        op = {"+": ADD, "-": SUB, "*": MUL, "1*": MUL1}[op]
        out += bytes([REG[a] << 4 | REG[b], (SQR if op == MUL and a == b else op) << 4 | REG[dst]])
    assert all(out[::2])
    return bytes(out) + b"\0"


# X25519 (RFC 7748), the ladder: two points (X : Y) and (Z : T) (the RFC's (X2 : Z2) and
# (X3 : Z3)) whose difference is the client's point u = E0; they start as infinity (1 : 0)
# and (u : 1). A24 is 121665.
INIT25519 = asm("""
    X = ONE + ZERO
    Y = ZERO + ZERO
    Z = E0 + ZERO
    T = ONE + ZERO
""")
STEP25519 = asm("""
    T0 = X + Y          # A
    T1 = X - Y          # B
    T2 = Z + T          # C
    T3 = Z - T          # D
    T3 = T3 * T0        # DA
    T2 = T2 * T1        # CB
    T0 = T0 * T0        # AA
    T1 = T1 * T1        # BB
    Z = T3 + T2
    T = T3 - T2
    X = T0 * T1         # X2
    T1 = T0 - T1        # E
    Z = Z * Z           # X3
    T = T * T
    Y = A24 1* T1
    Y = Y + T0
    T = T * E0          # Z3
    Y = Y * T1          # Z2
""")
# edwards25519, extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, T = XY/Z. A table
# entry is (y + x, y - x, 2 d x y) of an affine point; adding one (Hisil et al. 2008,
# "madd"; complete: it also doubles and adds the neutral point (1, 1, 0)):
INITED = asm("""
    X = ZERO + ZERO
    Y = ONE + ZERO
    Z = ONE + ZERO
    T = ZERO + ZERO
""")
MADDED = asm("""
    T0 = Y - X
    T1 = Y + X
    T3 = Z + Z          # D
    T0 = T0 * E1        # A
    T1 = T1 * E0        # B
    T2 = T * E2         # C
    X = T1 - T0         # E
    Y = T1 + T0         # H
    T0 = T3 - T2        # F
    T1 = T3 + T2        # G
    T = X * Y
    Z = T0 * T1
    X = X * T0
    Y = T1 * Y
""")
# The key share: Montgomery's u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y), kept as that
# fraction in E1 / E2 until the ladder has run: with the ladder's X / Y (the shared secret),
# one inversion does for both. XPRE, T1 = 1 / T0, XPOST. (Raw values, to be frozen.)
KEYED = asm("""
    E1 = Z + Y
    E2 = Z - Y
""")
XPRE = asm("""
    T0 = E2 * Y
""")
XPOST = asm("""
    T2 = T1 * Y
    E1 = E1 * T2        # our public key
    T2 = T1 * E2
    X = X * T2          # the shared secret
""")
# Making the table (boot): from a point and T1 = 1 / Z to its entry, in T0 T1 T2. C = 2 d.
TOPRE = asm("""
    T0 = X * T1         # x
    T1 = Y * T1         # y
    T2 = T0 * T1
    T2 = T2 * C
    T3 = T1 + T0
    T1 = T1 - T0
    T0 = T3 + ZERO
""")


def chain(text):
    """'DST = A^(2^N) * B' lines (or 'DST = A * B') -> (dst, a, n, b), as register numbers."""
    out = []
    for line in text.strip().splitlines():
        dst, _, a, _, b = line.split("#")[0].split()
        a, _, n = a.partition("^(2^")
        out.append((REG[dst], REG[a], int(n.rstrip(")") or 0), REG[b]))
    return out


# The inversion mod 2^255 - 19 (`inv`): T1 = T0^(p - 2) by an addition chain, each line A
# squared N times and then multiplied by B: 254 squarings and 11 multiplications, where bit
# by bit it takes 255 and 252. T0-T3 only: what `xdh` and the table keep is elsewhere. In
# the image it is a program whose operations say N (their index in NSQ, plus 1), which only
# `inv` reads.
CHAIN25519 = chain("""
    T1 = T0 * T0            # 2
    T2 = T1^(2^2) * T0      # 9
    T0 = T2 * T1            # 11
    T1 = T0^(2^1) * T2      # 2^5 - 1
    T2 = T1^(2^5) * T1      # 2^10 - 1
    T3 = T2^(2^10) * T2     # 2^20 - 1
    T1 = T3^(2^20) * T3     # 2^40 - 1
    T1 = T1^(2^10) * T2     # 2^50 - 1
    T2 = T1^(2^50) * T1     # 2^100 - 1
    T3 = T2^(2^100) * T2    # 2^200 - 1
    T3 = T3^(2^50) * T1     # 2^250 - 1
    T1 = T3^(2^5) * T0      # 2^255 - 21
""")
NSQ = sorted({n for _, _, n, _ in CHAIN25519})
INV25519 = bytes(x for d, a, n, b in CHAIN25519 for x in (a << 4 | b, (NSQ.index(n) + 1) << 4 | d)) + b"\0"
assert len(NSQ) < 16 and all(INV25519[:-1:2])
# P-256, Jacobian coordinates (X : Y : Z), x = X/Z^2, y = Y/Z^3, everything times R. A table
# entry is an affine point (x, y); C is R mod p (a 1). Adding one (8 M + 3 S; not for the
# point itself, its negative or infinity: see the docstring), doubling (a = -3; boot only):
INIT256 = asm("""
    X = E0 + ZERO
    Y = E1 + ZERO
    Z = C + ZERO
""")
MADD256 = asm("""
    T0 = Z * Z
    T1 = Z * E1
    T2 = T0 * E0        # U2
    T1 = T1 * T0        # S2
    T0 = T2 - X         # H
    T1 = T1 - Y         # r
    Z = Z * T0
    T2 = T0 * T0        # H^2
    T3 = T1 * T1        # r^2
    T0 = T2 * T0        # H^3
    T2 = T2 * X         # X H^2
    X = T3 - T0
    X = X - T2
    X = X - T2
    T2 = T2 - X
    T2 = T2 * T1
    T0 = T0 * Y         # Y H^3
    Y = T2 - T0
""")
DBL256 = asm("""
    T0 = Z * Z          # delta
    T1 = Y * Y          # gamma
    T2 = X * T1         # beta
    T3 = X - T0
    X = X + T0
    T3 = T3 * X
    X = T3 + T3
    T3 = X + T3         # alpha = 3 (X - delta) (X + delta)
    Z = Y + Z
    Z = Z * Z
    Z = Z - T1
    Z = Z - T0
    T2 = T2 + T2
    T2 = T2 + T2        # 4 beta
    X = T3 * T3
    X = X - T2
    X = X - T2
    T2 = T2 - X
    T2 = T2 * T3
    T1 = T1 * T1
    T1 = T1 + T1
    T1 = T1 + T1
    T1 = T1 + T1        # 8 gamma^2
    Y = T2 - T1
""")
# Making the table (boot): from a point and T1 = 1 / Z to (x, y) in T0 T1.
TOAFF = asm("""
    T0 = T1 * T1
    T2 = T0 * T1
    T0 = X * T0
    T1 = Y * T2
""")
# After the sum and T1 = 1 / Z: X = r = x, canonical and raw.
FIN256 = asm("""
    T0 = T1 * T1
    T0 = X * T0
    X = T0 * ONE
""")
# ECDSA, mod n: X = r (raw), E0 = hash (raw), D = d R, T1 = R^2 / k (what the inversion
# makes of a raw k). Y = s = (hash + r d) / k, canonical.
SIGN = asm("""
    T0 = X * D
    T0 = T0 + E0
    T0 = T0 * T1
    Y = T0 * ONE
""")

# (STEP25519 is not among them: the image has it as calls, see straight())
PROGRAMS = {"INIT25519": INIT25519, "INITED": INITED, "MADDED": MADDED,
            "KEYED": KEYED, "XPRE": XPRE, "XPOST": XPOST, "TOPRE": TOPRE, "INIT256": INIT256,
            "MADD256": MADD256, "DBL256": DBL256, "TOAFF": TOAFF, "FIN256": FIN256, "SIGN": SIGN,
            "INV25519": INV25519}


def straight(prog):
    """A program for 2^255 - 19 as the instructions that do what `vm` would with it: for
    every operation its registers' addresses and a call. The ladder's step is in the image
    that way (tools/gen.py: step.inc): it runs 255 times a handshake, and fetching and
    telling apart its 18 operations cost a seventh of them."""
    out = []
    regs = [None, None, None]  # edi, esi, ebx: addresses known to survive each call
    for i in range(0, len(prog) - 1, 2):
        b, a, dst, op = prog[i] & 15, prog[i] >> 4, prog[i + 1] & 15, prog[i + 1] >> 4
        want = [dst, a, b if op != SQR else None]
        names = ("edi", "esi", "ebx")
        pending = {r for r in range(3) if want[r] is not None and regs[r] != want[r]}
        while pending:
            # Prefer a register copy when its source is already live. Do not overwrite
            # the sole copy of a value needed by another pending operand.
            move = None
            for r in sorted(pending):
                src = next((s for s in range(3) if s != r and regs[s] == want[r]), None)
                if src is not None and not any(q != r and regs[r] == want[q] and
                                               sum(v == want[q] for v in regs) == 1
                                               for q in pending):
                    move = (r, src, True)
                    break
            if move is None:
                r = min(pending)
                move = (r, None, False)
            r, src, copied = move
            if copied:
                out.append(f"        mov {names[r]}, {names[src]}")
                regs[r] = regs[src]
            else:
                out.append(f"        mov {names[r]}, REGS + {32 * want[r]}")
                regs[r] = want[r]
            pending.remove(r)
        out.append("        JUMPH 5\n        call " + ("fadd19", "fsub19", "fmul", "fmul1", "fsqr")[op - 1])
        if op == MUL:
            regs[1] = regs[2]  # fmul preserves edi/ebx and sets esi = ebx
    return "\n".join(out) + "\n"


class Field:
    """What the asm knows of a modulus: M (what add and sub correct by, and Montgomery
    reduces by), -1/M mod 2^64 (0: the field of 2^255 - 19, which folds instead), and the
    exponent of an inversion."""

    def __init__(self, m, mont):
        self.m = m                                  # the real modulus
        self.M = m if mont else 2 * m
        self.minv = -pow(m, -1, W) % W if mont else 0
        self.exp = m - 2
        assert R - (1 << 225) < self.M < R          # (one conditional subtraction after a product)


F25519, FP256, FN256 = Field(P25519, False), Field(P256, True), Field(N256, True)


class Machine:
    """The register machine, with the asm's exact arithmetic and its preconditions asserted."""

    def __init__(self):
        self.r = [0] * 16
        self.r[REG["ONE"]] = 1
        self.r[REG["A24"]] = 121665
        self.f = None
        self.muls = 0

    def add(self, a, b):
        s = a + b
        for _ in range(2):
            if s >= R:
                s -= self.f.M
        assert 0 <= s < R
        return s

    def sub(self, a, b):
        s = a - b
        for _ in range(2):
            if s < 0:
                s += self.f.M
        assert 0 <= s < R
        return s

    def mul(self, a, b):
        f = self.f
        assert a < R and b < R
        self.muls += 1
        t = a * b
        if not f.minv:
            t = t % R + 38 * (t >> 256)             # five limbs, the fifth at most 38
            t = t % R + 38 * (t >> 256)
            if t >= R:
                t += 38 - R
        else:
            for _ in range(4):
                t = (t + (t * f.minv % W) * f.M) >> 64
            assert t < R + f.M
            if t >= R:
                t -= f.M
            assert t % f.m == a * b * pow(R, -1, f.m) % f.m
        assert t < R
        return t

    def run(self, prog):
        r = self.r
        for i in range(0, len(prog) - 1, 2):
            b, a, dst, op = prog[i] & 15, prog[i] >> 4, prog[i + 1] & 15, prog[i + 1] >> 4
            assert (op != MUL1 or r[a] < W) and (op != SQR or a == b)
            r[dst] = (self.add, self.sub, self.mul, self.mul, self.mul)[op - 1](r[a], r[b])

    def inv(self, x):
        """T1 = x^(m-2): mod 2^255 - 19 by CHAIN25519, else by right-to-left square and
        multiply (bit 0 of m - 2 is always 1)."""
        r, e = self.r, self.f.exp
        r[REG["T0"]] = x
        if self.f is F25519:
            for dst, a, n, b in CHAIN25519:
                v = r[a]
                for _ in range(n):
                    v = r[dst] = self.mul(v, v)
                r[dst] = self.mul(v, r[b])
            return
        assert e & 1
        r[REG["T1"]] = x
        for i in range(1, 256):
            r[REG["T0"]] = self.mul(r[REG["T0"]], r[REG["T0"]])
            if e >> i & 1:
                r[REG["T1"]] = self.mul(r[REG["T1"]], r[REG["T0"]])

    def binv(self, xs):
        """What `inv` makes of each of xs, with one `inv`: of their product."""
        r, t0, t1 = self.r, REG["T0"], REG["T1"]
        p = [xs[0]]
        for x in xs[1:]:
            p.append(self.mul(p[-1], x))
        self.inv(p[-1])
        out = [0] * len(xs)
        for i in range(len(xs) - 1, 0, -1):
            r[t0] = self.mul(r[t1], p[i - 1])
            r[t1] = self.mul(r[t1], xs[i])
            out[i] = r[t0]
        out[0] = r[t1]
        return out

    def entry(self, e):
        self.r[:len(e)] = e

    def comb(self, table, k, madd):
        """The point in X.. plus the sum over i of table[i][nibble i of k]."""
        for i in range(64):
            self.entry(table[i][k >> 4 * i & 15])
            self.run(madd)

    # --- the tables, as boot makes them ---
    def table25519(self):
        r, x = self.r, REG["X"]
        self.f = F25519
        r[REG["C"]] = 2 * D25519 % P25519
        r[x:x + 3] = BX25519, BY25519, 1            # the base point (T is not looked at)
        table = []
        for _ in range(64):
            self.inv(r[REG["Z"]])
            self.run(TOPRE)
            self.entry(r[REG["T0"]:REG["T0"] + 3])  # 16^i B, to be added 16 times
            self.run(INITED)
            row = []
            for _ in range(16):
                self.inv(r[REG["Z"]])
                self.run(TOPRE)
                row.append(tuple(r[REG["T0"]:REG["T0"] + 3]))
                self.run(MADDED)
            table.append(row)
        return table

    def table256(self):
        r = self.r
        self.f = FP256
        r[REG["C"]] = R % P256
        self.entry((GX256 * R % P256, GY256 * R % P256))
        self.run(INIT256)
        table = []
        for _ in range(64):
            row = []
            for d in range(16):
                self.inv(r[REG["Z"]])
                self.run(TOAFF)
                row.append(tuple(r[REG["T0"]:REG["T0"] + 2]))
                if d == 0:
                    self.entry(row[0])              # 16^i G, to be added 14 times
                    self.run(DBL256)
                elif d < 15:
                    self.run(MADD256)
            table.append(row)
        return table

    # --- what a handshake does ---
    def x25519(self, table, e, u):
        """(our public key, the shared secret) for our secret e (clamped as in RFC 7748) and
        the client's public key u."""
        r = self.r
        self.f = F25519
        e = e & ((1 << 255) - 8) | (1 << 254)
        self.run(INITED)
        self.comb(table, e, MADDED)
        self.run(KEYED)
        r[REG["E0"]] = u & ((1 << 255) - 1)         # (RFC 7748: the top bit is not part of u)
        self.run(INIT25519)
        x = REG["X"]
        for i in reversed(range(256)):
            bit = e >> i & 1
            if bit:
                r[x:x + 4] = r[x + 2:x + 4] + r[x:x + 2]
            self.run(STEP25519)
            if bit:
                r[x:x + 4] = r[x + 2:x + 4] + r[x:x + 2]
        self.run(XPRE)
        self.inv(r[REG["T0"]])
        self.run(XPOST)
        return r[REG["E1"]] % P25519, r[REG["X"]] % P25519  # (`freeze`)

    def sign(self, table, d, k, z):
        """(r, s) for hash z and nonce k; r is x(kG) without the reduction mod n."""
        r = self.r
        self.f = FN256
        k2 = self.sub(k, KOFF)                      # (weakly reduced: any number that is k - KOFF mod n)
        self.f = FP256
        self.entry(table[63][7])                    # 2^255 G
        self.run(INIT256)
        # The sum so far is never the point added to it, nor its negative (MADD256 can't do
        # those). In multiples of G the sum is 2^255 + a, with a < 16^i 17/15 before window
        # i; the point added is b = (d + 1) 16^i. Both stay below n except in the last
        # window, and are told apart by 2^255 in all but that one, where 2^255 + a = b mod n
        # holds for at most two of the 2^252 values the lower nibbles can take.
        acc = 1 << 255
        for i in range(64):
            b = ((k2 >> 4 * i & 15) + 1) << 4 * i
            assert (acc - b) % N256 and (acc + b) % N256, "an addition MADD256 can't do"
            acc += b
            self.entry(table[i][k2 >> 4 * i & 15])
            self.run(MADD256)
        self.inv(r[REG["Z"]])
        self.run(FIN256)
        self.f = FN256
        r[REG["D"]] = d * R % N256
        r[REG["E0"]] = z
        self.inv(k)
        self.run(SIGN)
        return r[REG["X"]], r[REG["Y"]]


def selftest():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    e, tt = {REG["T0"]: 1}, range(REG["T0"], REG["T3"] + 1)  # the chain: p - 2, in T0-T3
    for dst, a, n, b in CHAIN25519:
        assert dst in tt and a in tt and b in tt and (n == 0 or b != dst)
        e[dst] = (e[a] << n) + e[b]
    assert e[REG["T1"]] == P25519 - 2
    mach = Machine()
    t25519, t256 = mach.table25519(), mach.table256()
    for row in t25519:
        assert all(len(e) == 3 for e in row)
    assert t25519[0][0] == (1, 1, 0)
    for f in (F25519, FP256, FN256):                # one inversion for many: the same residues
        mach.f = f
        xs = [int.from_bytes(os.urandom(32), "little") for _ in range(9)] + [1, f.m - 1]
        for x, y in zip(xs, mach.binv(xs)):
            mach.inv(x)
            assert y % f.m == mach.r[REG["T1"]] % f.m
    mach.muls = 0
    for t in range(8):
        # X25519: compare both public key and shared secret, and check small-order points
        peer = X25519PrivateKey.generate()
        e_bytes = os.urandom(32) if t > 1 else bytes([255 * t]) * 32
        e = int.from_bytes(e_bytes, "little")
        u = int.from_bytes(peer.public_key().public_bytes_raw(), "little")
        if t == 3:
            u |= 1 << 255                           # (a top bit that is to be ignored)
        if t in (4, 5):
            u = t - 4                               # (points of small order: 0 and 1 -> secret 0)
        pub, ours = mach.x25519(t25519, e, u)
        if t in (4, 5):
            assert ours == 0, "small-order x25519"
        else:
            sk = X25519PrivateKey.from_private_bytes(e_bytes)
            assert pub.to_bytes(32, "little") == sk.public_key().public_bytes_raw(), "x25519 pub"
            theirs = peer.exchange(X25519PublicKey.from_public_bytes(pub.to_bytes(32, "little")))
            assert ours.to_bytes(32, "little") == theirs, "x25519"
        # ECDSA
        key = ec.generate_private_key(ec.SECP256R1())
        d = key.private_numbers().private_value
        k = int.from_bytes(os.urandom(32), "little") if t > 1 else (1 << 256) - 1 - t
        z = int.from_bytes(os.urandom(32), "big") if t else (1 << 256) - 1
        r, s = mach.sign(t256, d, k, z)
        assert 0 < r < N256 and 0 < s < N256
        key.public_key().verify(utils.encode_dss_signature(r, s), z.to_bytes(32, "big"),
                                ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    print("ec.py: programs ok;", ", ".join(f"{n} {len(p)}" for n, p in PROGRAMS.items()), "bytes;",
          mach.muls // 8, "multiplications per handshake")


if __name__ == "__main__":
    selftest()
