/* ct.c: "nothing in the curve arithmetic, table lookups or ciphers branches on or indexes
 * with a secret", checked rather than read. The asm crypto (src/os.asm built with -DHOST)
 * runs under Valgrind's memcheck with every secret marked as undefined memory: memcheck
 * follows what is made from undefined bits and complains when a jump is decided by them
 * or an address is made of them. So a run without complaints is one in which neither time
 * nor the cache can say anything about a secret. What is public by nature (a key share, a
 * ciphertext and its tag, a signature) is marked defined again when it leaves.
 *
 * Secret here: our X25519 scalar and the shared secret, every key of the key schedule and
 * of the cipher, what is sealed, every ECDSA nonce of a stock and the private key.
 *
 *   make ct        (Valgrind from tools/outside.sh fetch; ten seconds)
 *
 * With an argument n, the run has a jump that does depend on a secret, or (6) an address:
 * the controls, each of which memcheck must find (make ct runs them all). They also say
 * that what comes out of each routine still counts as secret: 1 the shared secret, 2 a key
 * of the key schedule, 3 a record before it leaves, 4 what a record held, 5 a signature
 * before it leaves, 6 a table looked up by a byte of the shared secret. */
#include "asm.h"
#include <stdlib.h>
#include <valgrind/memcheck.h>

#define SECRET(p, n) (void)VALGRIND_MAKE_MEM_UNDEFINED(p, n)
#define PUBLIC(p, n) (void)VALGRIND_MAKE_MEM_DEFINED(p, n)

static int control;
static void jump(int n, const u8 *p)
{
    if (control == n && (p[0] & 1)) printf("(control %d: odd)\n", n);
}

int main(int argc, char **argv)
{
    static u8 m[2000], out[4096], tmp[2100], pub[32], shared[32], hs[32], ts[32], kiv[64], rs[64], z[32];
    /* the public key of the all-zero private key: some client's key share */
    static const u8 peer[32] = {0x2f,0xe5,0x7d,0xa3,0x47,0xcd,0x62,0x43,0x15,0x28,0xda,0xac,0x5f,0xbb,0x29,0x07,
                                0x30,0xff,0xf6,0x84,0xaf,0xc4,0xcf,0xc2,0xed,0x90,0x99,0x5f,0x58,0xcb,0x3b,0x74};
    u32 i, L;
    control = argc > 1 ? atoi(argv[1]) : 0;
    if (asm_init()) return 1;
    for (i = 0; i < sizeof m; i++) m[i] = i * 7 + 3;

    /* The key exchange: our scalar is secret, and so is what comes of it but our key share. */
    memcpy(E, m + 500, 32);
    SECRET(E, 32);
    xdh_(pub, shared, peer);
    PUBLIC(pub, 32);
    jump(1, shared);
    if (control == 6) printf("%d\n", m[shared[1]]);

    /* The key schedule, as `handshake` goes through it: the shared secret is what HMAC is
     * made over, then every secret is the key of the next. */
    hm(hs, m, shared, 32);                              /* handshake secret */
    ex(ts, hs, "\x20\x0c" "s hs traffic", m + 100);     /* a traffic secret */
    ex(kiv, ts, "\x10\x03" "key", 0);                   /* and its key and iv */
    ex(kiv + 32, ts, "\x0c\x02" "iv", 0);
    sha(tmp, shared, 32);                               /* (and the hash by itself) */
    jump(2, kiv + 32);

    /* AES-128-GCM both ways, under that key, of secret bytes: lengths around the blocks
     * of 16 and 64 and a full record. */
    SECRET(m, 1500);
    for (i = 0; i < 12; i++) {
        u32 n = (u32[]){1, 15, 16, 17, 63, 64, 65, 128, 129, 200, 1419, 1500}[i];
        L = sl(out, m, n, kiv, i);
        jump(3, out + L - 1);
        PUBLIC(out, L);                                 /* a record is public */
        L = op(tmp, out + 5, L - 21, kiv, i);           /* what it held, and its tag: not */
        jump(4, tmp + L - 1);
    }
    PUBLIC(m, sizeof m);

    /* Signatures: every nonce of a stock is secret (the host build lets us give them), and
     * so is the key. The hash signed is the transcript's, which the client has too. */
    for (i = 0; i < NPOOL * 32; i++) HK[i] = m[(i * 13 + 5) % 1999] | 1;
    SECRET(HK, NPOOL * 32);
    SECRET(REGS + R_D, 32);
    HKSET[0] = 2, POOLN = 0;
    for (i = 0; i < 3; i++) {
        memcpy(z, m + 40 * i, 32);
        sign_(rs, z);
        jump(5, rs + 32);
        PUBLIC(rs, 64);                                 /* r and s are sent */
    }
    for (i = 0; i < 64; i++) printf("%02x", rs[i]);
    printf("\n");
    return 0;
}
