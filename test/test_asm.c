/* Host harness for the asm crypto (src/os.asm built with -DHOST). Without arguments it
 * prints the lines test/test_crypto.py checks; with one, it does what the lines on its
 * input ask for, one answer a line (test/outside.py: Wycheproof's vectors and others from
 * outside). Build: see the Makefile. */
#include "asm.h"

static void hex(const char *tag, const u8 *p, u32 n)
{
    printf("%s ", tag);
    while (n--) printf("%02x", *p++);
    printf("\n");
}

/* What the lines on the input ask for (hex throughout; "-" is no bytes):
 *   sha M                    SHA-256 of M
 *   hmac K M                 HMAC-SHA256 under the 32 bytes K of M (64 bytes at most)
 *   xdh E U                  our key share for the scalar E (clamped), and the secret shared with U
 *   open KEY IV AAD CT       AES-128-GCM: what CT holds under KEY (16 bytes) and the nonce IV,
 *                            and the tag it should have, made over AAD (16 bytes at most) and CT
 *   seal KEY IV AAD M        the other way: the ciphertext of M (whose last byte goes in as
 *                            the byte that says what the others are) and its tag
 *   sign D K Z               (r, s) for the hash Z with the nonce K (little-endian) under the
 *                            key whose d R mod n is D (little-endian; "-": the image's own) */
static u32 unhex(u8 *o, const char *h)
{
    u32 n = 0;
    if (h[0] == '-') return 0;
    for (; h[0] && h[1]; h += 2, n++) sscanf(h, "%2hhx", o + n);
    return n;
}
static void put(const u8 *p, u32 n)
{
    if (!n) printf("-");
    while (n--) printf("%02x", *p++);
    printf("\n");
}
static int commands(void)
{
    static char line[70000], w[6][20000];
    static u8 a[5][10000], out[10100], d0[32];
    memcpy(d0, REGS + R_D, 32);
    while (fgets(line, sizeof line, stdin)) {
        u32 n[5] = {0}, f = sscanf(line, "%19999s %19999s %19999s %19999s %19999s %19999s", w[0], w[1], w[2], w[3], w[4], w[5]);
        if (f < 2) continue;
        if (!strcmp(w[0], "sha")) {
            n[0] = unhex(a[0], w[1]);
            sha(out, a[0], n[0]);
            put(out, 32);
        } else if (!strcmp(w[0], "hmac")) {
            unhex(a[0], w[1]), n[1] = unhex(a[1], w[2]);
            hm(out, a[0], a[1], n[1]);
            put(out, 32);
        } else if (!strcmp(w[0], "xdh")) {
            unhex(E, w[1]), unhex(a[1], w[2]);
            xdh_(out, out + 32, a[1]);
            put(out, 64);
        } else if (!strcmp(w[0], "open") || !strcmp(w[0], "seal")) {
            static u8 kiv[44];
            u32 L;
            memset(kiv, 0, sizeof kiv), memset(HAAD, 0, 16);
            unhex(kiv, w[1]), unhex(kiv + 32, w[2]);
            HAADN[0] = 1 + unhex(HAAD, w[3]);
            n[4] = unhex(a[4], w[4]);
            if (w[0][0] == 'o') L = op(out, a[4], n[4], kiv, 0), put(out, L);
            else L = sl(out, a[4], n[4], kiv, 0), put(out + 5, L - 5);
            HAADN[0] = 0;
        } else if (!strcmp(w[0], "sign")) {
            if (w[1][0] == '-') memcpy(REGS + R_D, d0, 32);
            else unhex(REGS + R_D, w[1]);
            unhex(HK, w[2]), unhex(a[2], w[3]);
            HKSET[0] = 1, POOLN = 0;
            sign_(out, a[2]);
            put(out, 64);
        } else printf("?\n");
    }
    return 0;
}

int main(int argc, char **argv)
{
    static u8 m[2000], out[4096], tmp[2100], h[32], kiv[68], rngseed[32], rngout[176];
    u8 *seedp = rngseed;
    setbuf(stdout, NULL);
    u32 i, lens[] = {0, 3, 55, 56, 63, 64, 119, 1000, 1999};
    if (asm_init()) return 1;
    if (argc > 1) return commands();
    for (i = 0; i < sizeof m; i++) m[i] = i * 7 + 3;
    for (i = 0; i < sizeof rngseed; i++) rngseed[i] = i;
    ASMCALL(hctr_test_seed, "+D"(seedp));
    {
        u8 *p = rngout;
        unsigned n = 4;
        ASMCALL(hctr_test_generate, "+D"(p), "+c"(n));
        p = rngout + 32, n = 4;
        ASMCALL(hctr_test_generate, "+D"(p), "+c"(n));
        hex("drbg64", rngout, 64);
    }
    seedp = rngseed;
    ASMCALL(hctr_test_seed, "+D"(seedp));
    {
        u8 *p = rngout;
        unsigned n = 3;
        ASMCALL(hctr_test_generate, "+D"(p), "+c"(n));
        hex("drbg24", rngout, 24);
    }
    seedp = rngseed;
    ASMCALL(hctr_test_seed, "+D"(seedp));
    {
        u8 *p = rngout;
        unsigned n = 22;
        ASMCALL(hctr_test_generate, "+D"(p), "+c"(n));
        hex("drbg176", rngout, 176);
    }
    seedp = rngseed;
    ASMCALL(hctr_test_seed, "+D"(seedp));
    {
        u8 *p = rngout;
        unsigned n = 4;
        unsigned long preserved;
        ASMCALL(hrand_check, "+D"(p), "+c"(n), "=a"(preserved));
        if (preserved != 1 || n != 0 || p != rngout + 32) {
            fputs("rand caller-register contract failed\n", stderr);
            return 1;
        }
    }
    for (i = 0; i < sizeof lens / sizeof *lens; i++) {
        char t[32];
        memcpy(tmp, m, lens[i]);
        sha(h, tmp, lens[i]);
        sprintf(t, "sha%u", lens[i]);
        hex(t, h, 32);
    }
    hm(h, m, m + 32, 50);
    hex("hmac", h, 32);
    {
        const u32 hmac_lens[] = {0, 1, 31, 32, 33, 55, 56, 63, 64};
        for (i = 0; i < sizeof hmac_lens / sizeof *hmac_lens; i++) {
            char t[32];
            hm(h, m, m + 32, hmac_lens[i]);
            sprintf(t, "hmac%u", hmac_lens[i]);
            hex(t, h, 32);
        }
    }
    ex(h, m, "\x20\x07" "derived", m + 100);
    hex("expand", h, 32);
    for (i = 0; i < 32; i++) kiv[i] = m[300 + i], kiv[32 + i] = m[400 + i];
    for (i = 0; i < 10; i++) {       /* AES-128-GCM */
        u32 n = (u32[]){1, 100, 1500, 15, 16, 17, 63, 64, 65, 128}[i], L;
        char t[32];
        L = sl(out, m, n, kiv, i * 77);
        sprintf(t, "gcm%u_%u", n, i * 77);
        hex(t, out, L);
        L = op(tmp, out + 5, L - 21, kiv, i * 77);    /* and back: the plaintext, then the tag */
        sprintf(t, "ungcm%u_%u", n, i * 77);
        hex(t, tmp, L);
        L = slc(out, m, n, kiv, i * 77);
        sprintf(t, "gcmcached%u_%u", n, i * 77);
        hex(t, out, L);
    }
    /* X25519 with our scalar e (clamped as in RFC 7748): key share, and the secret with the
     * public key of the all-zero private key; with scalars of all ones and all zeros, with a
     * client's u that has its top bit set (which is to be ignored), and with points of small
     * order (u = 0 and u = 1, which must both give an all-zero secret) */
    {
        static u8 peer[32] = {0x2f,0xe5,0x7d,0xa3,0x47,0xcd,0x62,0x43,0x15,0x28,0xda,0xac,0x5f,0xbb,0x29,0x07,
                              0x30,0xff,0xf6,0x84,0xaf,0xc4,0xcf,0xc2,0xed,0x90,0x99,0x5f,0x58,0xcb,0x3b,0x74};
        static u8 pub[32], shared[32], small[32];
        for (i = 0; i < 6; i++) {
            u32 j;
            char t[32];
            for (j = 0; j < 32; j++) E[j] = i == 1 ? 0xff : i == 2 ? 0 : m[500 + 40 * i + j];
            peer[31] = i == 3 ? peer[31] | 0x80 : peer[31] & 0x7f;
            memset(small, 0, 32), small[0] = i == 5;
            xdh_(pub, shared, i >= 4 ? small : peer);
            sprintf(t, "xpub%u", i);
            hex(t, pub, 32);
            sprintf(t, "xshared%u", i);
            hex(t, shared, 32);
        }
    }
    /* ECDSA: (r, s) for a hash. The nonces are made 64 at a time (`stock`); for some of
     * these the first one used is ours: all ones, 1, and one that shares most of its
     * nibbles with what the table lookup takes off (so that many digits are 0 or 15). */
    for (i = 0; i < 70; i++) {
        u32 j;
        char t[32];
        static u8 z[32];
        const u8 *zp = z;
        for (j = 0; j < 32; j++) z[j] = m[900 + (40 * i + j) % 1000];
        if (i == 2) memset(z, 0xff, 32);
        if (i == 3) memset(z, 0, 32);
        if (i >= 1 && i <= 4) {
            for (j = 0; j < 32; j++) HK[j] = i == 1 ? m[600 + j] : i == 2 ? 0xff : i == 3 ? !j : 0x11;
            if (i == 4) HK[31] = 0x91, HK[0] = 0x12;
            HKSET[0] = 1, POOLN = 0;
        } else HKSET[0] = 0;
        ASMCALL(sign, "+S"(zp));
        sprintf(t, "sig%u", i);
        memcpy(tmp, z, 32), memcpy(tmp + 32, REGS + R_X, 32), memcpy(tmp + 64, REGS + R_Y, 32);
        hex(t, tmp, 96); /* hash (big-endian) | r | s (little-endian) */
    }
    /* The field arithmetic on its own, for each of the three fields: every pair of some
     * numbers that sit on the edges (0, the modulus and what is near it, 2^256 - 1, ...) and
     * some that don't; test_crypto.py has the model's answers (tools/ec.py). */
    {
        typedef unsigned long long u64;
        static u64 v[24][4], r[4];
        for (int f = 0; f < 3; f++) {
            const u64 *nm = (const u64 *)(F25519 + 104 * f), *mm = nm + 4;
            int n = 0, j, k;
            #define SET(a, b, c, d) (v[n][0] = (a), v[n][1] = (b), v[n][2] = (c), v[n][3] = (d), n++)
            SET(0, 0, 0, 0); SET(1, 0, 0, 0); SET(2, 0, 0, 0);
            SET(~0ull, ~0ull, ~0ull, ~0ull); SET(~0ull - 1, ~0ull, ~0ull, ~0ull);
            SET(mm[0], mm[1], mm[2], mm[3]); SET(mm[0] - 1, mm[1], mm[2], mm[3]); SET(mm[0] + 1, mm[1], mm[2], mm[3]);
            SET(nm[0], nm[1], nm[2], nm[3]); SET(nm[0] - 1, nm[1], nm[2], nm[3]); SET(nm[0] + 1, nm[1], nm[2], nm[3]);
            SET(0, 0, 0, 1ull << 63); SET(~0ull, ~0ull, ~0ull, ~0ull >> 1); SET(~0ull, 0, 0, 0); SET(0, 0, 0, 1);
            SET(~0ull, ~0ull, ~0ull, mm[3]); SET(0, 0, 0, mm[3]);
            for (j = 0; j < 5; j++, n++) memcpy(v[n], m + 100 + 40 * j + 7 * f, 32);
            for (j = 0; j < n; j++) { /* and the inversion of each (T1) */
                u8 *x = (u8 *)v[j];
                int c = f;
                __asm__ volatile("call hinv" : "+S"(x), "+c"(c) : : SCRATCH);
                printf("f%d_inv_%d ", f, j);
                for (int b = 0; b < 32; b++) printf("%02x", REGS[R_T1 + b]);
                printf("\n");
            }
            for (j = 0; j < n; j++) { /* its square, */
                u8 *d = (u8 *)r, *x = (u8 *)v[j];
                int c = f;
                __asm__ volatile("call hfsqr" : "+D"(d), "+S"(x), "+c"(c) : : SCRATCH);
                printf("f%d_sqr_%d ", f, j);
                for (int b = 0; b < 32; b++) printf("%02x", ((u8 *)r)[b]);
                printf("\n");
            }
            for (j = 0; j < n; j++) /* and its lowest limb times each */
                for (k = 0; k < n; k++) {
                    u64 one[4] = {v[j][0], 0, 0, 0};
                    u8 *d = (u8 *)r, *x = (u8 *)one, *y = (u8 *)v[k];
                    int c = f;
                    __asm__ volatile("call hfmul1" : "+D"(d), "+S"(x), "+b"(y), "+c"(c) : : SCRATCH);
                    printf("f%d_mul1_%d_%d ", f, j, k);
                    for (int b = 0; b < 32; b++) printf("%02x", ((u8 *)r)[b]);
                    printf("\n");
                }
            for (j = 0; j < n; j++)
                for (k = 0; k < n; k++) {
                    static const char *const op[] = {"hfas", "hfsub", "hfmul"};
                    for (int o = 0; o < 3; o++) {
                        u8 *d = (u8 *)r, *x = (u8 *)v[j], *y = (u8 *)v[k];
                        int c = f;
                        if (o == 0) __asm__ volatile("call hfas" : "+D"(d), "+S"(x), "+b"(y), "+c"(c) : : SCRATCH);
                        if (o == 1) __asm__ volatile("call hfsub" : "+D"(d), "+S"(x), "+b"(y), "+c"(c) : : SCRATCH);
                        if (o == 2) __asm__ volatile("call hfmul" : "+D"(d), "+S"(x), "+b"(y), "+c"(c) : : SCRATCH);
                        printf("f%d_%s_%d_%d ", f, op[o] + 2, j, k);
                        for (int b = 0; b < 32; b++) printf("%02x", ((u8 *)r)[b]);
                        printf("\n");
                    }
                }
        }
    }
    return 0;
}
