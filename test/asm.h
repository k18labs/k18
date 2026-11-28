/* The asm crypto of src/os.asm, built with -DHOST, as C can call it (test_asm.c, ct.c).
 * The asm keeps the eight old registers (or says what it returns in them); r8-r15 and the
 * SSE registers are scratch. Its buffers are at fixed addresses from 2 MiB up: `asm_init`
 * maps them and makes the constants and tables that boot makes. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

typedef unsigned char u8;
typedef unsigned int u32;

#define SCRATCH "memory", "cc", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", \
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", \
                "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
#define ASMCALL(fn, ...) __asm__ volatile("call " #fn : __VA_ARGS__ : : SCRATCH)

static void sha(u8 *out, u8 *m, u32 n) { ASMCALL(sha256, "+D"(out), "+S"(m), "+c"(n)); }
static void hm(u8 *out, const u8 *k, const u8 *m, u32 n) { ASMCALL(hmac, "+D"(out), "+b"(k), "+S"(m), "+c"(n)); }
static void ex(u8 *out, const u8 *sec, const char *lab, const u8 *ctx) { ASMCALL(expand, "+D"(out), "+b"(sec), "+S"(lab), "+d"(ctx)); }
/* a record for the n bytes at m, of which the last says what the others are */
static u32 sl(u8 *o, const u8 *m, u32 n, const u8 *kiv, u32 seq)
{
    u8 *e = o;
    u32 type = m[--n];
    __asm__ volatile("clc\n\tcall seal" : "+D"(e), "+S"(m), "+c"(n), "+b"(kiv), "+d"(seq), "+a"(type) : : SCRATCH); /* CF = 0: encrypt */
    return e - o;
}
static u32 slc(u8 *o, const u8 *m, u32 n, const u8 *kiv, u32 seq)
{
    u8 *e = o;
    u32 type = m[--n];
    __asm__ volatile("clc\n\tcall seal_cached" : "+D"(e), "+S"(m), "+c"(n), "+b"(kiv), "+d"(seq), "+a"(type) : : SCRATCH);
    return e - o;
}
/* what a record held (n bytes at c, between header and tag), decrypted, and the tag it should have had */
static u32 op(u8 *o, const u8 *c, u32 n, const u8 *kiv, u32 seq)
{
    u8 *e = o;
    __asm__ volatile("stc\n\tcall seal" : "+D"(e), "+S"(c), "+c"(n), "+b"(kiv), "+d"(seq) : : SCRATCH); /* CF = 1: decrypt */
    return e - o;
}

extern u8 E[], REGS[];
enum { R_X = 3 * 32, R_Y = 4 * 32, R_T1 = 8 * 32 }; /* as in tools/ec.py */
/* our key share for the secret E to pub, the secret shared with the owner of u to shared */
static void xdh_(u8 *pub, u8 *shared, const u8 *u)
{
    ASMCALL(xdh, "+D"(pub), "+S"(u));
    memcpy(shared, REGS + R_X, 32);
}


extern u8 HK[], HKSET[], HAAD[], HAADN[], F25519[];
extern unsigned POOLN;
enum { R_D = 14 * 32, NPOOL = 64 };

static int asm_init(void)
{
    if (mmap((void *)0x200000, 0x200000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) != (void *)0x200000) {
        perror("mmap");
        return 1;
    }
    __asm__ volatile("call shaconst\n\tcall echost" ::: SCRATCH);
    return 0;
}
/* (r, s) for the hash z (big-endian, as it is) to rs: both little-endian */
static void sign_(u8 *rs, const u8 *z)
{
    ASMCALL(sign, "+S"(z));
    memcpy(rs, REGS + R_X, 32), memcpy(rs + 32, REGS + R_Y, 32);
}
