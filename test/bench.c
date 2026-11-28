/* Host timing of the asm crypto (src/os.asm built with -DHOST): `make bench`. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <cpuid.h>
#include <x86intrin.h>
typedef unsigned char u8;
#define SCRATCH "memory", "cc", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", \
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", \
                "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
#define ASMCALL(fn, ...) __asm__ volatile("call " #fn : __VA_ARGS__ : : SCRATCH)
extern u8 E[], REGS[];
static unsigned long long rlast;
static int rdrand64(u8 *out){
    unsigned long long x;
    unsigned char ok;
    for (int i = 0; i < 16; i++) {
        __asm__ volatile("rdrand %0; setc %1" : "=r"(x), "=qm"(ok));
        if (!ok) continue;
        if (x == rlast) return 0;
        rlast = x;
        memcpy(out, &x, sizeof x);
        return 1;
    }
    return 0;
}
static int rdrand4(u8 *out){
    for (int i = 0; i < 4; i++)
        if (!rdrand64(out + i * 8)) return 0;
    return 1;
}
static int rdrand_ready(void){
    u8 sample[32];
    for (int i = 0; i < 16; i++)
        if (!rdrand4(sample)) return 0;
    return 1;
}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
#define SAMPLES 7
static unsigned long long ticks_start(void){_mm_lfence();return __rdtsc();}
static unsigned long long ticks_end(void){unsigned aux;unsigned long long t=__rdtscp(&aux);_mm_lfence();return t;}
static void sort_u64(unsigned long long *a, int n){
    for(int i=1;i<n;i++){unsigned long long x=a[i];int j=i;while(j&&a[j-1]>x)a[j]=a[j-1],j--;a[j]=x;}
}
static void sort_double(double *a, int n){
    for(int i=1;i<n;i++){double x=a[i];int j=i;while(j&&a[j-1]>x)a[j]=a[j-1],j--;a[j]=x;}
}
#define TIME(name, n, ...) do { \
    double us_[SAMPLES], dev_[SAMPLES]; unsigned long long cyc_[SAMPLES], mad_[SAMPLES]; \
    for(int s_=0;s_<SAMPLES;s_++){ \
        for(i=0;i<(n)/100+1;i++){__VA_ARGS__;} \
        double t_=now(); unsigned long long c_=ticks_start(); \
        for(i=0;i<(n);i++){__VA_ARGS__;} \
        c_=ticks_end()-c_; us_[s_]=(now()-t_)*1e6/(n); cyc_[s_]=c_/(n); \
    } \
    sort_double(us_,SAMPLES); sort_u64(cyc_,SAMPLES); \
    for(int s_=0;s_<SAMPLES;s_++){dev_[s_]=us_[s_]>us_[SAMPLES/2]?us_[s_]-us_[SAMPLES/2]:us_[SAMPLES/2]-us_[s_]; \
        mad_[s_]=cyc_[s_]>cyc_[SAMPLES/2]?cyc_[s_]-cyc_[SAMPLES/2]:cyc_[SAMPLES/2]-cyc_[s_];} \
    sort_double(dev_,SAMPLES); sort_u64(mad_,SAMPLES); \
    printf("%-38s %8.2f us  %9llu cycles  MAD %llu cycles\n", name,us_[SAMPLES/2],cyc_[SAMPLES/2],mad_[SAMPLES/2]); \
} while(0)
int main(void){
    setbuf(stdout, NULL);       /* keep the last completed timing visible if a later probe faults */
    mmap((void *)0x200000, 0x200000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    __asm__ volatile("call shaconst" ::: SCRATCH);
    static u8 u[32]={9}, pub[32], z[32], m[4096], h[32]; int i;
    TIME("tables (boot)", 1, __asm__ volatile("call echost" ::: SCRATCH));
    for(i=0;i<32;i++) E[i]=i*7+1, z[i]=i*3;
    TIME("x25519: our share and the secret", 2000, { u8 *p = pub; const u8 *q = u; ASMCALL(xdh, "+D"(p), "+S"(q)); });
    TIME("ecdsa: sign (64 nonces at a time)", 6400, { const u8 *q = z; ASMCALL(sign, "+S"(q)); });
    TIME("ecdsa: one more nonce, or 64 /", 6500, __asm__ volatile("call hstock" ::: SCRATCH));
    /* (what full load is: each of the two alone is cheaper than between the other's turns) */
    TIME("the two in turn, as a handshake", 1280, { u8 *p = pub; const u8 *q = u; ASMCALL(xdh, "+D"(p), "+S"(q)); q = z; ASMCALL(sign, "+S"(q)); });
    TIME("sha256 of 64 bytes (2 blocks)", 20000, { u8 *o = h, *mm = m; unsigned n = 64; ASMCALL(sha256, "+D"(o), "+S"(mm), "+c"(n)); });
    TIME("sha256 of 3000 bytes", 2000, { u8 *o = h, *mm = m; unsigned n = 3000; ASMCALL(sha256, "+D"(o), "+S"(mm), "+c"(n)); });
    static u8 hmkey[32], hmmsg[64], hmout[32];
    for(int j=0;j<32;j++)hmkey[j]=j*3+1;
    for(int j=0;j<64;j++)hmmsg[j]=j*7+3;
    TIME("HMAC-SHA256 of 50 bytes", 20000, { u8 *o=hmout; const u8 *k=hmkey,*mm=hmmsg; unsigned n=50; ASMCALL(hmac,"+D"(o),"+b"(k),"+S"(mm),"+c"(n)); });
    TIME("HMAC-SHA256 of 64 bytes", 20000, { u8 *o=hmout; const u8 *k=hmkey,*mm=hmmsg; unsigned n=64; ASMCALL(hmac,"+D"(o),"+b"(k),"+S"(mm),"+c"(n)); });
    /* A short response, a mid-size record, and the largest record in one segment. */
    static u8 kiv[44], rec[2048], random[32], rngseed[32];
    unsigned eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & bit_RDRND) && rdrand_ready()) {
        int failed = 0;
        TIME("random: four 64-bit values", 2000, if (!rdrand4(random)) failed++);
        if (failed) printf("RDRAND sample failures: %d\n", failed);
    }
    else
        puts("random: four 64-bit values       skipped (RDRAND unavailable)");
    for (int j = 0; j < sizeof rngseed; j++) rngseed[j] = j;
    {
        u8 *seed = rngseed;
        ASMCALL(hctr_test_seed, "+D"(seed));
    }
    TIME("random: CTR_DRBG four qwords", 2000, { u8 *p = random; unsigned n = 4; ASMCALL(hctr_test_generate, "+D"(p), "+c"(n)); });
    static const int record_lens[] = {64, 180, 512, 1024, 1418};
    for (int j = 0; j < sizeof record_lens / sizeof *record_lens; j++) {
        int len = record_lens[j];
        char t[64];
        sprintf(t, "AES-128-GCM record of %d bytes", len);
        TIME(t, 20000, { u8 *o = rec, *mm = m, *k = kiv; unsigned n = len, seq = i, type = 23;
            __asm__ volatile("clc\n\tcall seal" : "+D"(o), "+S"(mm), "+c"(n), "+b"(k), "+d"(seq), "+a"(type) : : SCRATCH); });
        /* Compare rebuilding AES/GHASH setup with reusing the just-built context. */
        { u8 *o=rec,*mm=m,*k=kiv; unsigned n=len,seq=0,type=23;
          __asm__ volatile("clc\n\tcall seal" : "+D"(o), "+S"(mm), "+c"(n), "+b"(k), "+d"(seq), "+a"(type) : : SCRATCH); }
        sprintf(t, "AES-128-GCM cached record %d bytes", len);
        TIME(t, 20000, { u8 *o = rec, *mm = m, *k = kiv; unsigned n = len, seq = i, type = 23;
            __asm__ volatile("clc\n\tcall seal_cached" : "+D"(o), "+S"(mm), "+c"(n), "+b"(k), "+d"(seq), "+a"(type) : : SCRATCH); });
    }
    /* the pieces: one multiplication, one addition, one ladder step, one inversion */
    static const char *const fn[] = {"2^255-19", "P-256 p", "P-256 n"};
    extern u8 X_MADDED[], X_MADD256[];
    for (int f = 0; f < 3; f++) {
        char t[64];
        u8 *a = REGS + 7 * 32, *b = REGS + 8 * 32;
        sprintf(t, "multiplication, %s", fn[f]);
        TIME(t, 200000, { u8 *d = a, *x = a, *y = b; int c = f; __asm__ volatile("call hfmul" : "+D"(d), "+S"(x), "+b"(y), "+c"(c) : : SCRATCH); });
        sprintf(t, "squaring, %s", fn[f]);
        TIME(t, 200000, { u8 *d = a, *x = a; int c = f; __asm__ volatile("call hfsqr" : "+D"(d), "+S"(x), "+c"(c) : : SCRATCH); });
        sprintf(t, "addition, %s", fn[f]);
        TIME(t, 200000, { u8 *d = a, *x = a, *y = b; int c = f; __asm__ volatile("call hfas" : "+D"(d), "+S"(x), "+b"(y), "+c"(c) : : SCRATCH); });
        sprintf(t, "inversion, %s", fn[f]);
        TIME(t, 2000, { u8 *x = a; int c = f; __asm__ volatile("call hinv" : "+S"(x), "+c"(c) : : SCRATCH); });
    }
    TIME("ladder step (10 mul, 8 add)", 100000, __asm__ volatile("call hstep" ::: SCRATCH));
    TIME("edwards madd (7 mul, 7 add)", 100000, { u8 *x = X_MADDED; int c = 0; __asm__ volatile("call hvm" : "+S"(x), "+c"(c) : : SCRATCH); });
    TIME("P-256 madd (11 mul, 7 add)", 100000, { u8 *x = X_MADD256; int c = 1; __asm__ volatile("call hvm" : "+S"(x), "+c"(c) : : SCRATCH); });
    return 0;
}
