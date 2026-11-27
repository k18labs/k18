// rawc: plain-HTTP connections to the guest made of raw packets on the tap. No sockets: a
// connection costs this client 12 bytes, so tens of millions fit, from as many source
// addresses as that takes (the host has none of them: the guest answers to our MAC, and the
// host's own IP stack drops what is not for it). Run inside ./tap.sh:
//
//   rawc N [W]     open N connections (W in flight, default 512), fetch the page over each as
//                  it opens, then fetch it again over every one of them
//
// Each connection: SYN, (SYN-ACK), ACK with the request, (response), ACK. A packet that gets
// no answer is sent again after RTO ms, TRIES times. Prints what happened to how many.
// Env: IP0 (first source address, default 10.64.0.0), PPI (ports per address, default 60000),
//      HOLD (seconds between opening and the second fetch), ROUNDS (second fetches, default 1),
//      SPLIT (set: the ack and the request go as two packets), CLOSE (set: FIN at the end),
//      RTO (ms, default 500), TRIES (default 8), GUEST, TAP, DPORT, VIA.
//
// On a real interface instead of the tap (as root, from a machine next to the server):
// TAP=eth0 GUEST=<server> VIA=<next hop, whose MAC the frames go to> IP0=<a source address>.
// The source addresses must be routed back to that machine and must not be its own, or its
// kernel answers the server's SYN-ACKs with resets (or drop those: iptables -A OUTPUT -p tcp
// --tcp-flags RST RST -d <server> -j DROP). One address gives PPI connections, at most 64,511.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Override in test builds; production does not resolve this command through PATH. */
#ifndef K18_IP_PATH
#define K18_IP_PATH "/usr/sbin/ip"
#endif

enum { NEW, SYN, REQ, IDLE, FIN, DONE, FAILED };
typedef struct {
    uint32_t iss;   // the server's initial sequence number
    uint32_t sent;  // when our last packet went out (ms)
    uint16_t reqs;  // responses received
    uint8_t st, tries;
} conn;

static conn *C;
static uint32_t N, W = 512, PPI = 60000, IP0, GUEST, RTO = 500, TRIES = 8;
static int fd, DPORT = 80, SPLIT, inflight;
static uint8_t mac_dst[6], mac_src[6];
static char resp[4096];
static int rlen;
static const char REQ_[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
#define QLEN ((int)sizeof REQ_ - 1)
static uint64_t n_tx, n_rx, n_retx, n_reset, n_timeout, n_bad, n_served;

static uint32_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static double mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static uint32_t isn(uint32_t i) { return i * 2654435761u + 12345; }

static uint32_t sum16(const uint8_t *p, int n, uint32_t s) {
    for (; n > 1; n -= 2, p += 2) s += p[0] << 8 | p[1];
    if (n) s += p[0] << 8;
    return s;
}
static uint16_t fold(uint32_t s) {
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return ~s;
}

#define BATCH 256
static uint8_t txb[BATCH][160];
static struct mmsghdr txm[BATCH];
static struct iovec txv[BATCH];
static int txn;

static void flush(void) {
    for (int off = 0; off < txn;) {
        int r = sendmmsg(fd, txm + off, txn - off, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == ENOBUFS) { usleep(100); continue; }
            perror("sendmmsg");
            exit(1);
        }
        off += r;
    }
    txn = 0;
}

static void tx(uint32_t i, uint8_t flags, uint32_t seq, uint32_t ack, const char *pay, int n) {
    uint8_t *f = txb[txn];
    uint32_t src = htonl(IP0 + i / PPI);
    uint16_t sport = 1024 + i % PPI;
    memcpy(f, mac_dst, 6);
    memcpy(f + 6, mac_src, 6);
    f[12] = 8, f[13] = 0;
    uint8_t *ip = f + 14, *tcp = f + 34;
    memset(ip, 0, 40);
    ip[0] = 0x45;
    ip[2] = (40 + n) >> 8, ip[3] = 40 + n;
    ip[6] = 0x40;
    ip[8] = 64, ip[9] = 6;
    memcpy(ip + 12, &src, 4);
    memcpy(ip + 16, &GUEST, 4);
    uint16_t c = fold(sum16(ip, 20, 0));
    ip[10] = c >> 8, ip[11] = c;
    tcp[0] = sport >> 8, tcp[1] = sport;
    tcp[2] = DPORT >> 8, tcp[3] = DPORT;
    tcp[4] = seq >> 24, tcp[5] = seq >> 16, tcp[6] = seq >> 8, tcp[7] = seq;
    tcp[8] = ack >> 24, tcp[9] = ack >> 16, tcp[10] = ack >> 8, tcp[11] = ack;
    tcp[12] = 0x50, tcp[13] = flags;
    tcp[14] = 0xFF, tcp[15] = 0xFF;
    if (n) memcpy(tcp + 20, pay, n);
    c = fold(sum16(tcp, 20 + n, sum16(ip + 12, 8, 6 + 20 + n)));
    tcp[16] = c >> 8, tcp[17] = c;
    txv[txn].iov_base = f;
    txv[txn].iov_len = 54 + n;
    txm[txn].msg_hdr.msg_iov = &txv[txn];
    txm[txn].msg_hdr.msg_iovlen = 1;
    n_tx++;
    if (++txn == BATCH) flush();
}

static void request(uint32_t i, uint32_t t) {  // (again, if it is not the first time)
    conn *c = &C[i];
    uint32_t seq = isn(i) + 1 + c->reqs * QLEN;
    if (SPLIT && !c->reqs) tx(i, 0x10, seq, c->iss + 1, NULL, 0);
    tx(i, 0x18, seq, c->iss + 1 + c->reqs * rlen, REQ_, QLEN);
    c->st = REQ;
    c->sent = t;
}

static void fail(conn *c, uint64_t *why) {
    if (c->st == SYN || c->st == REQ || c->st == FIN) inflight--;
    c->st = FAILED;
    ++*why;
}

static void rx(const uint8_t *f, int len, uint32_t t) {
    if (len < 54 || f[12] != 8 || f[13] != 0 || f[23] != 6 || memcmp(f + 26, &GUEST, 4)) return;
    const uint8_t *ip = f + 14, *tcp = ip + (ip[0] & 15) * 4;
    if ((tcp[0] << 8 | tcp[1]) != DPORT) return;
    uint32_t a = ((uint32_t)ip[16] << 24 | ip[17] << 16 | ip[18] << 8 | ip[19]) - IP0, p = (tcp[2] << 8 | tcp[3]) - 1024;
    if (p >= PPI || a >= (N + PPI - 1) / PPI) return;
    uint32_t i = a * PPI + p;
    if (i >= N) return;
    conn *c = &C[i];
    int n = (ip[2] << 8 | ip[3]) - (ip[0] & 15) * 4 - (tcp[12] >> 4) * 4;
    uint32_t seq = tcp[4] << 24 | tcp[5] << 16 | tcp[6] << 8 | tcp[7];
    uint8_t flags = tcp[13];
    n_rx++;
    if (c->st == FAILED || c->st == DONE) return;
    if (flags & 4) return fail(c, &n_reset);
    if ((flags & 0x12) == 0x12) {
        if (c->st != SYN) return;
        c->iss = seq;
        c->tries = 0;
        return request(i, t);
    }
    if (c->st == FIN && (flags & 1)) {
        tx(i, 0x10, isn(i) + 2 + c->reqs * QLEN, seq + n + 1, NULL, 0);
        c->st = DONE;
        inflight--;
        n_served++;
        return;
    }
    if (n <= 0 || c->st != REQ) return;
    if (seq != c->iss + 1 + c->reqs * rlen) return;  // (an old one again)
    if (n != rlen || memcmp(tcp + (tcp[12] >> 4) * 4, resp, rlen)) return fail(c, &n_bad);
    c->reqs++;
    c->tries = 0;
    c->st = IDLE;
    inflight--;
    n_served++;
    tx(i, 0x10, isn(i) + 1 + c->reqs * QLEN, seq + n, NULL, 0);
}

static void pump(void) {
    static uint8_t rb[BATCH][2048];
    static struct mmsghdr rm[BATCH];
    static struct iovec rv[BATCH];
    for (int k = 0; k < BATCH; k++) {
        rv[k].iov_base = rb[k], rv[k].iov_len = sizeof rb[k];
        rm[k].msg_hdr.msg_iov = &rv[k], rm[k].msg_hdr.msg_iovlen = 1;
    }
    flush();
    int r = recvmmsg(fd, rm, BATCH, MSG_DONTWAIT, NULL);
    if (r <= 0) {
        struct pollfd pf = {fd, POLLIN, 0};
        poll(&pf, 1, 1);
        return;
    }
    uint32_t t = now_ms();
    for (int k = 0; k < r; k++) rx(rb[k], rm[k].msg_len, t);
}

// one pass over all connections: start(i) sends the first packet of what is to happen to i
static void phase(const char *name, void (*start)(uint32_t, uint32_t)) {
    uint32_t next = 0, base = 0, scanned = now_ms();
    uint64_t served0 = n_served, reset0 = n_reset, timeout0 = n_timeout, retx0 = n_retx;
    double t0 = mono(), shown = t0;
    while (base < N) {
        uint32_t t = now_ms();
        while (next < N && inflight < (int)W) start(next++, t);
        pump();
        t = now_ms();
        if (t - scanned >= 20) {
            scanned = t;
            for (uint32_t i = base; i < next; i++) {
                conn *c = &C[i];
                if ((c->st != SYN && c->st != REQ && c->st != FIN) || t - c->sent < RTO << (c->tries > 3 ? 3 : c->tries)) continue;
                if (++c->tries > TRIES) { fail(c, &n_timeout); continue; }
                n_retx++;
                c->sent = t;
                if (c->st == SYN) tx(i, 0x02, isn(i), 0, NULL, 0);
                else if (c->st == REQ) request(i, t);
                else tx(i, 0x11, isn(i) + 1 + c->reqs * QLEN, c->iss + 1 + c->reqs * rlen, NULL, 0);
            }
            while (base < next && C[base].st != SYN && C[base].st != REQ && C[base].st != FIN) base++;
        }
        if (mono() - shown > 5) {
            shown = mono();
            fprintf(stderr, "  %s: %u of %u started, %.0f s\n", name, next, N, shown - t0);
        }
    }
    double dt = mono() - t0;
    printf("RAW %s: %llu of %u in %.1f s (%.0f/s), %llu reset, %llu timed out, %llu sent again\n", name,
           (unsigned long long)(n_served - served0), N, dt, N / dt, (unsigned long long)(n_reset - reset0),
           (unsigned long long)(n_timeout - timeout0), (unsigned long long)(n_retx - retx0));
    fflush(stdout);
}

static void open_(uint32_t i, uint32_t t) {
    C[i].st = SYN;
    C[i].sent = t;
    inflight++;
    tx(i, 0x02, isn(i), 0, NULL, 0);
}
static void again(uint32_t i, uint32_t t) {
    if (C[i].st != IDLE) return;
    inflight++;
    request(i, t);
}
static void close_(uint32_t i, uint32_t t) {
    if (C[i].st != IDLE) return;
    inflight++;
    C[i].st = FIN;
    C[i].sent = t;
    tx(i, 0x11, isn(i) + 1 + C[i].reqs * QLEN, C[i].iss + 1 + C[i].reqs * rlen, NULL, 0);
}

/* Keep the neighbor lookup out of a shell; address is already a canonical IPv4 string. */
static int neighbor_line(const char *address, char *line, size_t size) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        int err = errno;
        close(pfd[0]);
        close(pfd[1]);
        errno = err;
        return -1;
    }
    if (child == 0) {
        close(pfd[0]);
        if (dup2(pfd[1], STDOUT_FILENO) < 0) _exit(126);
        close(pfd[1]);
        execl(K18_IP_PATH, "ip", "neigh", "show", address, (char *)NULL);
        _exit(127);
    }

    close(pfd[1]);
    FILE *out = fdopen(pfd[0], "r");
    if (!out) {
        int err = errno;
        close(pfd[0]);
        int status;
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        errno = err;
        return -1;
    }
    int have_line = fgets(line, size, out) != NULL;
    int read_error = ferror(out);
    fclose(out);

    int status;
    pid_t waited;
    do waited = waitpid(child, &status, 0); while (waited < 0 && errno == EINTR);
    if (waited < 0) return -1;
    if (!have_line || read_error || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return fprintf(stderr, "usage: rawc N [W]\n"), 2;
    N = strtoul(argv[1], 0, 0);
    if (argc > 2) W = atoi(argv[2]);
    const char *e, *tap = (e = getenv("TAP")) ? e : "k2t", *guest = (e = getenv("GUEST")) ? e : "10.0.2.15";
    IP0 = ntohl(inet_addr((e = getenv("IP0")) ? e : "10.64.0.0"));
    GUEST = inet_addr(guest);
    if ((e = getenv("PPI"))) PPI = atoi(e);
    if ((e = getenv("RTO"))) RTO = atoi(e);
    if ((e = getenv("TRIES"))) TRIES = atoi(e);
    if ((e = getenv("DPORT"))) DPORT = atoi(e);
    SPLIT = getenv("SPLIT") != NULL;
    int rounds = (e = getenv("ROUNDS")) ? atoi(e) : 1, hold = (e = getenv("HOLD")) ? atoi(e) : 0;

    char cmd[128], line[256] = "";
    snprintf(cmd, sizeof cmd, "%s/page80.bin", (e = getenv("B")) ? e : "build");  // what port 80 says (tools/pack.py)
    FILE *f = fopen(cmd, "rb");
    if (!f) return perror(cmd), 2;
    rlen = fread(resp, 1, sizeof resp, f);
    fclose(f);
    if (rlen < 1 || rlen > 1400) return fprintf(stderr, "%s: a response of one segment is all this client knows\n", cmd), 2;

    const char *via = (e = getenv("VIA")) ? e : guest;
    struct in_addr via_addr;
    char via_ip[INET_ADDRSTRLEN];
    if (inet_pton(AF_INET, via, &via_addr) != 1)
        return fprintf(stderr, "invalid VIA IPv4 address: %s\n", via), 2;
    if (!inet_ntop(AF_INET, &via_addr, via_ip, sizeof via_ip)) return perror("inet_ntop"), 2;
    if (neighbor_line(via_ip, line, sizeof line) < 0 || !strstr(line, "lladdr"))
        return fprintf(stderr, "no neighbour entry for %s\n", via), 2;
    unsigned m[6];
    if (sscanf(strstr(line, "lladdr") + 7, "%2x:%2x:%2x:%2x:%2x:%2x", m, m + 1, m + 2, m + 3, m + 4, m + 5) != 6)
        return fprintf(stderr, "invalid neighbour entry for %s\n", via), 2;
    for (int k = 0; k < 6; k++) mac_dst[k] = m[k];

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) return perror("socket"), 1;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, tap, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) return perror(tap), 1;
    memcpy(mac_src, ifr.ifr_hwaddr.sa_data, 6);
    struct sockaddr_ll ll = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP), .sll_ifindex = if_nametoindex(tap)};
    if (bind(fd, (void *)&ll, sizeof ll) < 0) return perror("bind"), 1;
    int one = 1, big = 256 << 20;
#ifdef PACKET_IGNORE_OUTGOING
    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof one);
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &big, sizeof big) < 0) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &big, sizeof big);
    (void)one;

    C = calloc(N, sizeof(conn));
    if (!C) return perror("calloc"), 1;
    phase("opened and fetched", open_);
    if (hold) sleep(hold);
    for (int r = 0; r < rounds; r++) phase("fetched again", again);
    if (getenv("CLOSE")) phase("closed", close_);
    uint32_t held = 0;
    for (uint32_t i = 0; i < N; i++) held += C[i].st == IDLE || C[i].st == DONE;
    printf("RAW total: %u of %u connections %s; %llu packets out, %llu in, %llu unexpected answers\n", held, N,
           getenv("CLOSE") ? "served to the end" : "held and served to the end", (unsigned long long)n_tx,
           (unsigned long long)n_rx, (unsigned long long)n_bad);
    return held != N;
}
