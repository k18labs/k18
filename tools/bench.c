// bench: how many connections (or requests) a second a server takes, and how long each
// takes: for k18 and for whatever it is compared with (bench/). Unlike tapc it does not hold
// connections: each of W places per process connects, does the TLS handshake, fetches the
// page KA times, closes (with a reset: no TIME-WAIT, on either side), and starts over, for
// T seconds. P processes, each with its own epoll and its own OpenSSL context.
//
//   DST=ip:port [PLAIN=1] [P=4] [W=64] [T=10] [KA=1] bench
//
// Env: DST (default 10.0.2.15:443, or :80 with PLAIN), P (processes), W (connections in
// flight in each), T (seconds measured, after one of warm-up), KA (requests per connection:
// 1 measures handshakes, many measures requests), SUITES and KEX (what the client offers:
// default TLS_AES_128_GCM_SHA256 and X25519, so that every server is asked for the same
// work; KEX='*X25519MLKEM768:*X25519' sends the two key shares, 1.5 KB of ClientHello, that
// browsers and OpenSSL 3.5 send by default; the name is not GROUPS because bash keeps that
// one to itself), CA (a file: verify the chain against it, as a browser would; default: no
// verification, which leaves the client more time to ask), SRC (bind to this address),
// TIMEOUT (seconds a connection may take, default 10).
// Prints connections/s, requests/s, errors, and the time from connect() (KA=1) or from the
// request (KA>1) to the last byte of the response: median, 90%, 99%, 99.9%, longest.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { FREE, CONNECTING, HANDSHAKE, REQUEST, RESPONSE };
#define NB 200000            // histogram: buckets of 10 us, up to 2 s; the last one is "longer"
typedef struct {
    uint64_t conns, reqs, errs, timeouts, bytes;
    uint32_t hist[NB];
} stats;
typedef struct {
    SSL *ssl;
    int fd, got, want, left;
    uint64_t t0, deadline;
    uint8_t st, ev;
    char buf[2048];
} conn;

static const char REQ[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
static int W = 64, T = 10, KA = 1, PLAIN, TIMEOUT = 10, ep, measuring;
static struct sockaddr_in dst, src;
static int have_src;
static SSL_CTX *ctx;
static stats *st;
static conn *C;

static uint64_t now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000ull + t.tv_nsec / 1000;
}

static void want(conn *c, int ev) {
    if (c->ev == ev) return;
    struct epoll_event e = {.events = ev, .data.ptr = c};
    epoll_ctl(ep, c->ev ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, c->fd, &e);
    c->ev = ev;
}

static void start(conn *c);

static void done(conn *c, int err) {  // close with a reset, and begin again
    if (measuring) {
        if (err == 2) st->timeouts++;
        else if (err) st->errs++;
    }
    if (c->ssl) SSL_free(c->ssl);
    c->ssl = NULL;
    close(c->fd);
    c->st = FREE;
    ERR_clear_error();
    start(c);
}

static void start(conn *c) {
    int one = 1;
    struct linger lg = {1, 0};
    c->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (c->fd < 0) { perror("socket"); exit(1); }
    setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (have_src) {
        setsockopt(c->fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof one);
        bind(c->fd, (void *)&src, sizeof src);
    }
    c->ev = 0;
    c->got = 0;
    c->want = 0;
    c->left = KA;
    c->st = CONNECTING;
    c->t0 = now_us();
    c->deadline = c->t0 + TIMEOUT * 1000000ull;
    if (connect(c->fd, (void *)&dst, sizeof dst) < 0 && errno != EINPROGRESS) {
        if (measuring) st->errs++;
        close(c->fd);
        c->st = FREE;  // (out of ports, or refused at once: try again on the next turn)
        return;
    }
    want(c, EPOLLOUT);
}

// the length of the response whose start is in b (n bytes), or 0 if its header is not all there
static int resp_len(const char *b, int n) {
    const char *e = memmem(b, n, "\n\n", 2), *e2 = memmem(b, n, "\r\n\r\n", 4);
    int h;
    if (e2 && (!e || e2 < e)) h = e2 + 4 - b;
    else if (e) h = e + 2 - b;
    else return 0;
    for (const char *p = b; p < b + h - 15; p++)
        if ((p == b || p[-1] == '\n') && !strncasecmp(p, "Content-Length:", 15)) return h + atoi(p + 15);
    return h;
}

static int blocked(conn *c, int r) {  // after a call that did not finish: 1 = wait for the socket
    if (PLAIN) return r < 0 && errno == EAGAIN ? want(c, EPOLLIN), 1 : 0;
    int e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ) return want(c, EPOLLIN), 1;
    if (e == SSL_ERROR_WANT_WRITE) return want(c, EPOLLOUT), 1;
    return 0;
}

static void drive(conn *c) {
    int r;
    if (c->st == CONNECTING) {
        int err = 0;
        socklen_t l = sizeof err;
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) return done(c, 1);
        if (measuring) st->conns++;
        if (!PLAIN) {
            c->ssl = SSL_new(ctx);
            SSL_set_fd(c->ssl, c->fd);
            SSL_set_connect_state(c->ssl);
            c->st = HANDSHAKE;
        } else c->st = REQUEST;
    }
    if (c->st == HANDSHAKE) {
        if ((r = SSL_do_handshake(c->ssl)) != 1) {
            if (!blocked(c, r)) done(c, 1);
            return;
        }
        c->st = REQUEST;
    }
    for (;;) {
        if (c->st == REQUEST) {
            if (KA > 1) c->t0 = now_us();
            r = PLAIN ? write(c->fd, REQ, sizeof REQ - 1) : SSL_write(c->ssl, REQ, sizeof REQ - 1);
            if (r <= 0) {
                if (!blocked(c, r)) done(c, 1);
                return;
            }
            c->st = RESPONSE;
            c->got = c->want = 0;
        }
        for (;;) {  // RESPONSE
            r = PLAIN ? read(c->fd, c->buf + c->got, sizeof c->buf - c->got)
                      : SSL_read(c->ssl, c->buf + c->got, sizeof c->buf - c->got);
            if (r <= 0) {
                if (!blocked(c, r)) done(c, 1);
                return;
            }
            c->got += r;
            if (!c->want) c->want = resp_len(c->buf, c->got);
            if (c->want && c->got >= c->want) break;
            if (c->got == sizeof c->buf) return done(c, 1);  // (not our page)
        }
        if (measuring) {
            uint64_t us = now_us() - c->t0;
            st->reqs++;
            st->bytes += c->got;
            st->hist[us / 10 < NB ? us / 10 : NB - 1]++;
        }
        if (--c->left <= 0) return done(c, 0);
        c->deadline = now_us() + TIMEOUT * 1000000ull;
        c->st = REQUEST;
    }
}

static void worker(void) {
    static struct epoll_event ev[512];
    C = calloc(W, sizeof(conn));
    ep = epoll_create1(0);
    if (!PLAIN) {
        const char *e;
        ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
        if (!SSL_CTX_set_ciphersuites(ctx, (e = getenv("SUITES")) ? e : "TLS_AES_128_GCM_SHA256") ||
            !SSL_CTX_set1_groups_list(ctx, (e = getenv("KEX")) ? e : "X25519")) exit(2);
        if ((e = getenv("CA"))) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            if (!SSL_CTX_load_verify_locations(ctx, e, NULL)) exit(2);
        }
    }
    uint64_t t0 = now_us(), tm = t0 + 1000000, tend = tm + T * 1000000ull, swept = t0;
    for (int i = 0; i < W; i++) start(&C[i]);
    for (;;) {
        int n = epoll_wait(ep, ev, 512, 10);
        for (int i = 0; i < n; i++) {
            conn *c = ev[i].data.ptr;
            if (ev[i].events & (EPOLLERR | EPOLLHUP) && c->st != CONNECTING) done(c, 1);
            else drive(c);
        }
        uint64_t t = now_us();
        if (!measuring && t >= tm) measuring = 1;
        if (t >= tend) break;
        if (t - swept > 100000) {
            swept = t;
            for (int i = 0; i < W; i++)
                if (C[i].st == FREE) start(&C[i]);
                else if (C[i].deadline < t) done(&C[i], 2);
        }
    }
    _exit(0);
}

int main(void) {
    const char *e;
    int P = 4, dport;
    char dip[64] = "10.0.2.15";
    PLAIN = getenv("PLAIN") != NULL;
    dport = PLAIN ? 80 : 443;
    if ((e = getenv("DST"))) sscanf(e, "%63[^:]:%d", dip, &dport);
    if ((e = getenv("P"))) P = atoi(e);
    if ((e = getenv("W"))) W = atoi(e);
    if ((e = getenv("T"))) T = atoi(e);
    if ((e = getenv("KA"))) KA = atoi(e);
    if ((e = getenv("TIMEOUT"))) TIMEOUT = atoi(e);
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, dip, &dst.sin_addr);
    dst.sin_port = htons(dport);
    if ((e = getenv("SRC"))) {
        have_src = 1;
        src.sin_family = AF_INET;
        inet_pton(AF_INET, e, &src.sin_addr);
    }
    signal(SIGPIPE, SIG_IGN);
    stats *all = mmap(NULL, P * sizeof(stats), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (all == MAP_FAILED) { perror("mmap"); return 1; }
    for (int p = 0; p < P; p++)
        if (!fork()) {
            st = &all[p];
            worker();
        }
    while (wait(NULL) > 0) {}
    static stats sum;
    for (int p = 0; p < P; p++) {
        sum.conns += all[p].conns, sum.reqs += all[p].reqs, sum.errs += all[p].errs;
        sum.timeouts += all[p].timeouts, sum.bytes += all[p].bytes;
        for (int i = 0; i < NB; i++) sum.hist[i] += all[p].hist[i];
    }
    double q[] = {0.5, 0.9, 0.99, 0.999, 1}, ms[5] = {0};
    uint64_t seen = 0;
    for (int i = 0, k = 0; i < NB && k < 5; i++) {
        seen += sum.hist[i];
        while (k < 5 && sum.reqs && seen >= q[k] * sum.reqs && seen) ms[k++] = (i + 1) / 100.0;
    }
    printf("%s %s:%d P=%d W=%d KA=%d T=%d: %.0f connections/s, %.0f requests/s, %llu errors, %llu timeouts; "
           "ms: median %.2f, 90%% %.2f, 99%% %.2f, 99.9%% %.2f, longest %.2f%s\n",
           PLAIN ? "http" : "https", dip, dport, P, W, KA, T, (double)sum.conns / T, (double)sum.reqs / T,
           (unsigned long long)sum.errs, (unsigned long long)sum.timeouts, ms[0], ms[1], ms[2], ms[3], ms[4],
           sum.hist[NB - 1] ? " (or more)" : "");
    return 0;
}
