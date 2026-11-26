// tapc: lean TLS load client (from k1), verifying the certificate chain and name on every
// connection. One worker = one source IP, one thread, epoll, OpenSSL; ~20 KB per connection.
//
//   tapc SRC_IP BASE_PORT COUNT INDEX_HTML [BARRIER_DIR WORKER_ID WORKERS]
//
// Opens COUNT TLS connections from SRC_IP:BASE_PORT.. to $DST (default 10.0.2.15:443, the guest
// on tap; 127.0.0.1:8443 reaches it through slirp's hostfwd) and keeps them open. At
// 64, 128, ... open and at the end it fetches the page over every connection and compares the body.
// With a barrier directory, workers wait until all have opened before the final fetch, and hold
// their connections until all have finished it, so every connection is open at the same time.
// Env: PLAIN (set: plain HTTP to port 80, no TLS), INFLIGHT (handshakes/fetches at once,
// default 4), TIMEOUT (seconds, default 60), NOMARK (set: no fetches before all are open:
// open_s is then the time the handshakes took), SUITES (the TLS 1.3 cipher suites to offer, e.g.
// TLS_AES_128_GCM_SHA256; default: OpenSSL's, of which the server takes AES-128-GCM),
// DST (ip:port), B (build directory: B/name is the name the certificate must carry, B/ca.pem
// the CA to trust; an empty ca.pem means the system's roots, for a real certificate).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { UNUSED, CONNECTING, HANDSHAKE, IDLE, REQUEST, RESPONSE, FAILED };

typedef struct {
    SSL *ssl;
    int fd;
    uint32_t deadline;
    uint8_t st, ev;
} conn;

static const char REQ[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
static conn *C;
static int N, ep, inflight, opened, served, hs_err, get_err, closed_err, in_use;
static int INFLIGHT = 4, TIMEOUT = 60, PLAIN;
static SSL_CTX *ctx;
static struct sockaddr_storage src, dst;   // (IPv4, or IPv6 if SRC_IP is such an address)
static socklen_t alen;
static char srcname[64];
// (the port of an address of either kind)
static in_port_t *portof(struct sockaddr_storage *a) {
    return a->ss_family == AF_INET6 ? &((struct sockaddr_in6 *)a)->sin6_port : &((struct sockaddr_in *)a)->sin_port;
}
static char expect[4096];
static int expect_len;

static uint32_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec;
}
static double mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void want(conn *c, int ev) {
    if (c->ev == ev) return;
    struct epoll_event e = {.events = ev, .data.ptr = c};
    epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &e);
    c->ev = ev;
}

static void fail(conn *c, const char *why) {
    static const char *const what[] = {"unused", "connecting", "handshake", "idle", "request", "response", "failed"};
    fprintf(stderr, "FAILED: %s port %d while in %s: %s\n", srcname, ntohs(*portof(&src)) + (int)(c - C),
            what[c->st], why);
    if (c->st == CONNECTING || c->st == HANDSHAKE) hs_err++, inflight--;
    else if (c->st == REQUEST || c->st == RESPONSE) get_err++, inflight--, opened--;
    else if (c->st == IDLE) closed_err++, opened--;
    if (c->ssl) SSL_free(c->ssl);
    c->ssl = NULL;
    close(c->fd);
    c->st = FAILED;
    ERR_clear_error();
}

static const char *why(conn *c, int r) {  // what a call that failed for good says about it
    static char b[200];
    if (PLAIN) return r == 0 ? "closed by the server" : strerror(errno);
    int e = SSL_get_error(c->ssl, r);
    unsigned long q = ERR_peek_error();
    if (e == SSL_ERROR_SSL && q) return ERR_error_string_n(q, b, sizeof b), b;
    if (e == SSL_ERROR_SYSCALL) return errno ? strerror(errno) : "closed by the server, no close_notify";
    if (e == SSL_ERROR_ZERO_RETURN) return "closed by the server";
    snprintf(b, sizeof b, "SSL error %d", e);
    return b;
}

static int blocked(conn *c, int r) {  // after an SSL call failed: 1 = wait for the socket
    if (PLAIN) return r < 0 && errno == EAGAIN ? want(c, EPOLLIN), 1 : 0;
    int e = SSL_get_error(c->ssl, r);
    if (e == SSL_ERROR_WANT_READ) return want(c, EPOLLIN), 1;
    if (e == SSL_ERROR_WANT_WRITE) return want(c, EPOLLOUT), 1;
    return 0;
}

static int body_ok(const char *b, int n) {
    const char *end = memmem(b, n, "\n\n", 2), *cl = memmem(b, n, "Content-Length:", 15);
    const char *crlf = memmem(b, n, "\r\n\r\n", 4);  // (other servers than ours end lines so)
    if (crlf && (!end || crlf < end)) end = crlf + 2;
    if (!end || !cl) return 0;
    int len = atoi(cl + 15);
    end += 2;
    return len == expect_len && end + len == b + n && !memcmp(end, expect, len);
}

static void drive(conn *c, uint32_t ev) {
    char buf[1024];
    int r;
    if (c->st == IDLE) {  // the server never speaks first: any event on an idle connection means it died
        fail(c, "the server spoke or closed");
        return;
    }
    if (c->st == CONNECTING) {
        int err = 0;
        socklen_t l = sizeof err;
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) return fail(c, strerror(err));
        if (PLAIN) {
            c->st = IDLE;
            inflight--;
            opened++;
            want(c, 0);
            return;
        }
        c->ssl = SSL_new(ctx);
        SSL_set_fd(c->ssl, c->fd);
        SSL_set_connect_state(c->ssl);
        c->st = HANDSHAKE;
    }
    if (c->st == HANDSHAKE) {
        if ((r = SSL_do_handshake(c->ssl)) != 1) {
            if (!blocked(c, r)) fail(c, why(c, r));
            return;
        }
        c->st = IDLE;
        inflight--;
        opened++;
        want(c, 0);
        return;
    }
    if (c->st == REQUEST) {
        if ((r = PLAIN ? write(c->fd, REQ, sizeof REQ - 1) : SSL_write(c->ssl, REQ, sizeof REQ - 1)) <= 0) {
            if (!blocked(c, r)) fail(c, why(c, r));
            return;
        }
        c->st = RESPONSE;
    }
    if (c->st == RESPONSE) {
        if ((r = PLAIN ? read(c->fd, buf, sizeof buf) : SSL_read(c->ssl, buf, sizeof buf)) <= 0) {
            if (!blocked(c, r)) fail(c, why(c, r));
            return;
        }
        if (!body_ok(buf, r)) return fail(c, "not the page");  // each response is one TLS record
        c->st = IDLE;
        inflight--;
        served++;
        want(c, 0);
    }
    (void)ev;
}

static void start(int i) {
    conn *c = &C[i];
    int one = 1;
    struct linger lg = {1, 0};  // reset on exit, so the next run can reuse the ports at once
    c->fd = socket(src.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (c->fd < 0) { perror("socket"); exit(1); }
    setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    setsockopt(c->fd, IPPROTO_TCP, 1 /* TCP_NODELAY */, &one, sizeof one);
    struct sockaddr_storage a = src;
    *portof(&a) = htons(ntohs(*portof(&src)) + i);
    c->st = CONNECTING;
    c->deadline = now() + TIMEOUT;
    inflight++;
    in_use = i + 1;
    if (bind(c->fd, (void *)&a, alen) < 0 ||
        (connect(c->fd, (void *)&dst, alen) < 0 && errno != EINPROGRESS)) {
        fprintf(stderr, "bind/connect port %d: %s\n", ntohs(*portof(&a)), strerror(errno));
        return fail(c, "bind/connect");
    }
    c->ev = EPOLLOUT;
    struct epoll_event e = {.events = EPOLLOUT, .data.ptr = c};
    epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &e);
}

static void pump(void) {
    static uint32_t last;
    static struct epoll_event ev[1024];
    int n = epoll_wait(ep, ev, 1024, 100);
    for (int i = 0; i < n; i++) drive(ev[i].data.ptr, ev[i].events);
    uint32_t t = now();
    if (t != last) {
        last = t;
        for (int i = 0; i < in_use; i++)
            if (C[i].st != IDLE && C[i].st != FAILED && C[i].st != UNUSED && C[i].deadline < t) fail(&C[i], "took too long");
    }
}

static void verify(void) {  // fetch the page over every open connection
    int i = 0;
    served = 0;
    while (i < in_use || inflight) {
        while (inflight < INFLIGHT && i < in_use) {
            conn *c = &C[i++];
            if (c->st != IDLE) continue;
            c->st = REQUEST;
            c->deadline = now() + TIMEOUT;
            inflight++;
            drive(c, EPOLLOUT);
        }
        if (inflight) pump();
    }
}

static void barrier(const char *dir, const char *name, const char *id, int workers) {
    char p[512];
    size_t l = strlen(name);
    snprintf(p, sizeof p, "%s/%s.%s", dir, name, id);
    close(open(p, O_CREAT | O_WRONLY, 0644));
    for (;;) {
        int k = 0;
        DIR *d = opendir(dir);
        for (struct dirent *e; (e = readdir(d));)
            k += !strncmp(e->d_name, name, l) && e->d_name[l] == '.';
        closedir(d);
        if (k >= workers) return;
        usleep(200000);
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: tapc SRC_IP BASE_PORT COUNT INDEX_HTML [BARRIER_DIR WORKER_ID WORKERS]\n");
        return 2;
    }
    if (getenv("INFLIGHT")) INFLIGHT = atoi(getenv("INFLIGHT"));
    if (getenv("TIMEOUT")) TIMEOUT = atoi(getenv("TIMEOUT"));
    PLAIN = getenv("PLAIN") != NULL;
    N = atoi(argv[3]);
    FILE *f = fopen(argv[4], "rb");
    if (!f) { perror(argv[4]); return 2; }
    expect_len = fread(expect, 1, sizeof expect, f);
    fclose(f);
    // (over IPv6 if SRC_IP is such an address: then the guest is fd00:15::15, or DST=[address]:port)
    int six = strchr(argv[1], ':') != NULL;
    char dip[64] = "10.0.2.15", name[256] = "", path[600];
    int dport = PLAIN ? 80 : 443;
    if (six) strcpy(dip, "fd00:15::15");
    if (getenv("DST") && sscanf(getenv("DST"), "[%63[^]]]:%d", dip, &dport) < 1) sscanf(getenv("DST"), "%63[^:]:%d", dip, &dport);
    snprintf(srcname, sizeof srcname, "%s", argv[1]);
    src.ss_family = dst.ss_family = six ? AF_INET6 : AF_INET;
    alen = six ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (six) {
        inet_pton(AF_INET6, argv[1], &((struct sockaddr_in6 *)&src)->sin6_addr);
        inet_pton(AF_INET6, dip, &((struct sockaddr_in6 *)&dst)->sin6_addr);
    } else {
        inet_pton(AF_INET, argv[1], &((struct sockaddr_in *)&src)->sin_addr);
        inet_pton(AF_INET, dip, &((struct sockaddr_in *)&dst)->sin_addr);
    }
    *portof(&src) = htons(atoi(argv[2]));
    *portof(&dst) = htons(dport);
    const char *bdir = getenv("B") ? getenv("B") : "build";
    snprintf(path, sizeof path, "%s/name", bdir);
    if (!(f = fopen(path, "rb")) || !fgets(name, sizeof name, f)) { perror(path); return 2; }
    fclose(f);
    name[strcspn(name, "\n")] = 0;
    const char *dir = argc > 7 ? argv[5] : NULL, *id = dir ? argv[6] : "0";
    int workers = dir ? atoi(argv[7]) : 1;

    ctx = SSL_CTX_new(TLS_client_method());
    // every connection verifies the chain and the name: no handshake completes otherwise
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    struct stat sb;
    struct in_addr tmp;
    snprintf(path, sizeof path, "%s/ca.pem", bdir);
    if (stat(path, &sb) == 0 && sb.st_size ? !SSL_CTX_load_verify_locations(ctx, path, NULL)
                                           : !SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "no CA to trust (%s)\n", path);
        return 2;
    }
    X509_VERIFY_PARAM *vp = SSL_CTX_get0_param(ctx);
    if (!(inet_pton(AF_INET, name, &tmp) == 1 ? X509_VERIFY_PARAM_set1_ip_asc(vp, name)
                                              : X509_VERIFY_PARAM_set1_host(vp, name, 0))) return 2;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (getenv("SUITES") && !SSL_CTX_set_ciphersuites(ctx, getenv("SUITES"))) return 2;
    // KEX: the groups to offer; a key share goes with the first, so "P-256:X25519" makes
    // the server ask for another ClientHello (HelloRetryRequest)
    if (getenv("KEX") && !SSL_CTX_set1_groups_list(ctx, getenv("KEX"))) return 2;
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    C = calloc(N, sizeof(conn));
    ep = epoll_create1(0);

    double t0 = mono();
    int next = 0, mark = getenv("NOMARK") ? 1 << 30 : 64;
    while (next < N || inflight) {
        while (inflight < INFLIGHT && next < N) start(next++);
        pump();
        if (opened >= mark && !inflight) {
            verify();
            printf("  [%s] %6d open, %7.1fs: %d served, handshake errors %d, fetch errors %d\n", id, opened,
                   mono() - t0, served, hs_err, get_err);
            fflush(stdout);
            while (mark <= opened) mark *= 2;
        }
    }
    double opened_at = mono() - t0;
    if (dir) barrier(dir, "opened", id, workers);
    int before = opened;
    verify();
    if (dir) barrier(dir, "verified", id, workers);
    struct rusage u;
    getrusage(RUSAGE_SELF, &u);
    printf("RESULT worker %s attempted %d open %d served %d hs_err %d get_err %d died_idle %d open_s %.1f rss_kib %ld\n",
           id, N, before, served, hs_err, get_err, closed_err, opened_at, u.ru_maxrss);
    fflush(stdout);
    _exit(0);
}
