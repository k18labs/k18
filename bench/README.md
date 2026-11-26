# k18 next to nginx and Caddy

What k18 does on a 2-vCPU cloud server, and what nginx (with BoringSSL and with OpenSSL)
and Caddy do on the same server type with the same page, key and certificate.

| on a 2-vCPU cloud server | k18 | nginx + BoringSSL | nginx + OpenSSL 3.5 | Caddy 2.6 |
|---|---|---|---|---|
| new TLS 1.3 connections a second (full handshake) | 10,000 - 11,100 (1) | 3,900 - 4,100 | 2,100 - 2,200 | 1,700 - 1,850 |
| HTTPS requests a second, connections kept | 109,000 - 122,000 (2) | 47,000 - 48,000 | 37,000 - 40,000 | 9,000 - 12,000 |
| new plain HTTP connections a second | 30,000 - 35,000 (2) | 17,000 - 22,000 | 16,000 - 22,000 | 7,000 - 8,000 |
| HTTP requests a second, connections kept | 110,000 - 128,000 (2) | 60,000 - 71,000 | 58,000 - 68,000 | 14,000 |
| memory per held connection: plain, TLS | 24 bytes, 128 bytes | 3.2 KiB, 7.1 KiB | 4.0 KiB, 25.8 KiB | not measured |
| what has to be on the disk | 11,094 bytes (3) | 3.6 MB + a kernel (17 MB) | 9.1 MB + a kernel | 39 MB + a kernel |

(1) At 512 to 4,096 connections in flight; 8,750 to 9,890 at 64. Measured on a later
night than the nginx and Caddy columns, on the same server type (a Skylake cx23).

(2) Not k18's limit: the server's network path carries about 130,000 frames a second each
way, and k18's processors are 80 to 89% idle at that point ("What limits whom"). The
other columns, and k18's new TLS connections, are limited by the processors.

(3) The image measured in the comparison: system and one page. The current system size
is in the top-level README.

## The machines
- Server: Hetzner cx23 in Nuremberg: 2 shared vCPUs (Xeon Skylake, 2.1 GHz), 4 GB, one
  virtio-net queue. For k18 it boots the image (GRUB, multiboot); for the others it runs
  Ubuntu 26.04 (kernel 7.0.0-30).
- Load generator: a ccx33 in the same location (8 dedicated vCPUs, Ubuntu 26.04), 0.4 ms
  away (ping: 0.41 ms best, 0.8 average).
- Shared vCPUs: the same row measured twice differs by 10%, sometimes 15%, and drifts
  over half an hour. Compare two images on one server, in turn, in both orders.
- A cx23 is not always a Skylake: some are AMD EPYC (Rome, Milan), with different numbers.
  The numbers here are from Skylakes.

## The client: `tools/bench.c`
8 processes, each with W connections in flight. Each connection does a full TLS 1.3
handshake (X25519, TLS_AES_128_GCM_SHA256, no resumption), fetches the page, is closed
with a reset and opened again. With `KA=1000000` it stays open and fetches repeatedly.
The certificate is not verified (that is client time; `tools/tapc.c`, which holds
connections, verifies chain and name on every one). It reports connections or requests a
second and the time from `connect()` to the last byte of the response (on a kept
connection, from the request). A timeout is a connection that took over 10 s.

Its ClientHello is small (one key share, 250 bytes). Browsers and OpenSSL 3.5 send two
key shares, a post-quantum one first: 1.5 KB in two segments. One row asks that way
(`KEX='*X25519MLKEM768:*X25519'`).

`bench/run.sh IP` runs the eleven rows below: 15 s each after a second of warm-up.

## The servers
All serve `www/index.html` (27 bytes) with the certificate and key of `cert-hz/` (ECDSA
P-256, the generated leaf and CA), TLS 1.3 only, X25519, no session tickets or cache, on
ports 443 and 80, no logging.
- k18: built without `DEBUG`, `KNOCK` and `LIFE`.
- nginx 1.28.3 with OpenSSL 3.5.5, Ubuntu's package (`nginx-light`), with
  `bench/nginx.conf`: a worker per processor, `reuseport`, a backlog of 65,535; and
  `bench/setup-nginx.sh` for the kernel (queue and file limits raised, receive packet
  steering on, so both processors take packets from the one queue as under k18).
- nginx 1.28.3 built from nginx.org's source against BoringSSL (commit of 2026-11-11,
  `-DCMAKE_BUILD_TYPE=Release`; `bench/build-nginx-boring.sh`), same configuration.
- Caddy 2.6.2 (Ubuntu's package, not a recent Caddy; Go's crypto/tls) with
  `bench/Caddyfile`.

## Results
Connections or requests a second; in brackets the median and 99th percentile in ms.
"In flight" is how many connections the client keeps open at once (8 x W).

| | in flight | k18 | nginx + BoringSSL | nginx + OpenSSL | Caddy |
|---|---|---|---|---|---|
| HTTPS, a new connection each | 64 | 8,750 - 9,890 (1) | 3,884 (15.0, 42.2) | 2,229 (26.5, 70.6) | 1,836 (34.1, 66.4) |
| | 512 | 10,010 - 11,130 (1) | 3,887 (102, 347) | 2,086 (208, 571) | 1,846 (266, 508) |
| | 4,096 | 10,330 - 11,230 (1) | 4,114 (850, over 2,000) | 2,199 (1,811, over 2,000) | 1,743 (over 2,000) |
| the same, two key shares as a browser sends | 512 | 9,101 (52.7, 133) (2) | 3,817 (132, 337) | 2,477 (205, 460) | |
| HTTPS, connections kept | 64 | 109,360 (0.55, 1.24) | 46,906 (1.27, 3.11) | 39,572 (1.54, 3.48) | 12,336 (4.36, 17.3) |
| | 512 | 122,357 (4.02, 6.43) | 48,247 (10.3, 18.4) | 36,842 (13.7, 21.3) | 8,800 (53.8, 145) |
| HTTP, a new connection each | 64 | 29,938 (1.94, 4.93) | 17,487 (3.16, 9.88) | 15,550 (3.47, 11.6) | 6,808 (9.09, 20.9) |
| | 512 | 35,428 (13.8, 19.7) | 22,281 (18.1, 61.5) | 21,148 (19.6, 65.6) | 7,283 (70.5, 129) |
| | 4,096 | 34,455 (62.7, 1,110) | 21,706 (102, 1,323) | 21,940 (48.1, 1,320) | 7,780 (529, 1,441) |
| HTTP, connections kept | 64 | 110,280 (0.55, 1.22) | 59,815 (1.01, 2.67) | 58,370 (1.02, 2.57) | 14,084 (3.81, 15.3) |
| | 512 | 128,404 (3.86, 5.38) | 70,560 (6.64, 16.0) | 67,621 (7.09, 16.6) | 14,427 (34.3, 69.9) |

(1) Lowest to highest of six runs, on a later night, same server type; latencies not
recorded. (2) Measured before the curve code was made faster; not measured since.

No errors. No timeouts, except k18 in the 4,096 row of plain HTTP: 83 of 517,000
connections ("More in flight than can be served"). The HTTP rows of the two nginx
columns are the same nginx doing the same work without TLS: they show how much a row
moves between runs.

Per new TLS connection, of both processors' time: k18 about 400,000 cycles, nginx with
BoringSSL 1.0 million, with OpenSSL 1.9 million, Caddy 2.3 million.

k18's curve arithmetic is somewhat faster than OpenSSL's, but most of the gain is
elsewhere: there is no kernel and no socket layer, and a connection is 128 bytes. On the
development machine (Ryzen 7 3800X, Zen 2; `make bench`, the operations in turn as a
handshake does them):

| | k18 | OpenSSL 3.5.5 (EVP) |
|---|---|---|
| X25519: our key share and the shared secret | 143,000 cycles | 136,000 + 118,000 |
| ECDSA P-256 signature | 65,000 | 75,000 |
| all a handshake needs | 205,000 | 329,000 |

A step of k18's X25519 ladder is 370 cycles, OpenSSL's about 410 (118,000 less an
inversion, divided by 255). On the server, `openssl speed` gives 77,000 cycles for a
signature and 120,000 for an X25519 multiplication.

`rdrand` cost depends on the processor: 3,530 cycles for 64 bits on Zen 2, 288 on the
Skylake server, 41 on an EPYC-Milan. A handshake draws twelve: 42,000 cycles on Zen 2
(a fifth of the curve work), negligible elsewhere.

### What limits whom
- nginx and Caddy: their processors (`vmstat` on the server: 0 to 6% idle in every row).
- k18, new TLS connections: its processors (2 to 5% idle; a `DEBUG=2` image and
  `bench/busy.sh`).
- k18, everything else: the network path. With connections kept it levels off at about
  130,000 requests a second, with new plain connections at 35,000 (140,000 frames a
  second in), and its processors are 80 to 89% idle. Two load generators at once get the
  same total (59,900 + 64,700 requests a second). k18 on one processor gets the same
  (133,000 HTTP requests a second at 15% busy, 126,000 HTTPS at 28%: 2,400 and 4,800
  cycles a request, driver included). The load generator is not the limit either (its
  processes 80% idle, its receive queue's processor half idle). The limit is on the
  host's side and cannot be seen from inside the guest.
- So the rows marked (2) in the first table understate k18: on a path that carried more,
  k18 would do several times as much, and the others would not.

### More in flight than can be served
4,096 connections in flight is more than any of the four can serve in under half a
second.
- k18 lets frames wait in its rings (16,384 frames per processor). New TLS connections at
  4,096 in flight: over six runs the median was 0.33 to 0.53 s and the 99th percentile
  0.8 to 1.6 s; none took over 10 s, and an image that counts found no frame lost. At
  16,384 in flight the rings overflow: 245 of 100,000 over 10 s, median 1.6 s.
- nginx lets them wait in the kernel's queues: median 0.85 s (BoringSSL) and 1.8 s
  (OpenSSL), none over 10 s.
- On port 80 at 4,096 in flight, 1% of connections take a second longer with every
  server: a SYN is lost on the way (the client's `nstat`, TcpExtTCPSynRetrans). k18 asks
  more of the path than it carries and nginx does not get that far, so k18 has the
  connections that lose their SYN four times in a row and take over 10 s (0.02% in the
  worst run), and nginx has none. k18's own rings lost no frame there. Where on the path
  they are lost was not found.

## Files
The site of `tools/mksite.py`, packed as `./k18 pack build-hzn/www -n IP -i IP -c cert-hz
--plain80`. `bench/files.sh`: wrk, 8 s a row, 64 connections that stay unless noted. nginx
1.28.3 with OpenSSL 3.5.5 and `bench/nginx.conf`, same files and certificate, was
measured on an earlier night than k18, on the same server type.

wrk's OpenSSL lists AES-256-GCM first, then ChaCha20-Poly1305, then AES-128-GCM. nginx
takes the first. k18 has only AES-128-GCM and takes it whatever the order; a client that
offers only ChaCha20-Poly1305 gets "handshake failure". Browsers list AES-128-GCM first.

| | k18 | nginx + OpenSSL |
|---|---|---|
| the page (167 bytes), requests a second, 64 and 512 connections | 97,656 and 113,813 | 33,880 and 34,142 |
| the page to a client that has it (304) | 111,756 | |
| 14,000 bytes, wrk's order | | 26,654, 362 MB/s (AES-256-GCM) |
| 14,000 bytes, AES-128-GCM | 36,254 - 36,888 a second | 23,851, 324 MB/s |
| 1.5 MiB, wrk's order | 1.27 GB/s | 611 a second, 0.90 GB/s (AES-256-GCM) |
| 1.5 MiB, AES-128-GCM | 1.24 - 1.30 GB/s | 667 a second, 0.98 GB/s |
| the same, 8 connections | 0.89 - 1.01 GB/s | 689 a second, 1.01 GB/s |
| the same, 1 connection | 141 - 244 MB/s | 261 a second, 392 MB/s |
| 200 KB of text, uncompressed | 6,099 a second, 1.16 GB/s | |
| the same to a client that takes brotli (99 KB) | 12,025 a second | |

No request failed or took over 2 s. So small files and pages go three times as fast as
from nginx, and 14 KB files a third to a half faster. Large files go a quarter to a
third faster at 64 connections and about as fast at 8; over one connection nginx is 1.6
to 2.8 times as fast.

The large rows are from a later night (another Skylake cx23), with segments that stay
inside the client's window. Before that, the last record of a burst that the window
limited reached past its edge, a Linux client with data unread dropped it, and that was
a loss. The image before and the image after on that server in turn: 64 connections
1.12 - 1.31 GB/s before and 1.24 - 1.30 after, 8 connections 0.77 - 0.98 and 0.89 -
1.01, one connection 128 - 246 MB/s and 141 - 244; new TLS connections (12,200 and
12,400 a second at 512 in flight) and kept requests the same. One connection goes by
whether it has lost anything yet: one that has stays at 64 KB for good ("Over a
distance"), which over 0.5 ms is 130 to 150 MB/s; one that has not goes at 190 to 245.

How it is done:
- **The card cuts the frames** (virtio's CSUM and HOST_TSO4, where offered). A frame of
  ours holds up to 45 records of a response, sealed into a 64 KiB buffer; the card cuts
  and checksums each into a segment. A lost segment is still one record, rebuilt from
  the image. Without TSO a segment is a frame, and the path's 130,000 frames a second
  cap a large file at about 166 MB/s.
- **Sealing is four blocks at a time**: AES-128-GCM four blocks abreast and GHASH four at
  a time. A full record (1,418 bytes) takes 1,780 cycles on the development machine
  (`make bench`). How busy the processors are at 1.2 GB/s was not measured.
- **Windows are scaled**, so more than 64 KB can be in flight ("Over a distance").
- Files that get shorter are **also packed compressed** (gzip, brotli), and a client that
  has a file is told so (ETag, 304).

### Where a jump lies
The server's processor (Skylake) decodes a jump again every time it meets it if the jump
crosses or ends on a 32-byte boundary (a microcode fix for an erratum; everything sharing
those 32 bytes is decoded again too). With the SHA-256 round loop, the curve code's
dispatch and the field addition placed that way, new TLS connections were 6% slower on
Skylake; on Zen 2 there was no difference. So the routines a handshake spends its time
in each begin where none of their jumps lies on a boundary (`HOT` in src/os.asm,
`tools/jcc.py`). They need not begin on a 32-byte boundary: it is enough that each
begins at one of the offsets where its jumps are clear (most routines have ten or twenty
such offsets in 32), and `HOT` pads to that. Images placed this way make as many
connections as each other, within the spread of a row.

### Over a distance
Windows are scaled, but SACK is not built, and without it losses are found one segment a
round trip. A window that doubled every round trip up to 367 KB lost 91 segments at once
on a path that held less, and took 23.6 s for 6 MiB. So:
- the window doubles up to 64 KB, then grows by a segment for every 64 KiB acknowledged;
- a response begins with 64 KB at most;
- a connection that has lost anything once stays at 64 KB;
- several losses in one window are repaired one round trip each, not one timer each.

6 MiB through emulated paths (`tools/bneck.sh`; an image without TSO, so a frame is a
segment):

| the path | time |
|---|---|
| 20 Mbit/s, a queue of 60 packets, 50 ms round trip | 4.3 s |
| no limit, 100 ms | 5.5 s |
| 100 Mbit/s, a queue of 100, 20 ms | 1.2 s |
| 50 Mbit/s, a queue of 50, 10 ms | 1.15 s |
| 5 Mbit/s, a queue of 30, 100 ms | 12.4 s |
| 20 Mbit/s, a queue of 200, 1% lost | 14 to 19 s |
| 20 Mbit/s, a queue of 10, 50 ms | 34 s |

1.5 MiB with a new connection, over a round trip of 20 ms and of 100 ms (`DELAY=n` in
front of tap.sh): 0.37 s and 1.8 s. The last row is what it does badly: a queue of ten
packets and a sender that does not pace.

## Held connections
`tools/tapc.c` from the load generator (`bench/hold.sh`; 60,000 from one address is what
the ports allow):
- k18: 60,000 TLS connections opened (256 at a time, 28 s: the client's speed), chain and
  name verified on each, all held, then the page fetched over each. Thirty such runs,
  each after a burst of new connections: 1.8 million connections, all opened, verified
  and served except one the client could not start (its port was taken). The same with
  60,000 plain connections. Also with the image that serves files: 60,000 of each.
- A held connection costs k18 24 bytes on port 80 and 128 bytes on 443, by construction:
  on this server room for 143 million and 3.8 million.
- nginx: the same 60,000, measured as what the server's `MemAvailable` loses while they
  are held: 4.0 KiB a plain connection; 25.8 KiB a TLS connection with OpenSSL (22 KiB of
  it in the workers), 7.1 KiB with BoringSSL. In the 3 GiB free under Linux that is room
  for roughly 120,000 TLS connections with OpenSSL and 440,000 with BoringSSL (not tried).

## Size
- k18: the image measured was 11,094 bytes, all of it: boot code, driver, TCP, TLS, the
  two curves, the page.
- nginx + OpenSSL: nginx 1.6 MB, libssl 1.1 MB, libcrypto 6.4 MB; under them the kernel
  (vmlinuz, compressed: 17.3 MB) and the rest of a Linux system.
- nginx + BoringSSL: one binary of 3.6 MB (stripped), and the kernel.
- Caddy: 39.2 MB, and the kernel.

By the project's measure, TLS connections that can be held per KiB on disk (kernel
included, the rest of the system not): k18 about 350,000 (3.8 million slots, 10.8 KiB);
nginx + BoringSSL about 20; nginx + OpenSSL about 5.

## What this does not say
- nginx and Caddy are web servers: any file, any header, virtual hosts, HTTP/2, logs,
  reloads, every cipher and curve a client may want, session resumption. k18 serves GET
  and HEAD of the files packed into it, to clients that speak TLS 1.3 with an X25519
  share. In the `run.sh` rows of the comparison its response was 59 bytes (a status line
  and one header), nginx's 256 (a status line and eight). The image that serves files
  sends six headers (179 bytes for the 167-byte page).
- No resumption was measured, because k18 has none: every connection here is a full
  handshake. A server with session tickets handles a returning client for less; how
  nginx then compares with k18's full handshake was not measured.
- One server type, one location, shared vCPUs. Not measured: other instance types,
  dedicated cores, more than two processors on a real machine, anything over a real
  distance.
- The rate client asks for the cheapest thing a TLS server can be asked for (AES-128-GCM,
  a 27-byte page) and does not verify certificates. A different mix moves all four.
- Unikraft and F-Stack were not measured. Unikraft needs its own hypervisor (these cloud
  servers offer no nested virtualisation; on the development machine it could run next
  to k18 under QEMU, not set up yet). F-Stack needs DPDK to take the network card from
  Linux, which on a server with one card takes ssh away too.
- BoringSSL was measured inside nginx only, not by itself.

## Doing it again
1. A load generator next to the server (docs/server.md). On it:
   `apt-get install -y gcc libssl-dev`, a directory with `tools/bench.c`, `tools/tapc.c`,
   `www/`, `bench/run.sh`, `bench/busy.sh`, `bench/hold.sh`, and in `build/` the server's
   `ca.pem` and `name` (from `build-hz/`); `gcc -O2 -o build/bench tools/bench.c -lssl
   -lcrypto` (tapc the same).
2. k18: build, `tools/deploy.sh`, then on the generator `./run.sh IP`.
   `hcloud server reset NAME` brings Linux back. (A server that keeps its Linux:
   docs/server.md, "Beside a Linux".)
3. nginx: copy `bench/nginx.conf`, `www/index.html` and `cert-hz/server.pem` and
   `server.key` to `/root/k18bench/` on the server, `ssh root@server 'bash -s' <
   bench/setup-nginx.sh`, then `./run.sh IP`. With BoringSSL: `bench/build-nginx-boring.sh`
   on the generator, the binary to the server, started as that script's first lines say.
   Caddy: its package, `bench/Caddyfile`.
4. Held connections: `./hold.sh tls 60000 IP` on the generator, and when it says "all
   open", `touch /tmp/bar/go` (before that, read the server's `/proc/meminfo`).
5. How busy k18 is: an image with `DEBUG=2`, then `./busy.sh IP PLAIN=1 DST=IP:80 P=8 W=64
   KA=1000000` and the like.
6. Afterwards: the server's key is on its disk in `/root/k18bench` and `/etc/nginx/k18bench`
   (remove both, and the packages), and the generator costs by the hour (`hcloud server
   delete`).
7. Two images of k18 in turn: `./k18 deploy IP DIR --grub --reset 'hcloud server reset NAME'` for
   each, and the rows that matter in between (for example the first two of run.sh, twice,
   12 s each). Files: `./files.sh IP [all]` on the generator (`apt-get install wrk`;
   `bench/files.sh` beside run.sh); for nginx the site's folder goes to
   `/var/www/k18bench`.
