# Commands

Every command, script and make variable. When to run which: CLAUDE.md, "Workflow".

## The `k18` tool

Full usage is in the comment at the top of `./k18`; what happens on the machine is in
docs/server.md. Everything it makes is readable by its owner only (umask 077).

- `./k18 pack FOLDER [-n NAME] [--san NAME]... [-i IP] [-6 IP6] [-c CERTDIR] [-o OUT]
  [--plain80] [--hsts SECONDS] [--cache SECONDS] [--header 'Name: value']
  [--no-compress]` makes OUT/os.bin and OUT/disk.img, and saves its options in
  OUT/pack.conf. Without `-i` the image uses DHCP. Port 80 redirects to https://NAME/
  unless `--plain80`. The server ignores the requested name, so every name in the
  certificate (`--san`) gets the site; pack warns about names CERTDIR's certificate
  does not cover.
- `./k18 run [OUT] [-p PORT]` boots the image in QEMU (https://127.0.0.1:8443/,
  http://127.0.0.1:9443/).
- `./k18 publish SITE HOST -n NAME [pack's options] [--rescue 'COMMAND'] [--boot
  'COMMAND'] [--disk DEVICE] [--first] [--if-due] [--days N] [--email ADDRESS]
  [--staging]`: the machine boots its rescue system, proves it holds the key of the
  certificate the site was serving, and hands over the key and certificate stored at
  the end of its disk. If there are none, or the certificate expires within N days
  (30), lacks a name or is untrusted, a new pair comes from Let's Encrypt. SITE is then
  packed, written over the disk and booted. Nothing is kept locally. `--if-due` does
  nothing while the site is up with a certificate valid for more than N days (for
  `ci/publish.yml`). `--first`: the machine has nothing to prove itself with yet.
- `./k18 deploy HOST [OUT] [--rescue 'COMMAND'] [--boot 'COMMAND'] [--disk DEVICE]
  [--first]`: the same last steps for an image packed locally. The machine must hold
  the key that goes with OUT.
- `./k18 deploy HOST [OUT] --grub [--persist] [--reset 'COMMAND']`: installs OUT/os.bin
  beside the server's Linux, booted by GRUB (docs/server.md, "Beside a Linux").
- `./k18 renew HOST [OUT] [--rescue 'COMMAND' ... | --grub --reset 'COMMAND'] [--days
  N] [--force] [--dry-run] [--email ADDRESS] [--staging]`: when OUT's certificate
  expires within N days (30), makes a new key and request locally, has certbot answer
  the challenge on port 80 of the rescue system (or the server's Linux), repacks OUT
  from OUT/pack.conf and boots it; if no certificate comes, the old image is booted
  again. Otherwise it does nothing, so cron can run it daily. `--force`: renew anyway
  (the private CA's certificate lasts until 2049). `--staging`: Let's Encrypt's test
  server; the final check then fetches without verifying.

## Building

- `make` assembles `src/os.asm` into `build/os.bin` and `build/disk.img` with the site
  of `www/`. The disk (`tools/mkdisk.py`) has the `src/boot.asm` boot sector and a
  partition with the image and the `src/efi.asm` application, so BIOS and UEFI both
  boot it. It assembles twice: first to find where the code ends (`build/os.sizing`),
  then loaded `DELTA` bytes above 1 MiB so the code ends on a page boundary
  (`build/delta`, passed as `-DDELTA=n`; docs/internals.md, "Memory"). `nasm` by hand
  needs that define.
- `make B=dir CERT=dir NAME=n IP=a.b.c.d IP6=addr SITE=folder P80=redirect
  HSTS=seconds CACHE=seconds HEADERS='Name: value' COMPRESS=0` builds another image:
  `B` output directory (scripts read it from the environment too), `CERT` certificate
  directory, `NAME` the name in a generated certificate (`SAN='a b'` adds names), `IP`
  a fixed address, `IP6` an IPv6 address, `SITE` the folder, `P80` what port 80 does,
  `HSTS`/`CACHE`/`HEADERS` headers on every file, `COMPRESS=0` no compressed copies.
  The last five reach the packer through the environment so quotes survive; a `$` in
  `HEADERS=` is still expanded by make. Only address, names, site and its settings are
  dependencies: after changing anything else, `make -B`.

## Size

`python3 tools/sizes.py build/os.lst` prints bytes per routine. The system is 14,899
bytes with a fixed address, 15,413 with DHCP (+496 code) and 16,069 with IPv6 (+660):

| Part (of 14,899) | Bytes |
|---|---|
| boot, clock calibration, page tables, driver, other processors | 2,710 |
| network, with the timers | 4,310 |
| requests and the forms of a file | 740 |
| TLS handshake and key schedule | 1,650 |
| SHA-256 | 440 |
| curves, with their programs and constants | 3,830 |
| cipher | 1,000 |
| certificate | 230 |

This includes the `HOT` padding (docs/internals.md): 74 bytes with a fixed address, 92
with DHCP, 88 with IPv6.

What features cost: segments that stay inside the client's window, and a client that
reads again served at once 54 (of them the segment size by a SYN's window 11, an ack
that repeats from further on 11); checking whose segment a segment is 26; zeroing
what loaders left in executable memory 7; our ChangeCipherSpec 10; the 400 without Host 38; audit items
4-7, 11 and 13 together 55; the inversion's addition chain 97; faster field add,
subtract, squaring and one-limb multiply 352; the ladder's swap in 16-byte registers
32; the ladder step as calls 347; one-limb-product Montgomery rounds for P-256 50; a
table lookup in registers 0; making only code executable 0.

## Reproducible builds

- Every build writes `OUT/made`: commit, assembler, defines, site.inc's numbers, the
  chain's hash, how the site was packed, and hashes of the image without its key
  (system, site, both). No secret. `./k18 pack` prints the hashes.
- `make KEYLESS=1` (or `KEYLESS=1 ./k18 pack ... -c DIR`, DIR holding only server.pem)
  makes the image without the key: it differs only in the key's 32 bytes.
- `tools/repro.sh system MADE CHAIN.pem` rebuilds the system part of someone's image
  from this checkout, their `made` and the chain their server shows (`openssl s_client
  -showcerts`), and says whether it matches. It needs the assembler `made` names (NASM
  3.01).
- `tools/repro.sh` alone (seconds; suite's `repro`): two builds under different folder,
  umask, time zone, locale and file order are identical; the keyless one differs in 32
  bytes only; the system part rebuilt from `made` matches.

## Packing

`tools/pack.py FOLDER OUT` (run by `make`) stores each file as its full response,
found through a hash table of paths.

- A folder's `index.html` is served at the folder's name with a slash; without it,
  a redirect. `404.html` serves unknown paths. Dot names are left out, except
  `.well-known`.
- A file's other forms follow it: its 304 (the ETag is 16 hex digits of a hash of the
  whole response), gzip and brotli, each with its own ETag and 304. A compressed form
  is kept if it saves a record and a tenth of the length. Brotli comes from the Python
  module, libbrotlienc or the command; without any, gzip only. `Vary: Accept-Encoding`
  is on every file with more than one form.
- The 404 has every header but Cache-Control. A folder's redirect, the 405 and the 400
  have HSTS; port 80 has none.
- OUT/site.json lists what each path must return (for the tests); OUT/page80.bin is
  port 80's response.

## Test suite

`tools/suite.sh [JOBS] [name...]` runs everything below (87 runs, twenty minutes; logs
in `$LOGS`, named on its last line). `SMP=1` or `SMP=4` in front for other than 2
processors. One failed connection is a FAIL. On a loaded host `raw1m_20k` can time out
a few hundred of a million connections: rerun it alone before believing it.

## Running images

- `EFI=1` in front of anything that starts QEMU boots by UEFI (OVMF from
  `/usr/share/ovmf/OVMF.fd` or `OVMF`). The suite's `measure_efi` and `site_efi` do
  this.
- KVM is used when /dev/kvm exists; `KVM=0` emulates (read when `tools/vm.sh` is
  sourced).
- `unshare -Urn ./tap.sh COMMAND`: a tap interface in a throwaway user and network
  namespace. The guest is 10.0.2.15, from its image or `tools/dhcpd.py`, which tap.sh
  starts. `DHCPD='COMMAND'` another DHCP server; `DHCPD=none` none (`STATIC=1`: the
  image has a fixed address, wait for it). Also in front of tap.sh: `DELAY=20` ms to
  the guest; `REORDER=25` % of packets to the guest overtake the rest; `MON=path`
  QEMU's monitor on a unix socket (`info registers`, `xp /16xw ADDRESS`); `LOSS`,
  `MTU`, `SMP`, `MEM` as in the load test.
- `tools/pcap.py FILE CLIENT_IP [PORT]`: one connection from a capture, a line a packet.

## Basic checks

- `./measure.sh` (ten seconds) builds, boots and checks with curl: chain and name,
  new connections and keep-alive, AES-128-GCM, "handshake failure" for ChaCha20 or
  AES-256 only, a P-256 key share, port 80, an unknown path, HEAD, refusal without our
  CA. Then `tools/abuse.py`: forged, replayed and truncated records and bad
  ClientHellos are ignored; every ClientHello rule has its alert; other methods get
  405; a record without a content type closes; split and pipelined requests on port
  80. The guest's 443 is 127.0.0.1:`PORT` (8443), its 80 `HPORT` (PORT + 1000). It
  reads `NAME`, `SITE`, `P80`, `HSTS` like make.
- `./browsers.sh`: Firefox and Chrome with our CA trusted in throwaway profiles (no
  certificate error flags in Chrome's net-log), and Chrome refusing without it. Run
  after any TLS, certificate, TCP or HTTP change.

## Site test

`tools/sitetest.sh [quick]`, or `unshare -Urn tools/sitetest.sh tap [quick]` with
`LOSS=3`, `REORDER=25`, `MTU=600`, `SMP=n` in front. It builds an image with the site
of `tools/mksite.py` (80 files with sizes around every record boundary, names that
need escaping, a folder, one 1.5 MiB file) and `tools/sitecheck.py` checks every path
with many kinds of client: GET and HEAD, small segments, slow readers, compression in
every spelling of Accept-Encoding, every ETag form, unknown paths, other methods, no
Host, requests in pieces or over 4 KB, half-closes, clients that disappear.

- `NOTSO=1`: an image that never asks for TSO (tap uses TSO, QEMU's user network not).
- `SUITES=...`: the cipher suites clients offer. `ONLY=text`: only checks with that in
  their name. `BIG=n`: the large file is n MiB. `NOBUILD=1`: use the existing image.
- `GONE=1` (tap; suite's `site_gone`, three minutes): a client vanishes mid-file; the
  server's RST must appear 50 to 170 s later, and a client that only stopped reading
  must still get its file.
- `HOST=a.b.c.d PORT=443 B=build-hz python3 tools/sitecheck.py quick`: the same against a
  server.

## Test-only make variables

- `ISNTOP=n ISNBITS=b`: fix the top b bits (12) of every initial sequence number, so
  sequence numbers cross 2^31 or 2^32 (suite's `*isn*`, `site_wrap*`).
- `KEYLIFE=n`, `STLIFE=n`: a key seals 2^n records; a client may send 2^n
  (`site_keylife`).
- `WXTEST=n`: do one thing that must stop the machine (`tools/wxtest.sh`, suite's
  `wx`): 1-5 and 9-11 what the page tables forbid (writing code or site, executing the
  stack, the first and last `ret` byte in the site, a packet buffer, just past the
  code, what a loader left); 12 the processor start page is empty; 6 and 7 a fault on
  the first and another processor; 8 a repeating random generator. `WXOPEN=1` is the
  control. `WXPAD=1`: 64 more bytes of code, for an image that would sit at exactly
  1 MiB.
- `WIN=n`: initial congestion window (10). `NOTSO=1`: one segment per frame.
- `BIGSH=n`: 2^n TSO buffers per processor (3); 0 or 1 tests waiting for the device.
- `RACE=n`: stalls what two processors do to each other (`tools/racetest.sh`).
- `CAP=n`: at most n slots per connection table. `IDLE=n`: a connection quiet for more
  than n × 64 s may be replaced (64). `TSHARE=n`: the TLS table gets 1/2^n of memory.
- `DEBUG=n`, `DHMAX=n`: see Debugging.

## Network tests

- `unshare -Urn ./tap.sh ./taprunc.sh [PER] [BASE_PORT] [W]`: the load test.
  `tools/tapc.c` (epoll and OpenSSL, verifying chain and name) opens PER connections
  from each of W source addresses (10.0.2.32 up, W ≤ 32), all at once, and fetches over
  each at the end. In front of `unshare`: `LOSS=1` (% each way), `MTU=n`, `TIMEOUT=10`,
  `SUITES=...`, `NOMARK=1` (no intermediate fetches), `PLAIN=1 INFLIGHT=64` (port 80),
  `SMP=n`, `MEM=n` (default 2, 256 MiB), `KEX=P-256:X25519` (a HelloRetryRequest each).
- `unshare -Urn ./tap.sh build/rawc N [W]` (`gcc -O2 -o build/rawc tools/rawc.c`): the
  scale test. N plain connections from raw
  packets, W in flight (512; thousands overflow the guest's ring on purpose), each
  opened and fetched, then all again. `MEM=4096` in front for more memory. Prints
  resets and timeouts. Run twice in one VM, returning clients must be taken as new.
- `make B=build-small CAP=1024`, then `B=build-small unshare -Urn ./tap.sh python3
  tools/churn.py [HELD] [LOOPS]`: connections that end five ways free their slots.
  `FLOOD=n` in front: packets from nonexistent clients (`tools/flood.py`) take none.
  With `IDLE=0`, quiet connections may be replaced.
- `make B=build-small-idle1 CAP=1024 IDLE=1`, then `B=build-small-idle1 unshare -Urn
  ./tap.sh python3 tools/idletest.py` (three minutes; suite's `idle`): with port 80's
  table full, new connections replace quiet ones but not the 32 that kept talking.
- `unshare -Urn ./tap.sh python3 tools/acktest.py` (seconds; suite's `ack`): segments in
  a client's name that are not the client's, on ports 80 and 443: an MSS below 216, acks
  for data never sent, sequence numbers far away, returning ports, RSTs off by one. A
  real connection with 21 such segments sent into it must still work. Controls: without
  these rules 15 of the 29 checks fail.
- `unshare -Urn tools/dhcptest.sh` (a minute; suite's `dhcp`, `dhcp_smp4`): the DHCP
  client against `tools/dhcptest.py`: retries with new IDs, ignores answers that are not
  to its current question or malformed, takes only the offering server's yes for the
  offered address, renews at half the lease, handles a NAK, survives 13,000 damaged
  answers. `... dhcptest.sh real` (80 s; `dhcp_dnsmasq`): against dnsmasq. The suite's
  `static_*` runs use `IP=10.0.2.15` with no DHCP server.
- `unshare -Urn tools/racetest.sh 1` (and `2`, `3`; suite's `race*`): images built
  `RACE=n` in which two processors race for a slot; the loser must get nothing.
- `B=build-site6 unshare -Urn ./tap.sh python3 tools/v6test.py` (seconds; suite's `v6`):
  an image with `IP6=fd00:15::15`, frame by frame: neighbour discovery, SYNs for us and
  not for us, a file in 1,220-byte records, 3,000 malformed frames. `V6=1` in front of
  `taprunc.sh` and `tools/sitetest.sh tap` uses IPv6 (suite's `*6*` runs).
- `B=build-site DELAY=300 unshare -Urn ./tap.sh python3 tools/rtttest.py` (15 s; suite's
  `rtt`): over a 300 ms round trip without loss, nothing may be sent twice.
- `SMP=3 MON=/tmp/k18mon unshare -Urn ./tap.sh python3 tools/cputest.py` (suite's
  `cpus3`): exactly the processors that take no frames are halted.
- `tools/bneck.sh` (inside tap.sh, image built `NOTSO=1`): a bottleneck of `BRATE`
  Mbit/s, `BQUEUE` packets, `BDELAY` ms each way, `BLOSS` % loss; fetches a large file
  and reports time and drops. `CAP=file` captures; `tools/tl.py file` prints a
  timeline. `tools/bnecktest.sh` runs two paths with time limits (suite's `bneck`).
- `unshare -Urn tools/hosttest.sh` (two and a half minutes; suite's `host`): `./k18
  publish`, `deploy` and `renew` against a simulated machine (disk a file, rescue
  system this shell with its tools replaced, ssh a script, boot a QEMU). 28 checks.
  `V=1` shows the tool's output.

## Fuzzing and external test vectors

`tools/outside.sh fetch` downloads what these need into `ext/` (not in git).

- `make outside` (a second): Wycheproof's X25519, AES-128-GCM and HMAC-SHA256 vectors,
  RFC 6979's P-256 signatures, OpenSSL for edge-case nonces (`test/outside.py`).
- `make ct` (ten seconds): the host build under Valgrind with every secret undefined;
  six planted violations must be caught (`test/ct.c`).
- `unshare -Urn tools/tlsfuzz.sh [NAME...]` (three minutes): 30 tlsfuzzer TLS 1.3
  scripts, 1,300 conversations. The server must serve after each; a conversation may
  fail only where `tools/tlsfuzz.sh` names the shortcut that causes it. `tools/tlsfuzz.py
  SCRIPT -h HOST -p PORT` runs one.
- `unshare -Urn ./tap.sh python3 tools/hellofuzz.py [N] [SEED]` (a minute; suite's
  `hellofuzz`): 20,000 randomly damaged ClientHellos; a real client must connect after
  every 500.
- `unshare -Urn ./tap.sh python3 tools/rawtest.py [SEED]` (seconds; suite's
  `rawframes`): 3,200 frames malformed below TCP. The machine must survive.

## Crypto unit tests

- `make test`: the asm crypto (`-DHOST`, `test/test_asm.c`, `test/test_crypto.py`)
  against pyca/cryptography and against the model, then `tools/ec.py` itself.
- `make bench`: the same object timed natively, down to one multiplication and one
  record.

## Benchmarks

- `tools/bench.c` (`gcc -O2 -o build/bench tools/bench.c -lssl -lcrypto`): P processes
  with W connections each, for T seconds; each connects, handshakes, fetches `KA` times,
  is reset and made again. `DST=ip:port`, `PLAIN=1`, `KA=1000000` for kept connections,
  `SUITES`, `KEX` (`'*X25519MLKEM768:*X25519'` is a browser's ClientHello), `CA=file`
  to verify, `TIMEOUT` (10 s). Prints rates, errors, timeouts and latency percentiles.
- `bench/run.sh IP`, `bench/files.sh IP [all]`, `bench/busy.sh IP ENV...` (with a
  `DEBUG=2` image), `bench/hold.sh`: see bench/README.md.
- `tools/load.py` (through slirp, `PORT=`): `hold N`, `burst K`, `seq N`, `ka N`. Start a
  VM first: `source tools/vm.sh; boot` with `B`, `PORT` and `IMG=$B/os.bin` set.

## Debugging

- `make B=build-dbg DEBUG=1`: the end of port 80's page shows six 16-bit hex counters of
  the processor that answered: bad frames, cycles per frame, connections refused and
  frames lost, early segments, retransmissions, RSTs sent. The first two digits are
  processors taking frames minus 1, and which one answered. `DEBUG=2`: counters 4 and 6
  are idle loop turns (× 4,096) and time (× 2^24 cycles). `DEBUG=3`: DHCP requests sent
  and yeses accepted; `DHMAX=n` caps leases at n seconds. Not for images that are
  measured or kept running.
- `python3 tools/jcc.py build/os.lst [ROUTINE...]` lists jumps that cross or end on a
  32-byte boundary (make runs it for `HOT`'s routines). `... mask ROUTINE` gives the
  start addresses where a routine has none, as `HOT` takes them; `fit` also shows what
  would lie on a boundary; `ROUTINE:loops` counts only jumps in loops.
