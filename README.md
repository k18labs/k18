# k18
# k18

k18 turns a folder of static files into an x86-64 operating system that serves them
over HTTPS: 15 KB of system with the files behind it, in one image. It has its own boot
sector, long mode, a virtio-net driver, ARP, TCP, TLS 1.3 and as much of HTTP as a
static site needs, all in assembly.

```bash
./k18 pack site/ -n example.org                   # -> build-example.org/os.bin and disk.img
./k18 run build-example.org                       # try it in QEMU: https://127.0.0.1:8443/
```

To put it on a server (`--rescue` is how your host starts its rescue system; this is
Hetzner's, Linode's is in `docs/server.md`; add `--first` the first time):

```bash
./k18 publish site/ 203.0.113.7 -n example.org --san www.example.org --hsts 31536000 \
  --rescue 'hcloud server enable-rescue --ssh-key KEY NAME && hcloud server reset NAME'
```

This gets a certificate from Let's Encrypt if the server has none or it is about to
expire, packs the site, writes the image over the server's disk and boots it. The image
is not tied to the server (it gets its address by DHCP), and nothing is kept on your
machine: the key is made where `k18` runs and is stored only on the server's disk.
`ci/publish.yml` is an optional workflow template for a separate repository that holds
the site; it is not enabled here. This repository's `.github/workflows/ci.yml` builds and
tests k18 on pushes and pull requests.
[docs/server.md](docs/server.md) covers hosts.

## What you get

- **Small.** The system is 15,413 bytes (14,899 with a fixed address, 16,069 with
  IPv6). The image is that plus your files, each stored as the response it is sent as,
  with gzip and brotli versions where they are smaller.
- **Nothing to break into.** No kernel, shell, file system, user accounts, login or
  outgoing connections. The only parsers are for a TLS record and a request line. Only
  code is executable: no executable page holds a constant, the key, a certificate or
  your files, and nothing writable (packets, stack) can be executed. A test checks the
  page tables. There are no fault handlers: a fault resets the machine.
- **Secure TLS.** TLS 1.3 only, X25519, ECDSA P-256, AES-128-GCM. A fresh key and nonce
  for every handshake, forward secrecy for every connection. The curve arithmetic and
  ciphers do not branch on or index with secrets, checked with Valgrind with every
  secret marked undefined. The crypto passes Project Wycheproof's vectors, and the
  image passes tlsfuzzer (1,300 conversations). Randomness comes from a per-processor
  AES-128 CTR_DRBG seeded and periodically reseeded with `rdrand`; repeated hardware
  output traps, and a source that stops succeeding cannot produce output from a reseed.
  Port 80 only redirects.
- **Cheap connections.** A TLS connection costs 128 bytes, however large the file: sent
  data is never stored, it is rebuilt from the image if lost. A SYN from an address that
  does not answer costs nothing, and a client that vanishes mid-file is dropped after a
  minute or two.
- **Fast.** On a Hetzner cx23 (2 shared vCPUs): 10,000 to 11,100 new TLS 1.3
  connections a second with a full handshake, more than twice nginx with BoringSSL;
  105,000 to 125,000 small pages a second on kept connections, against nginx's 34,000;
  large files at 1.2 GB/s, a quarter more than nginx. Without SACK, a large window
  recovers losses slowly over long distances. [bench/README.md](bench/README.md) has
  the details.
- **Reproducible.** An image without its key is the same bytes for whoever builds it.
  Every build writes what it is to `OUT/made`, and `tools/repro.sh` rebuilds the system
  from the source, that file and the certificates to compare.
- **Clunky on purpose.** Content and certificate are part of the image: a change means
  a new image, written from the host's rescue system, with a minute or two of downtime.
  Nothing renews itself: run `./k18 publish --if-due` daily; it does nothing until the
  certificate has a month left. One site per server, one IPv4 address from DHCP (plus
  IPv6 if given one: `-6`), GET and HEAD only, requests up to 4 KB, no ranges, TLS 1.3
  clients only. Only two request headers are read: Accept-Encoding and If-None-Match.

It needs a 64-bit processor with rdrand, AES-NI, PCLMULQDQ, SSE4.1, BMI2 and ADX (Intel
since Broadwell, AMD since Zen), BIOS, UEFI (without Secure Boot) or GRUB, and a
virtio-net card: a cloud server, or QEMU.

It is a work in progress. `CLAUDE.md` has the rules and current state; `docs/` has the
internals, commands, server setup and pitfalls.

## Development

```bash
make                 # -> build/os.bin and build/disk.img with the site in www/ (first build makes cert/)
./measure.sh         # boot in QEMU, fetch with curl (certificate verified), run the hostile client
make test            # crypto against pyca/cryptography and the model in tools/ec.py
tools/outside.sh fetch   # fetch Wycheproof, Valgrind and tlsfuzzer into ext/
make outside         # crypto against Wycheproof and RFC 6979 vectors
make ct              # crypto under Valgrind: no branch or address depends on a secret
unshare -Urn tools/tlsfuzz.sh   # tlsfuzzer against the image
tools/suite.sh       # all 87 regression runs: loss, reordering, scale, browsers, an 80-file site
tools/sitetest.sh    # that site alone: every path, every kind of client
unshare -Urn ./tap.sh ./taprunc.sh 2000 1024 4   # 8,000 connections from 4 source IPs
gcc -O2 -o build/rawc tools/rawc.c
unshare -Urn ./tap.sh build/rawc 1000000         # a million plain connections, raw packets
gcc -O2 -o build/bench tools/bench.c -lssl -lcrypto   # the benchmark client
```

By hand:

```bash
qemu-system-x86_64 -machine q35 -accel kvm -cpu host -smp 2 -m 256 -nodefaults -display none \
  -drive file=build/disk.img,format=raw,if=none,id=d0 \
  -device virtio-scsi-pci -device scsi-hd,drive=d0 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:8443-:443,hostfwd=tcp:127.0.0.1:8080-:80 -device virtio-net-pci,netdev=n0
curl --cacert build/ca.pem https://127.0.0.1:8443/
curl http://127.0.0.1:8080/
```

`build*/` and `cert*/` hold the server's private key and are not in git.
