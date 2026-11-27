# The server, the test machine, the certificate

## The test machine
`tools/vm.sh` and `tap.sh` boot a machine shaped like the server: `-machine q35`, 2
processors, a modern-only virtio-net (`disable-legacy=on`) behind a PCIe root port, the
disk on virtio SCSI, 256 MiB. `MEM=4096` in front of `tap.sh` gives the server's 4 GiB,
which also tests RAM and (as SeaBIOS then maps them) the card's registers above 4 GiB.
`tools/dhcpd.py` on the tap gives a one-hour lease. `EFI=1` boots with OVMF.

## The server (Hetzner cx23)
As seen from a Linux on it:
- "Hetzner vServer/Standard PC (Q35 + ICH9)", SeaBIOS, no UEFI.
- 2 vCPUs, 4 GB. "Intel Xeon Processor (Skylake, IBRS, no TSX)" at 2,100 MHz, with
  rdrand, aes, pclmulqdq, ssse3, sse4.1, adx, bmi2 (all required), pdpe1gb, x2apic,
  avx512f/bw/vl; no sha_ni, no avx512ifma. Some cx23s have an "AMD EPYC-Rome Processor"
  instead.
- RAM: 1 MiB to 0x7ffdc000 below 4 GiB, and 1,952 MiB above (to 0x17a000000).
- Network card: 1af4:1041 at 01:00.0, BAR 4 at 0xfd000000 (64-bit, but below 4 GiB);
  common/ISR/device/notify structures at +0/+0x1000/+0x2000/+0x3000, notify multiplier
  4, rings of 256, **one queue pair**. Features offered: CSUM, GUEST_CSUM, TSO,
  MRG_RXBUF, CTRL_VQ, EVENT_IDX, INDIRECT_DESC.
- Address: a /32, everything through the gateway 172.31.1.1. DHCP gives mask /32,
  router 172.31.1.1 (also as a classless route), a one-day lease (T1 12 h, T2 21 h), and
  answers a broadcast REQUEST.
- Disk: 38 GB on virtio SCSI (1af4:1048), /dev/sda in the rescue system.

SeaBIOS won't boot a disk of a few KiB, so `disk.img` is 8 MiB, sparse.

## UEFI boot
Tested in QEMU only, with OVMF (Debian's `ovmf`): 1 to 4 processors, with KVM and
emulated; RAM above 4 GiB; images of 16 KB to 300 MiB (from 24 MiB they overlap memory
OVMF holds from 8 MiB up). The machine state at entry (CR0, CR4, EFER, segments, every
processor) is the same as after a BIOS boot. The firmware keeps some memory, so the
table space is slightly smaller, and OVMF takes 2.5 s to the first answer.

Neither Hetzner Cloud nor Linode boots by UEFI. The firmware must start an unsigned
application (Secure Boot off) and read an MBR partition table, which UEFI requires. Not
tested, from reading: firmware that has put the local APICs into x2APIC mode leaves k18
with one processor (the others are started through the memory-mapped APIC registers).

## Installing from the rescue system
The image is `disk.img`, written over the whole disk from the host's rescue system: a
Linux the host boots from memory, reachable by ssh. Hosts differ only in how it is
entered and left, which `./k18 publish`, `deploy` and `renew` are told:
- `--rescue 'COMMAND'` boots the machine into its rescue system with your ssh key in it
  (leave it out if the machine is already there, as where that takes a console).
- `--boot 'COMMAND'` boots it from its disk, where `reboot` in the rescue system does not.
- `--disk DEVICE`: the machine's disk, where the rescue system sees more than one.

The `COMMAND` values for `--rescue`, `--boot`, and `--reset` run through the local shell as
the user running k18. Treat them as trusted code: use fixed commands you have reviewed, and
never pass network, pull-request, or other untrusted text into these options.

Steps (`k18`: `live`, `rescue`, `itself`, `write`, `up`):
1. `publish` fetches the certificate the site shows and verifies it as a browser would
   (except its dates). If there is none (three tries), the machine is not touched:
   nothing could identify it afterwards.
2. The machine boots its rescue system, whose ssh host keys are new. It proves itself
   by **the key and certificate in the last 64 KiB of its disk** (put there by the
   previous deploy: `idput`): it must sign with that key for a certificate known to be
   its own (`proves`), the one from step 1 (`publish`) or the one in the packed folder
   (`deploy`, `renew`: the machine then receives nothing it doesn't already have). A key
   file or certificate alone is refused; a machine that cannot prove itself is sent
   nothing and booted as it was. `--first` is for a machine with nothing to prove yet
   (its first image, a site that is down, a machine already in its rescue system): then
   only the network route vouches for it, as with any first ssh to a new server.
3. `publish` reads key and certificate from there (nothing is kept locally) and gets a
   new pair when due (docs/commands.md; a private CA's or staging certificate left by an
   earlier image is untrusted, unless `--staging`). The new key is made locally; certbot
   on the rescue system (installed with apt if missing) answers Let's Encrypt on port
   80. A result that is not a trusted certificate for that key counts as none. `deploy`
   and `renew` use the folders `k18 pack` made.
4. The disk is discarded (or its first 128 MiB zeroed), the image written, key and
   certificate put at the end, the image read back and compared; then the machine boots
   from the disk and the command waits for a verified fetch.

If no certificate comes, or the site cannot be packed, nothing is written and the
machine is booted as it was (`renew` also puts the old key and certificate back). If
writing fails half way, the machine stays in its rescue system and the command says so:
its disk no longer identifies it, and the next try needs `--first`. Downtime is mostly
the rescue system's boot. `tools/hosttest.sh` tests all of this on a simulated machine.

### Hosts
The image needs a BIOS that boots the disk's first sector, or UEFI firmware that starts
unsigned code; a virtio network card; an IPv4 address by DHCP (or `-i`); a processor as
the README says. For IPv6 it must be given the machine's address (`-6`): the one the
host shows.
- **Hetzner Cloud**: `--rescue 'hcloud server enable-rescue --ssh-key KEY NAME && hcloud
  server reset NAME'`. The rescue system lasts one boot: `reboot` in it boots the disk,
  so no `--boot`. One disk, /dev/sda. IPv4 by DHCP; IPv6 is static, gateway fe80::1, the
  machine's address by convention the first of its /64 (`...::1`). An address may have
  been another machine's: with `--grub`, ssh must learn the new host key first (`deploy
  --grub` reports what ssh said and leaves the server alone rather than resetting it).
  - Seen there: DHCP and IPv6, booted by GRUB beside a Linux and from the raw disk, back
    6 s after a reset; a quoted `--header` served as given; the IPv6 address as a second
    name (`https://[address]/` verifies); DHCP renewal at T1 (12 h), and every minute
    with `DHMAX=120`. A `deploy` or `publish` takes about a minute to a verified fetch,
    a minute and a half with a new certificate.
  - Let's Encrypt, production and `--staging` (an sslip.io name): `publish --first`,
    `--if-due`, `publish`, `--days 90`, `renew --force --rescue`. After a staging
    certificate a plain `publish` stops before touching the machine (only a publicly
    trusted certificate identifies it): `--first` without `--staging` replaces it. Not
    tested: `renew --grub` with Let's Encrypt.
- **Linode (Akamai)**, seen on a Nanode in Frankfurt: "Linode Compute Instance/Standard
  PC (Q35 + ICH9)", SeaBIOS, 1 vCPU "AMD EPYC 7713" (with sha_ni), 1 GB. Card 1af4:1000
  (the transitional ID, with the modern structures: BAR 4 at 0xfe004000, the same
  offsets and multiplier, one queue pair) at 00:03.0, behind no bridge; disk virtio SCSI
  (1af4:1004), 16 MiB smaller than requested. DHCP: mask /24, router `.1`, a
  **30-minute** lease from a server off the network (41 of 41 renewals in ten hours).
  IPv6 is routed without being told; `linodes view` shows the address (SLAAC, from the
  MAC): pass it with `-6`. The image as `publish` makes it serves over both. Not tested
  there: more than one processor, RAM above 4 GiB, load.

  Linode's rescue system (Finnix, `linode-cli linodes rescue`) needs the console first
  ("you need to use Lish at least once in order to start SSH": their documentation, not
  tried). Instead, a small Linux on a second disk serves as the rescue system. Once:
  `linode-cli linodes create --type TYPE --region REGION --label NAME --booted false`
  (no image; `--no-defaults` keeps linode-cli from adding its default image and
  `authorized_users`), then `linodes disk-create ID --size 3000 --image
  linode/debian13 --root_pass ... --authorized_keys "$(cat KEY.pub)"` and `linodes
  disk-create ID --size 64 --filesystem raw` (a disk is listed only once it is ready;
  "Linode busy" means retry), then two configurations: `linodes config-create ID
  --label helper --kernel linode/grub2 --devices.sda.disk_id LINUX
  --devices.sdb.disk_id RAW --root_device /dev/sda` and
  `linodes config-create ID --label k18 --kernel linode/direct-disk
  --devices.sda.disk_id RAW` (Direct Disk boots the disk's first sector). In the Linux,
  once: remove the swap line from /etc/fstab (it waits 90 s for a swap disk at every
  boot). From then on `--disk /dev/sdb --rescue 'linode-cli linodes reboot ID
  --config_id HELPER' --boot 'linode-cli linodes reboot ID --config_id K18'`. Whoever
  has the account's token can boot that Linux, as with any rescue system. A publish
  takes four minutes, three of them the reboot, which waits for k18 to shut down and it
  never does. `linodes reboot` without a configuration boots the last one started.
- **OVHcloud Public Cloud**, from their documentation, not tried: `--rescue 'ovhcloud
  cloud instance reboot-rescue ID --wait'` (or `nova rescue ID`); login is by password
  (shown in the console or returned by the API), so an ssh key must be added by hand
  first; `--disk /dev/sdb` ("sda is the rescue mode disk"); `--boot 'nova unrescue
  ID'`. Not known whether it boots a BIOS boot sector or gives the address by DHCP.
- **Scaleway** boots by UEFI only ("Legacy BIOS is not compatible with Scaleway
  Instances"), which the disk supports; not tried, and its rescue system not looked at.
- Not usable this way: Vultr and DigitalOcean (rescue is an ISO and a browser console;
  both import an image by URL instead: `vultr-cli snapshot create-url`, `doctl compute
  image create`, the latter only with a partition table and cloud-init in it); UpCloud
  (no rescue system: a second server writes the disk).

### Checking what a machine runs
The image holds its key, so it can't be shared; its `made` can (`./k18 publish` prints
its hashes, so a workflow's log has them). With `made`, the source at the commit it
names and the certificates the server shows, `tools/repro.sh system made chain.pem`
rebuilds the system part to compare: anyone can check it, given the owner's word that
`made` is the running image's. The site part: `KEYLESS=1 ./k18 pack`, same folder and
settings, same gzip and brotli.

### A push publishes
`ci/publish.yml` is a GitHub workflow for the repository that holds a site (its header
lists the variables and secrets to set). A push to `main` runs `./k18 publish`; a daily
schedule runs it with `--if-due --days 45`; a manual run with "first" does a machine's
first image. The site's key is in no repository and no secret: it is made on the
runner, stored on the machine's disk, and fetched from there by the next run.
- Who can publish: whoever can push to that branch, and whoever has the two secrets
  (the host's API token and the ssh key for its rescue system). The token can do
  anything its owner can in its project: use a project for that machine alone.
- GitHub disables scheduled workflows in a public repository after 60 days without
  activity. The last step re-enables it with the workflow's own token (that this resets
  the 60 days is untested). Hence 45 days, not 30: a run that acts comes within the 60.
- Tested on GitHub (private repository, Hetzner, Let's Encrypt): the push that adds the
  workflow fails and leaves the machine alone (nothing identifies it yet); a manual
  "first" run takes about two minutes, a push that changes the page a minute and a half.
- **No run started by the schedule has been seen.** Two private repositories of a free
  account, with schedules every 5 to 15 minutes for hours, saw none, while the workflow
  was active and pushes ran within seconds. Not checked: the account's billing page, a
  public repository, an older account. Don't rely on it: until a run marked "schedule"
  shows under Actions, a push, a manual run or your own cron job with `./k18 publish
  --if-due` must come within the certificate's last 45 days.

## Beside a Linux (`--grub`)
For a server that keeps its Linux, such as one being benchmarked: a reset brings Linux
and ssh back in 25 s. HOST is its address, NAME what the host calls it.
- `./k18 pack FOLDER -n HOST -i HOST -c cert-hz -o build-hz` (for the benchmark's
  page: `./k18 pack www ... -o build-hzb --plain80`), then `./k18 deploy HOST build-hz
  --grub --reset 'hcloud server reset NAME'`: if Linux does not answer ssh (k18 is
  running), the server is reset; then the image is copied to /boot/k18.bin and the
  server reboots into it once through a GRUB entry ("k18" in /etc/grub.d/40_custom,
  loaded with `multiboot`; where /boot is a separate file system the entry names
  /k18.bin on it, untested), and the command waits for a verified fetch. Linux stays
  installed and is what any later reset boots. k18 is up 4 s after the reboot (it
  zeroes all 4 GiB).
- With `--persist`, Linux gets a unit (`k18-chain.service`) that boots k18 a minute
  after Linux is up, unless /run/k18.hold exists: so k18 comes back by itself 90 s after
  a reset, and `./k18 deploy`, which creates that file as soon as ssh answers, still
  gets in. Without `--persist` the next deploy removes the unit. `./k18 renew HOST OUT
  --grub --reset '...'` renews such a server's certificate (certbot on its Linux).
- `curl --cacert build-hz/ca.pem https://HOST/` and `curl http://HOST/`
- `hcloud server reset NAME` boots Linux (GRUB's default) whatever the image does. A
  fault resets the machine too (no handlers: `GDT`), which boots Linux; a hang does
  not. The image never answers ping.
- By hand: `make B=build-hz CERT=cert-hz NAME=HOST IP=HOST` and `B=build-hz
  tools/deploy.sh root@HOST`.
- For a first look at anything new, add `DEBUG=1 LIFE=8` to that `make`: port 80's page
  then shows the counters (docs/commands.md, "Debugging"), and the machine resets itself
  after about 8 minutes whatever happens (use a `LIFE` image for nothing else). Without
  `LIFE`, an image whose network side fails stays up until somebody resets it.
- A load generator is a second server next to it, for an hour: `hcloud server create
  --name k18-load --type ccx33 --image ubuntu-26.04 --location nbg1 --ssh-key KEY --label
  purpose=k18-bench` (KEY from `hcloud ssh-key list`; the account's dedicated-core limit
  allows one ccx33, so a second generator must be a shared type such as cpx42), then
  `bench/README.md`. It is billed by the hour: `hcloud server delete k18-load` when done,
  and `hcloud server list` to check nothing is left.
- Load comes from a generator, not the user's home connection. From here, for a quick
  look: `B=build-hz DST=HOST:443 build/tapc 0.0.0.0 20000 400 www/index.html`, and with
  `PLAIN=1 INFLIGHT=32` and `DST=...:80` for port 80. Use base ports below 32768.
- A browser against the server: `tools/nssdb.py DIR/.pki/nssdb build-hz/ca.pem`, then
  `HOME=DIR google-chrome --headless=new --no-sandbox --user-data-dir=DIR/c --dump-dom
  https://HOST/`; `tools/ffcheck.py https://HOST/ build-hz/ca.pem "Hello"`. With a real
  name and certificate: Chrome as is, and `REALDNS=1 tools/ffcheck.py https://NAME/
  EMPTYFILE "TEXT"` (without `REALDNS` it resolves every name to 127.0.0.1).
- SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=NAME&hideResults=on&latest
  in a browser (a minute; `hideResults` keeps it off the public list).

## The certificate (`tools/gen.py`, `cert/`)
- `cert/server.key` (ECDSA P-256) and `cert/server.pem` (leaf, then intermediates) are
  the identity built into the image. To use a certificate from elsewhere, put those two
  files there (and no `ca.pem`); `tools/mkchain.py DIR` makes a realistic test chain.
- If they are missing, gen.py makes a 210-byte leaf for `NAME` (default 127.0.0.1; an
  IP address or DNS name; plus the names in `SAN`, 2 bytes and its length each) and its
  CA, `cert/ca.pem`. There is no CA key: the leaf's signature is fixed first (r = 5,
  s = 1) and the CA's public key is solved from the verification equation. Nobody knows
  its private key, so trusting this CA is harmless.
- gen.py also writes `build/ca.pem` (what tests trust; empty for a real chain) and
  `build/name` (the name tests ask for, while always connecting to 127.0.0.1 or the
  tap; also where port 80 redirects): `NAME` if the certificate covers it, else the
  certificate's first name. Not the first name alone, because Let's Encrypt sorts a
  certificate's names: it would pick `api.example.org` over `example.org`.
- A chain over ~1.1 KB makes the handshake reply longer than one TCP segment
  (`tools/mkchain.py cert-real`, `make B=build-real CERT=cert-real`: a flight of 1,909
  bytes; run the loss and reorder tests with it after touching `.resend` or
  `tcp_send`). A handshake buffer is 4 KiB, or the next power of two that holds the
  chain.
