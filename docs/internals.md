# How it works

Read the part you are about to change; `tools/ec.py` has the curve code's other half.

## Layout
- `src/os.asm` and the files it includes: everything after the loader, with the site
  appended (`incbin`). One assembly unit; its files, in image order: `os.asm` (addresses,
  macros, SHA-256 constants, the other processors' first steps, read-only data),
  `start.asm` and `setup.asm` (start-up), `poll.asm` (polling loops, rings, the card),
  `tcp.asm`, `ip6.asm`, `send.asm` (`sm`, `geom`, `sendseg`, `sendrun`), `request.asm`
  (`record`; `pick` and `seek`: which form of a response, by Accept-Encoding and
  If-None-Match), `timer.asm`, `conn.asm` (`find`, `prf`, `ckx`), `seg.asm` (`respond`,
  `oohold`, `hsbuf`, `tcp_send`, `tcp_seg`, `csum`), `dhcp.asm` (`dhask`, `dhsend`,
  `dhcp`), `tls.asm` (`handshake`, `hrrmsg`; `thash`: the transcript hash, continued, not
  restarted), `sha.asm` (`keys`, `sha256`/`shablk`, `hmac`, `expand`), `curves.asm`
  (`xdh`, `sign`, `stock`, `comb`, `select`, `vm`; `rand`: `rdrand`, each draw compared
  with the previous one), `aesgcm.asm` (`seal`). A conditional must end in the file it
  begins in, so code in the image but not in the host test build (`HOST`) is included
  from inside os.asm's conditional.
- Runtime: 64-bit long mode, interrupts off, an empty interrupt table on every processor
  (a fault resets the machine), one polling loop per processor. Code from k2 is 32-bit in
  style (`pushad` is a macro for the seven old registers other than the stack pointer);
  r8-r15 belong to the crypto and nobody preserves them. Addresses below 4 GiB live in
  32-bit registers; a connection's slot address (`rbp`) does not.
- Start-up, in 32-bit code as the loader leaves it: zero our memory below the table
  space, build page tables (who may write and execute what), enter long mode. Then: the
  memory map into page tables, zero and divide the table space, SHA-256 constants,
  `ecinit` (curve fields, constants and tables; programs unpacked), start of the key
  schedule, virtio-net, the key for `prf`, the other processors.
- `src/boot.asm`, the BIOS boot sector, reads the image (any length) 64 sectors at a time
  and copies each piece to where the image header says, from real mode with segments that
  reach all memory (set again for every piece: the BIOS may reset them). Then it gets the
  E820 memory map, enters protected mode and enters the image like a multiboot loader
  (the map in a multiboot information structure at ebx, as GRUB passes it).
- `src/efi.asm`: the same for UEFI, a 2,048-byte EFI application on the disk; os.bin
  knows of neither loader and is entered in the state a BIOS leaves. The application gets
  a page below 1 MiB, os.bin read into memory below 4 GiB, and the memory map;
  calls ExitBootServices; writes the free ranges into its page as a multiboot memory map
  (adjacent ranges merged, 128 at most); and continues there in 32-bit code (`low`):
  paging off (leaving long mode), CR4 and CR0 as a BIOS leaves them, and only then the
  copy to where the image header says (firmware sets CR0.WP, which `start` needs clear,
  may use five-level paging, and may have memory there, page tables included).
- The disk (`tools/mkdisk.py`, written by hand so its bytes are the same wherever it is
  built): the boot sector, one partition of type 0xEF holding a FAT16 file system with
  `os.bin` and `EFI/BOOT/BOOTX64.EFI`. The image's sectors are contiguous: the boot
  sector reads them directly (mkdisk.py patches in the load and entry address, the length
  and the first sector), the EFI application reads the file.
- virtio-net (`pcird` reads PCI configuration): the driver finds 1af4:1041 or :1000 on
  any bus, maps its common, notify and device structures at addresses of ours (a BAR may
  be 64-bit and anywhere), negotiates VERSION_1 and, if the device offers both, CSUM and
  HOST_TSO4 (the device checksums and segments frames of up to 64 KiB; `TSO` says
  whether), and polls the used ring.
  - `txbuf` returns the next transmit buffer (waiting while the device holds all N) and
    takes `TXLOCK`, since all processors share the ring; `txgo` queues the frame.
    `txkick` notifies the device (unless it set NO_NOTIFY) when the polling loop has
    handled all received frames, or every 32: a notification is a VM exit, dearer than
    the rest of a frame's work.
  - A frame for the card to segment is built outside the lock, in one of 8 per-processor
    64 KiB buffers (`txbig`: the next in a ring, once the device has sent what it last
    held, by `TXCNT`, the count of frames ever queued, against the device's). `tcp_big`
    queues it with the 12-byte header saying how to segment it, and notifies at once.
- `tcp`: an ARP request for our address gets a reply (only whole, 42-byte requests:
  behind a shorter frame lies the previous one). Beyond that only IPv4 without options,
  unfragmented, TCP, to our address, on port 443 or 80, with a correct TCP checksum and a
  length that fits the frame and both headers (at least 40, checked before 20 are
  subtracted) gets further. `tcp_send` splits an answer into segments, `tcp_seg` builds
  and sends one. Inside `tcp`: `.walk` (records), `.tx` (a response being sent).
- `tools/gen.py` makes `build/*.inc` from the certificate, curve programs and constants
  (`docs/server.md`), `tools/pack.py` the site's `build/site.bin` and `site.inc`. Other
  tools, tests and benchmarks: `docs/commands.md`; not described there: `tools/made.py`
  (writes `build/made`), `tools/k18test.sh` (the `k18` tool's test), `tools/tlsclient.py`
  (shared TLS client code), `tools/certerr.py` (for the browser checks), `test/asm.h`
  (the asm's C interface).
- The key is 32 bytes of the image (64 behind `EDC`: d R mod n), and nothing else in the
  image depends on it. The system depends on the site only through the numbers in
  site.inc, and on the build machine only through the assembler.

## Memory
What the page tables map (`start`):
- **The first 18 MiB, identity-mapped:**
  - 0: the frame being handled (`FR`), as received: its fields are the packet's variables
    (`P_SEQ` and so on), one displacement from ebx = 0
  - 1 MiB + `DELTA` (below): the image, up to 1 MiB of it
  - 2 MiB: buffers and variables (`BSS`; `OB` is our answer to one packet); the stack
    grows down from 4 MiB
  - 4 MiB: virtio rings (`VQ`), then the page tables
  - 5 and 7 MiB: receive and transmit buffers (`RXB`, `TXB`: 2 KiB each, descriptor
    i is buffer i, a 12-byte virtio header in front; `txgo` writes the descriptor's
    address every time, since a frame for the card to segment lies elsewhere)
  - 9 MiB: the other processors' page tables; 10 MiB: their memory
  - 16 MiB: buffers for frames the card segments (`BIGB`: 8 of 64 KiB for each of
    four processors), here because the device needs physical addresses
- An image larger than 1 MiB moves everything above it up, in whole 2 MiB pages
  (`LOW`, known at assembly time from pack.py). "2 MiB" here and in the source means
  2 MiB + LOW. An image can be up to 768 MiB.
- Permissions: the first 2 MiB use 4 KiB pages. Low memory is data (writable, never
  executable), except the page the other processors start in (code). The image's code
  pages are executable and read-only, the rest read-only. Everything from BSS up, in
  2 MiB pages, is data. `CR0.WP` is set after start-up's last write to a read-only
  page (the copy of `tramp`).
- **Where the code ends, a page ends** (`DELTA`, `codend`). The image is code followed by
  read-only data (constants, the key, the certificates, the site) with nothing between,
  and execution is controlled per page. So the image is loaded `DELTA` bytes above
  1 MiB (its header says where; `org`), which puts a page boundary exactly at the end
  of the code: no padding, and no constant, key, certificate or site byte in an
  executable page (the Makefile finds it with a first assembly: `OUT/delta`). `DELTA` is
  a multiple of 64, so alignment in the image is alignment in memory (`HOT`). The up to
  63 bytes this leaves are filled by `tramp`, the other processors' first code: the last
  of the code, it only runs from its copy, so the boundary may fall inside it (before
  `xend`). `codend` refuses to assemble with any other value.
- **What executable pages hold**: the image's code, the loader's 32-byte header in front
  of it, and before that the `DELTA` bytes from 1 MiB on, zeroed by `start` (a
  loader's leftovers); at 0x8000, the copy of `tramp` with its ten bytes of data (a
  counter and its segment values), then zeros (`start` zeroes the image's last piece,
  which the boot sector read through that page). The page `src/efi.asm` wrote in is data,
  or zeroed with 0x8000 if it is that page. Tested by `tools/wxtest.sh`.
- **The table space**, from 18 MiB up: every 2 MiB of RAM the memory map calls
  available, concatenated (on the server, the rest of the 2 GiB below 4 GiB, then
  everything above). Boot divides it, with n a power of two (one mask, `HSMASK`):
  - n handshake buffers (about 1/32 of it) and n 2 KiB places for early segments (1/64)
  - 4 n recent SYNs (128 bytes each, plus a dword for the time: `tnote`)
  - for each of four processors, a ring of n 2 KiB frames (`drain`) and a queue of 4 n
    64-byte entries for connections waiting for an ack (`tarm`)
  - the TLS table (an eighth of the rest: `TSHARE`), then the port 80 table.

  On the server (4 GiB of RAM) n is 16,384, and the tables hold 3.8 million TLS slots
  and 143 million for port 80.
- The card's structures (and the local APIC) are mapped in 4 MiB each in
  GiB 505. BSS variables are addressed relative to rip (`BSS equ mb + ...`:
  nasm won't do that for a plain number). The machine needs at least 64 MiB.

## Our address
Built with an address (`make IP=a.b.c.d`, `./k18 pack -i`), the image has it as a
constant in two comparisons (`NOTOURS`: the ARP target and the IP destination), asks
nothing and has no UDP. Without one (the default), it is a variable and a DHCP client is
included (514 bytes):
- Sending never needs the address: every frame we send answers one, from the address it
  was sent to, back to its sender (`tcp_seg` takes both from the current frame, `ethhdr`
  the card's MAC). So no mask, router or name server is requested or read.
- **Only the first processor does DHCP**, so its state has one reader and one writer:
  anything that may be an answer (UDP over IPv4, to any address) goes to it (`drain`);
  the others read `MYIP`. It asks when due (`dhask`, every pass of its polling loop,
  against `DHT`): a DISCOVER with no address, a REQUEST to keep one, both broadcast (the
  REQUEST as in RFC 2131's "rebinding": unicast would need a route), 342 bytes (300 the
  message, the minimum). Retries after 2, 4, ... 128 s, then every 128 s.
- An answer counts only if its UDP checksum is correct or absent (0: OVN's DHCP), it is
  from port 67 to 68, **it carries the transaction id of the question being asked**
  (`DHX`: 32 bits from `rand`, new for every question), **and we are asking** (`DHB`). So
  once we have an address nobody can change it until we ask again; while we ask (for days
  if no server answers a renewal), an attacker who saw the id on the link, or tries every
  id from afar (1.2 TB), has until the next question, 128 s at most. Of the
  options, walked to the end of the message, the first four bytes of three are kept:
  lease time (51), message type (53), server identifier (54).
- An OFFER, while we have no address and have requested none (`DHA`), gets a REQUEST for
  the offered address, naming the server; a second server's offer gets nothing (naming it
  would tell the first its offer was declined, RFC 2131, 3.1). An ACK for the address we
  requested (offered, or ours when renewing) sets `MYIP`, and `DHT` to half the lease
  from now plus a second, six days at most (32 bits of clock ticks). A NAK drops the
  address, and we ask again a second later. Our messages carry the time spent asking (1,
  2, 4, ... s: a server can be set to leave a client to others until then).
- `tools/dhcptest.sh`: nine images, each with one rule removed, each fail it.

## IPv6
Only in an image built with an IPv6 address (`make IP6=...`, `./k18 pack -6`): 752 bytes.
Hosts differ in how a machine would learn the address, and all of them show it
(`docs/server.md`). `ip6.asm` holds `tcp6`, `nd`, `our6`.
- **One layout.** `tcp6` rewrites an IPv6 frame for us in place into the IPv4 frame the
  rest of `tcp` knows: the header is 20 bytes longer, so the segment moves down 20 bytes.
  The frame keeps its EtherType (0x86DD at 12), by which `tcp_seg`, `find` and `cuts`
  tell the two apart. The client's 16-byte address stays in IPv4 header fields nobody
  reads again (bytes 14 to 25, 30 to 33), so the first 64 bytes still identify the client
  and how to reach it, which is all the timers keep (`tarm`, `tnote`). `P_ADV` lives
  where the frame had our MAC, for the same reason.
- **The client's identity in a slot** (four bytes, `P_IP`) is 32 bits of a keyed hash of
  address and ports, never 0 (`find`). Two clients are confused only if those bits and
  the port both match: nobody can aim at that, the key being ours; by chance one pair in
  2^48, and then the second replaces the first, as a client returning from the same port
  does. The address is hashed, then through the cipher again with the ports (`prf6`), so
  a cookie issued to one address and port is useless from another address. `drain` makes
  the same hash, so it picks the processor and places `find` does.
- **Checksum** (TCP and ICMPv6): addresses, length, next header and segment are
  everything from the length field on, in another order, once the two bytes after the
  length are 0 and the next header. So it is summed in place, like IPv4's.
- **Sending** (`tcp_seg.v6`): the frame starts 20 bytes earlier than an IPv4 frame, so
  from ebx on the TCP header and payload lie as always, also in frames the card segments
  (`txbig` leaves room in front; `cuts` requests HOST_TSO6 separately). From our address
  to the client's, hop limit 64.
- **A segment carries at most 1,220 bytes**, whatever MSS the client gives (or its first
  ack's low bits say our SYN-ACK recorded). With headers that is 1,280, which every IPv6
  link must carry: no path is too narrow, and reports that one is are not read.
- **Neighbour discovery** (`nd`): a solicitation for our address that passed no router
  (hop limit 255) and names its sender gets an advertisement with our MAC. That is all of
  ICMPv6, nothing about routers: we answer to where a frame came from.

## Processors
The server's card has one receive queue, so the first processor empties the device's ring
(`drain`) into the ring of the processor that owns each frame's connection, its own
included, chosen by `prf` of addresses and ports (low bits of the word that picks the
early-segment place). A ring holds n frames (16,384 with 4 GiB), about half a second
of handshake work; beyond that frames are dropped and clients retransmit. Each processor
handles its ring one frame at a time (`ring1`), with the same code. The device's ring is
small (256 on the server) and overflow is lost on the host, so the first processor
empties it before every frame it handles and from inside anything slow (`bdrain`: every
64 ladder steps, after each k G that `sign` computes itself, while waiting for the
transmit lock or a buffer).
- Each other processor has its own page tables, differing in two places: BSS and page 0
  are its own memory (BSS a copy of the first processor's after setup). So everything at
  a fixed address (the frame, the transcript, the curve registers, the nonce stock,
  counters) is per processor without the code saying so.
- Shared: the transmit ring (`TXLOCK`, from `txbuf` to `txgo`); handshake buffers (each
  processor uses every n-th: `hsnew`); early-segment places (a place's low bits are its
  processor); the connection tables: a connection belongs to one processor, a bucket does
  not. A new connection claims its slot with one `lock cmpxchg` on the slot's first 8
  bytes, against what `find` saw there; if another processor was faster, the packet is
  dropped and the client retransmits. Ack queues are per processor.
- The others are started with INIT and SIPI to "all but self" (`tramp`, copied to 0x8000:
  real mode straight to long mode); each takes a number with `lock xadd`. Frames go to
  the largest power of two of them (`NCPUM`). With one processor nothing changes but an
  uncontended lock. One that gets no frames (the third of three, or one that took its
  number after the count was read) waits for the count and halts (`apstart`; if the first
  processor counted none, it waits forever): its turn at the recent SYNs (`tidle`) would
  use the first processor's places.
- **A slot changing processors** (a connection idle for an hour, in a full table) is one
  atomic step on each side. The taker's `cmpxchg` expects the slot's first eight bytes as
  one load read them (`find.used`), C_AGE included, and writes its own there
  (`tcp.make`). The owner, before touching the connection, changes C_AGE with an `xchg`,
  then checks in one load that the slot is still its connection's (`hold`). So exactly
  one side notices: the taker gets nothing (its client retransmits), or the owner finds
  its connection gone (its packet is dropped). A slot idle for all of 255 units is not
  taken: a packet of its own one unit later would leave C_AGE unchanged.
- A packet from the client (`tcp`, after `find`) and the connection's timer (`tqrun`)
  both go through `hold`. The timer is no sign of life, and C_AGE decides when a client
  is given up, so the timer saves C_AGE and restores it when done, if the slot is still
  that connection's (`own`). Otherwise a timer could go on with a slot that has become
  another connection's: sending its records to the old client, or sealing under the new
  key with a record number from the old numbers (one key and nonce for two records).
  `tools/racetest.sh` stops the timer at exactly that point.

## How TCP works here
Nothing sent is kept, except the handshake flight: everything else is rebuilt from data
that does not change. A connection knows the next byte it expects (`C_NXT`), our next
byte (`C_SND`) and the client's last ack (`C_ACK`). Files are sent by `tcp.tx`; the
flight and port 80 (one response, the same for every request) the old way: all at once,
rebuilding the end when the client turns out to lack it (`.resend`).

**A response being sent (`tcp.tx`).** A TLS connection past its flight (`sm`) has one
current response: which one (`C_AS`: a number in the site, plus a bit for "headers
only"), where it began in our sequence numbers (`C_RS`), and the number of its first
record (`C_SR`). The response is a stretch of the image, cut into records sized to the
client's segments (`geom`: 216, 536, 1220 or 1440 bytes, minus 22 for the record), so
segment i can be built at any time from those three values and i.
- **Window.** In flight may be what the client's window allows (scaled by its SYN's
  shift, kept in the top four bits of `C_FL2`) and `C_CW` segments: 10 at first; one more
  per segment acknowledged while nothing has been lost and under 64 KB is in flight
  (doubling every round trip); halved after a loss (2 at least); then one more per
  16 KiB acknowledged. Past 64 KB (the maximum without window scaling) only while
  the connection has never lost anything (after its first loss, 64 KB at most for
  good), by one segment per 64 KiB acknowledged, up to 255 segments. A new response
  starts at 64 KB at most (44 segments). Why: `bench/README.md`, "Over a distance".
  A record goes whole or not at all, and none that would end past the edge of the
  client's window: a client need not take a segment that does (Linux since 6.17 drops
  it whole while it has data unread), and then something is lost where nothing was. So
  a window is used up to a segment short, and one smaller than a segment not at all
  (below, the timer).
- **Loss** is signalled by a duplicate ack (once if at most two segments are in flight,
  otherwise three times), by the client retransmitting old data, and by the timer; the
  one segment at the client's ack is retransmitted. Until the client's ack reaches
  `C_SND` nothing new is sent, so an ack that advances but not that far asks for a
  segment that was lost too: it is retransmitted at once.
- **Many records per frame** (`sendrun`). With `TSO`, all records that end inside what
  may go now, up to 45 (64 KiB), are sealed into one frame in a per-processor buffer
  (`txbig`); the card
  gets the headers once, the segment size, and the pseudo-header sum in the checksum
  field (`tcp_big`), and cuts where we would have. If what may go is under a third of the
  window and not the end of the response, it waits for the acks still to come (else small
  frames bring small acks, which release small frames). Retransmission is one record
  (`sendseg`); a frame lost whole is recovered one segment a round trip.
- **Retransmission timer** (`tarm`, `tqrun`). A connection owed something (an ack
  outstanding, or the client's window closed) is in its processor's queue once: the first
  64 bytes of one of its client's frames, the time, the ack. A polling loop with nothing
  else to do takes the oldest entry. Not yet due (ticks of 1/2048 s from `clock`,
  which scales `rdtsc` by `TSCM`, calibrated against timer 2 at boot; the wait doubles
  after each fruitless try, up to 16 s): requeued. Due: if the client has everything,
  done; if its ack has advanced, requeued; if not, the segment at its ack is
  retransmitted and the window halved. Nothing new goes on the timer's word: the window
  in the frame it kept is as old as that frame (`P_WIN` is zeroed). After six fruitless
  tries (16 s), a client
  silent for more than one unit of C_AGE (a minute or two) is gone: it gets a RST (at
  `C_SND`, which a client still lacking data rejects, RFC 5961) and its slot is freed.
  One with a closed window that answers stays.
- **A client that stops reading.** Its window shuts with everything we sent
  acknowledged, since nothing goes past its edge. The timer's segment is then the
  question what it takes by now: a whole segment, which it drops and answers with the
  ack it had. When it reads again it says so with that ack once more (a window update).
  Such an ack counts as a sign of loss only until the segment has gone again; after
  that, if one segment is all that is in flight and the ack's window holds it, the
  segment goes once more, at once (`.took`), where it used to wait for the timer, up to
  16 s. An ack whose window does not hold it gets nothing, so that never goes in a
  circle. This also holds when the ack comes from further on than we expect the client
  (`.early`): it is there for as long as a request of its waits to be sent again.
- **Timeout** (`C_RTO`, in 1/64 s): 3 R (TCP's rule after one measurement), at least
  0.25 s, at most 1 s. The round trip R is measured once, from our flight going out
  (`C_T0`) to the client having it (`tcp.est`; the client answers a flight at once with
  its Finished). A fixed 0.25 s would send a client 300 ms away every segment twice
  (`tools/rtttest.py`). The 1 s cap: a lost first flight puts the client's own timeout
  into R, and losses at a response's end should not wait seconds.
- The client's FIN (or a method we don't serve: `record` closes after answering) closes
  the connection: nothing more is accepted, our FIN goes with the last segment the client
  needs, and the slot is freed when that is acknowledged.
- Sequence numbers wrap: compare by the sign of a `sub` (`js`/`jns`), never `jl`/`jle`;
  the suite's `*isn*` and `site_wrap*` runs make each connection cross 2^31.

**Requests (`tcp.walk`, `record`).** A record that lies whole in a segment is read in
place; any other (and every ClientHello) is reassembled in a handshake buffer, up to
4 KB; one that claims more gets a RST. A record counts if its tag is correct for the
client's next record number (`C_ST`). Decrypted application data starting with `GET ` or
`HEAD ` has its path (up to a space, `?` or the line end) looked up in the site's table:
its response, or the 404. Another word and a space (a method is any word in any
case: bytes above space, no colon) gets the 405, and the end. Anything else authentic (an
alert, a header line in a record of its own) gets nothing, except a record of all zeros
with no content type, which ends the connection (RFC 8446, 5.4). After 2^32 - 2
records from the client (`STLIFE` in tests), or 2^24 sealed by our key (`KEYLIFE`), the
connection is closed so neither counter wraps.

The old way, and what both ways share:
- **Whose segment it is** (`tcp.est`, `.odd`), decided before anything in it is used: it
  starts within 64 KB (our window) of what we expect next, either way, and its ack is
  for something we sent and the client has not acknowledged (`C_ACK` to `C_SND`), or is
  behind `C_ACK` by less than 2^19 bytes (more than 255 segments can be in flight): a
  reordered packet, whose ack says nothing and whose data counts. Of any other segment
  nothing is used (not its ack, data, FIN or window), and it gets a bare ack; unless a
  SYN has come for the connection and this is the cookie of that SYN's answer ("The
  connection tables"). So an off-path attacker must guess both the client's sequence
  number and ours (RFC 9293, 3.10.7.4; RFC 5961, 5.2): one in 2^15 and one in 2^12 or
  2^13. (A forged ack alone could stall a response forever.) A RST ends the connection at
  exactly one number, the one our acks have given (`ackno`), which a host that knows only
  our segments would answer with. `tools/acktest.py`.
- In-order data is accepted (an overlap trimmed), out-of-order data is kept (below) and
  gets an ack of what we expect, and a keep-alive probe gets an ack.
- Two signs of loss lead to `.resend`, which rebuilds what we sent from the client's ack
  on (the last records by sealing again under the same sequence numbers, the end of the
  flight from the handshake buffer): old data again with an ack below `C_SND` (our
  answer, which carried the ack, was lost), and the same ack below `C_SND` twice without
  data (the client got something past a hole).
- **`F_DEFER`**: an answer of several segments does not acknowledge the client's last
  byte until the client's ack shows it has all of it, so the client keeps retransmitting
  that byte whichever of our segments were lost, and an old-way answer (`tcp_send`) needs
  no timer. With `tcp.tx` this applies to a response that goes at once and is at most
  64 KB (even with all our timers lost, the client asks again); a longer one is
  acknowledged at once, since a client that waits minutes for an ack gives up (Windows
  after five tries), and one re-asking while its response arrives looks like a loss. A
  client with nothing more to say acknowledges late (Linux: 40 ms) and gets our ack.
  Simpler rules (acknowledging with the last segment, or not what the current packet
  brought) leave both sides silent when a hole and a duplicate ack are both lost.
- A retransmitted ClientHello gets the same flight, not a new handshake: the client may
  have the first flight, and would then hold keys we no longer have.
- **Handshake buffers** (`HSP`: n of 4 KiB). A connection takes one with its first
  ClientHello byte (`hsnew`: the next free one in a ring; if 16 in a row are in use, the
  16th anyway). It holds the ClientHello as it arrives, then the flight in its place, and
  is in use while its owner's slot names it: until the client's ack shows it has the
  flight, a round trip. A connection whose buffer was taken and that needs it (more of
  its ClientHello, or a resend) is reset. Later a connection takes one again for every
  record that arrives in pieces, until the record is whole.
- A ClientHello without an x25519 key share gets a HelloRetryRequest as its whole flight
  (`hrrmsg`), and the connection waits for another ClientHello, keeping only the hash of
  the first where its keys will go (the transcript starts with that hash and the
  HelloRetryRequest, rebuilt from the second ClientHello: same session id, same suite).
  Meanwhile a non-handshake record (clients send a ChangeCipherSpec first) is skipped.
- Our flight is three records: the ServerHello, a ChangeCipherSpec (`14 03 03 00 01 01`;
  "Shortcuts that remain"), and one sealed record with the rest.
- **A client we can't serve** gets seven bytes and our FIN: a fatal alert. The checks, in
  order, after the extension walk (which needs none of them to stay in bounds):
  - "unexpected message": the first handshake message is not a ClientHello (type 1)
  - "protocol version": no TLS 1.3 in extension 43 (a TLS 1.2 client has none)
  - "decode error": a session id over 32 bytes, or a message length (three bytes) that
    does not match the record
  - "illegal parameter": compression methods other than just null (`01 00`)
  - "handshake failure": our cipher suite is not among its suites, x25519 not among its
    groups (extension 10), or no x25519 share after a HelloRetryRequest
  - "illegal parameter": an x25519 share that makes the shared secret zero (small order)

  The alert is the connection's flight (kept, resent if lost), and we close (`handshake`
  sets F_CLOSED, `tcp.fin` sends the FIN). A ServerHello for a suite the client did not
  offer would be what scanners call intolerance, and a handshake's work for every piece
  of junk. `tools/tlsprobe.sh HOST[:PORT] [CA]` asks a scanner's questions one at a time.
- **Out-of-order segments** are kept (`oohold`) and used once what precedes them arrives
  (`.reply`): on real networks two back-to-back segments (a ClientHello in two; Finished
  and the request) arrive swapped 5-25% of the time, and dropping the early one costs a
  retransmission timeout. Of n places of 2 KiB, a client's is chosen by its hash and
  holds one segment, the earliest; two clients sharing a place overwrite each other.
- **SYN-ACK retransmission**, the one thing sent unprompted, saves a client whose SYN-ACK
  was lost a second, and a 3 s retransmission timeout for the rest of the connection.
  A SYN gets no slot, so recent SYNs are kept aside (`tnote`: 4 n places by the client's
  hash, the frame as received); a connection that is made removes its SYN. A polling loop
  with no frame to handle visits the places (`tidle`, 8 a pass); a SYN still there after
  0.25 s goes through `tcp` again, three times at most, at most one per tick
  (1/2048 s): a SYN flood gets at most 2,048 extra SYN-ACKs a second per processor.
  Only when idle, like the data timer: the client's answer may be waiting in the ring.
- **Port 80** has no keys and no files: every request gets the same response (from
  pack.py: where the site is, or its front page). Requests are found by counting line
  ends (`.plain`: two in a row end a request, CRs ignored; a body would be read as more
  lines). At most 4 KiB is sent while anything sent before is unacknowledged; more
  waits in `oohold` for the ack (`.pbusy`, `.pwait`), so a 54-byte duplicate ack never
  makes port 80 resend more than 4 KiB.

## The connection tables
- Two tables, one per port, in the table space ("Memory"). A port 80 slot is 24 bytes:
  address, port, a byte of flags, a byte of time, `C_NXT`, `C_SND`, `C_ACK`, four spare
  bytes. A TLS slot is 128: the same first twenty; the client's next record number
  (`C_ST`); the current response (`C_SR`, `C_RS`, `C_AS`: ten bytes); its handshake
  buffer and how much of a record is in it; a byte of flags and the window shift
  (`C_FL2`); a byte of window (`C_CW`); 88 bytes of keys: two of 32 (AES-128 uses 16 of
  each) with their 12-byte IVs, five of the 16 unused bytes holding `C_T0` and `C_RTO`.
- A connection is in one of two buckets of 16 slots, picked by two words of
  `prf(addresses, ports)`. A new one goes into the bucket with more free slots (`find`),
  into its first free slot (address 0). Free slots are counted first; if another
  processor has taken the last one meanwhile, `find` looks again: each walk ends with its
  bucket (`tools/racetest.sh 3`). The table fills to 85% before anyone finds both buckets
  full, and at 92% one in a thousand does (`tools/rawc.c`).
- A bucket of 16 port 80 slots (384 bytes) starts on a 64-byte cache line, so every
  slot's first 8 bytes lie in one line and the `lock cmpxchg` that claims it (`tcp.make`)
  never spans two (which would lock the bus). TLS slots never span either.
- `prf` is eleven AES rounds (`aesenc`) over the frame's addresses and ports, under round
  keys from rdrand at boot: about 50 cycles, and clients can't aim at each other's
  buckets. Its four words pick the two buckets, make the cookie secret (`W`), and (the
  last) pick the early-segment place and the processor.
- **SYN cookies.** A SYN gets a SYN-ACK and no slot. Our initial sequence number:
  - bits 14-31: `W` xored with the low bits of the client's initial sequence number
  - bits 6-13: `W`'s own (`HINT`)
  - bits 2-5: the client's window shift (0 to 14, from its SYN's window scale option; our
    SYN-ACK then carries the option too, with a shift of 0)
  - bits 0-1: which of the four segment sizes the client accepts: the largest that is
    not more than its MSS, nor than the window its SYN says (a segment goes whole or
    not at all: one its window never holds would go only when the timer asks)

  The first packet that acknowledges it (the bare ack, or the first data if that ack was
  lost) creates the slot (`ckx`, `.make`), so a SYN flood from forged addresses takes no
  slots. With four bits for the shift, the cookie checks 26: a forged ack must be sent
  about 67 million times to get one 128-byte slot that nobody uses. The client can lie
  about its shift as about its window.
- A packet for no connection: if its ack carries our HINT bits, it belongs to a new
  connection whose first packets were lost, and is ignored. Otherwise, if it has data or
  a FIN, it gets a RST (the client is talking to a connection we no longer have); 1 in
  256 of those match the hint by chance and get silence. The test knob `ISNTOP` (12 bits
  forced) leaves 6 bits of the client's sequence number in the cookie instead of 10:
  enough for the lossy runs.
- An ack that fits no connection in its slot but is a valid cookie replaces the
  connection (the client reused the port and we never saw the old one end), **but only if
  a SYN has come for that slot since its last fitting ack** (`F_SYN`): a late duplicate
  of a connection's own first ack stays a valid cookie forever.
- **Full table.** When both buckets are full, the new connection is refused: its SYN gets
  a RST (`.deny`), or its first packet if room ran out after the SYN-ACK. Held
  connections are not evicted for new ones, except that a slot idle for more than `IDLE`
  (64 units of 64 s, 68 minutes; `C_AGE` is a byte of that clock) is taken if there is
  no free one, so vanished clients don't fill the table (`tools/idletest.py`). An evicted
  connection that had been sent nothing but its SYN-ACK is recreated by its next packet:
  its ack is still a valid cookie.
- A slot is freed by a RST at the number our acks have given, and by a FIN: the client
  gets our FIN, and if it had everything we sent, the slot is freed at once (if our FIN
  is lost, the client's next FIN gets a RST). Otherwise the slot stays (`F_CLOSED`),
  answering retransmissions until the client's ack covers our FIN.

## How the curve code works
Built for bytes per cycle. The design is in `tools/ec.py`'s docstring: one multiplication
(and two shorter variants), one add/subtract, numbers kept weakly reduced, a register
machine running the curve formulas as programs, the three scalar multiplications with
their tables, the inversions. Its model asserts every bound. The asm side:
- `fmul`: the 512-bit product (mulx with two carry chains, adcx/adox, a row per limb);
  then for 2^255 - 19 the part above 2^256 is folded back times 38, for P-256's p
  and n come four rounds of Montgomery reduction and a subtraction by carry. A round for
  p (-1/M is 1; M's limbs are all ones, half ones, zero and one) is a shift and one limb
  product; for n, five. `fsqr`: the square from ten limb products (six doubled, four
  squares); `fmul1`: times a one-limb number, from four. Both then reduce as `fmul` does.
- `fas`: add or subtract, then both corrected values are computed and one of three is
  kept (cmov); for 2^255 - 19 (adding or subtracting 38) by the carry alone. A
  field is 104 bytes built by `ecinit`: 2^256 - M, M, -1/M mod 2^64 (0 means
  "fold"), and the exponent for inversion.
- `vm`: each operation is 2 bytes in the image, unpacked at boot into four dwords (three
  addresses and the operation; ec.py turns a register multiplied by itself into a
  squaring), because decoding cost more than the additions. The ladder step is not run by
  `vm`: tools/gen.py writes ec.py's STEP25519 out as calls with their registers'
  addresses (`step.inc`, in `xdh`'s loop; `fas`'s add and subtract for 2^255 - 19
  are called directly as `fadd19` and `fsub19`), and JUMPH keeps each call off 32-byte
  boundaries: 370 cycles a step (Ryzen 7 3800X, `make bench`), where `vm` takes 430.
- **The order of a program's operations is what it costs.** A multiplication is 21 limb
  products (16, plus 5 to fold), a squaring 15, and the processor's one multiplier takes
  one a cycle, followed by a tail of carries. So an operation takes as long as its
  product count, barely overlaps with the next (which waits in a scheduler of some 60
  entries), and one that needs the previous result waits out that tail. Programs
  therefore put independent operations next to each other: the step does DA, CB, AA, BB,
  then the sums; MADD256 and MADDED likewise.
- Our key share uses a table of j 16^i B on edwards25519 (16 entries per nibble,
  98 KiB, built at boot), the signature's r = x(k G) one of (j + 1) 16^i G on
  P-256 (`KOFFV`: the offset taken off k first). `select` reads all 16 entries of a
  nibble and masks, 32 bytes at a time, gathering in two registers since gathering in
  memory waits on each store. The ladder swaps in 16-byte registers. Both X25519 results
  end in one division (`XPRE`, `inv`, `XPOST`) and `freeze`.
- `stock` makes 64 k G at a time, with two inversions for all (`binv`); `sign` takes one
  r and one 1/k and needs four multiplications. The polling loops call `stock` when idle
  and the stock is empty, one k G per call; `sign` calls it when it finds none. So a
  signature costs 70,000 cycles under full load and almost nothing below it.
- `inv`: mod 2^255 - 19 by `CHAIN25519` (254 squarings, 11 multiplications, 12,000
  cycles, using T0-T3); for P-256's p and n bit by bit (20,000 and 29,000 cycles).
- Our X25519 scalar is clamped and the top bit of the client's u is cleared (RFC 7748),
  so every small-order point gives a zero shared secret, which `handshake` refuses. r and
  s go out as DER INTEGERs of their own length (`derint`); nothing is retried.
- **`HOT mask`** before a routine places it so that none of its jumps crosses or ends on
  a 32-byte boundary, which Intel from Skylake to Cascade Lake (the server's) decodes
  again every time, with all of its 32 bytes (`bench/README.md`, "Where a jump lies").
  Used for the routines a handshake spends its time in (hash, ladder, register machine,
  field arithmetic, ciphers). The mask says at which of the 32 offsets after a boundary
  the routine may start, and it gets only the padding to the next allowed one
  (`tools/jcc.py`: `docs/commands.md`). In `xdh` and `seal`, called once per handshake
  and once per record, only jumps inside loops count.

## Records
`seal` builds a record from bytes and a content type. In reverse (carry set) it decrypts
a client record and appends the tag it should have had, which `record` compares before
reading anything. AES-128-GCM is the only cipher (every TLS 1.3 client must have it: RFC
8446, 9.1); a direction's key block is 32 bytes for the 16-byte key and 12-byte IV. The
key schedule is rebuilt for every record (`aeskey`: 176 bytes would not fit a slot). Four
counter blocks share the ten AES rounds (`aes4`, through `ks64`, 64 bytes of key stream),
and GHASH takes four blocks at a time with one reduction (`HTAB` holds H^1..H^4 times x;
`gh1` handles single blocks and the powers). Full 64-byte blocks are xored in xmm0-xmm3,
not through memory, then a 16-byte and a byte-wise tail.

## Shortcuts that remain
Simplifications kept to save bytes. Ask before removing the ones about TLS.
- **TLS 1.3 only, one suite**: TLS_AES_128_GCM_SHA256 (wherever the client lists it),
  X25519, ecdsa_secp256r1_sha256. A client lacking one of these, or with a session id
  over 32 bytes, gets an alert and nothing else. Of the ClientHello only the cipher
  suites, versions, groups and x25519 key share are read (`handshake` walks the
  extensions; every length is bounded by the ClientHello's end, anything inside an
  extension by that extension's end). Not read: SNI (every name gets the one site; the
  certificate says which names are valid), ALPN (we speak HTTP/1.1), signature algorithms
  (every TLS 1.3 client must support ours).
- The client's Finished is not verified as such: under handshake keys it fails the tag
  check like any forgery and is skipped. The first request proves the same.
- A bad record is skipped, not answered by an alert (a record with no content type gets
  our FIN, no alert). No close_notify, no KeyUpdate (a client that updates its keys is
  not understood; our connections end before our key seals too much), no session tickets.
- Our ChangeCipherSpec (for middleboxes that take us for TLS 1.2) follows the ServerHello
  on every handshake, whatever the client sent: 10 bytes, no condition. After a
  HelloRetryRequest it should follow that (RFC 8446, D.4); clients skip ours anyway.
- A client record over 4 KB (that many headers and cookies) ends the connection.
- A ClientHello is one record (decided: this stays). One split across two (allowed; no
  browser does it) is read as a short one with no TLS 1.3 in it, "protocol version", or,
  if its versions are in the first record, as one shorter than it claims, "decode error".
- Not checked: signature_algorithms, legacy_version (our ServerHello says 03 03
  regardless), whether the second ClientHello is the first plus a key share. A malformed
  x25519 share is treated as none: a HelloRetryRequest, where a server should refuse.
- **HTTP**: GET and HEAD; any other method gets the 405, not a 501 for unknown ones. The
  path is compared byte for byte with what pack.py made of the file names (`/a%20b.txt`,
  not `/a b.txt`; a query is cut off; no `..` to resolve), so a request in absolute form,
  `GET https://name/ HTTP/1.1`, which RFC 9112, 3.2.2 says a server must accept, gets the
  404 (decided: this stays; only proxies are sent that form).
  - A request is a record that starts with its request line: a line split over records is
    not found, and of two requests in one record the second is not seen.
  - Two headers are read, only for a file with other forms, and only in the record with
    the request line: Accept-Encoding (does the line contain "br" or "gzip" not followed
    by ";q=0"; other weights ignored, "*" means nothing) and If-None-Match (does it
    contain the chosen form's ETag; "*" does not count). A record continuing a header
    line with a word and a space is taken for a request with that method (405, the end).
  - A request needs a line starting "Host:" (any case; RFC 9112, 3.2) in that record, or
    gets the 400 and the end (as does one whose first record is `GET /` alone: tlsfuzzer
    sends two such). Its value is not checked, nor whether there are two.
  - No Range, no If-Modified-Since, no Date (there is no clock), no `Connection: close`
    (the client has the Content-Length; we close first only after a 405 or a 400).
- Two requests at once on 443: the next request is accepted only once the client has
  acknowledged all of the current response; the second is dropped with the rest of its
  segment and waits for the client's retransmission timer (0.2 s; `.busy`).
- **TCP**:
  - No SACK or timestamps: one loss found per round trip; windows past 64 KB open slowly.
  - No pacing: what an ack releases goes at once, so a path whose queue is shorter than
    that burst drops its tail. Pacing needs a per-connection timer (code, maybe some of
    the 128 bytes) and repeated round-trip measurement, in code where a mistake shows
    once in thousands: first run `tools/bneck.sh` with a short `BQUEUE` over
    `bench/README.md`'s paths to see whether bursts are the cost.
  - The round trip is measured once, at the handshake: a path that slows down later, or
    one of over a second, gets segments twice. A SYN-ACK is resent after 0.25 s
    whatever the round trip (a client farther away gets it twice, acknowledges twice,
    which looks like a loss to our flight, and gets that twice too).
  - The flight and port 80 go the old way (`tcp_send`; port 80 at most 4 KiB
    unacknowledged). Our own window is 64 KB, unscaled. A SYN with an MSS below 216 is
    refused: 216 is the smallest we cut to, and nobody is sent more than they said.
  - Whose segment it is: one up to 64 KB older than what we expect still has its ack
    read (RFC 9293 drops what is entirely old; a client resending old data is how we
    learn our answer was lost). An old ack counts, with its data, if under 2^19 bytes old
    whatever the client's window (RFC 5961, 5.2: no older than its largest window, not
    kept). Our acks to refused segments are not counted or rate-limited (its section 7
    wants a limit; a count is readable from outside, and we answer one for one).
  - A RST counts only at exactly the number our acks have given; one merely near gets no
    ack (its section 3). While `F_DEFER` holds our ack one behind, a client that gives up
    sends a RST one past it: that frees nothing, but our next segment gets a RST at our
    ack's number, which does. Every extra number accepted is one more for an attacker.
  - The window is used in whole segments: up to one segment less per window than a
    sender that cuts where the window ends. A client that makes its window smaller than
    a segment after its SYN gets one segment each time the timer asks. A request that
    comes before the response in hand is acknowledged waits for the client's TCP to send
    it again, and that timer has doubled for each time it did so in vain: after a long
    pause, seconds. While the timer's segment waits in front of a shut window our acks
    carry `C_SND`, past what that client takes: it does not hear them until it reads.
  - A reordered packet's window is taken as the client's latest. A refused segment still
    counts as a sign the address is alive (`C_AGE`: one a minute keeps a slot from
    eviction). The IP header checksum is not checked: what we use of that header is fixed
    or covered by the TCP checksum.
- **Port 80**: one response, whatever is asked; a request body is not understood.
- **IPv6**: one address, built in; nothing after the header but TCP (no extension
  headers, no fragments); no answer to duplicate address detection or echo; a neighbour
  solicitation is answered without walking its options (even one with a zero-length
  option, which RFC 4861 says to discard); no MLD report, so a switch that forwards
  solicitations only to registered listeners hides us. Hetzner Cloud's and Linode's
  networks find us; no other host has been tried.
- **DHCP**: an unrenewed address is kept (we ask every 128 s); no check that the
  offered address is unused (no ARP probe, no DECLINE); no RELEASE (we never shut down);
  T1 is half the lease whatever options 58 and 59 say; the first offer is taken; only the
  address is requested or read.
- `keys` writes 20 junk bytes after an IV: the handshake builds both key blocks in `KA`
  and copies them into the slot. The handshake scratch (transcript, key schedule, curve
  registers) is one per processor: one handshake at a time on each, start to finish,
  inside one call of `tcp`.
- Randomness comes from an AES-128 CTR_DRBG without a derivation function. Each processor
  seeds and reseeds it with 32 bytes from RDRAND, checks each raw qword against the previous
  raw qword, and updates the DRBG after every Generate request. It reseeds before request 65.
  The no-DF seed path assumes RDRAND supplies at least the 128 bits of entropy required for
  AES-128 security strength. A failed RDRAND instruction retries indefinitely before returning
  output; a repeated output traps. APs reseed after their BSS copy and mix their processor
  number into the seed material, so they do not retain the boot processor's DRBG state.
- Secrets are not wiped: the next handshake overwrites them, and unused nonces wait in
  the stock (the private key is in the same memory: data, never executed).
- Executable pages hold, besides code, the loader's header, zeros, and `tramp`'s first
  part and ten bytes of its data ("Memory").
