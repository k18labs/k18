# Pitfalls, and what was tried and rejected

One or two lines each. Add to it when something costs an hour; delete what stops being true.

## Shell and tools
- `pkill -f pattern` and `pgrep -f pattern` match the shell that runs them, also over
  ssh. Use `pkill -f "holdloo[p]"`, or a pid file.
- Long shell commands with a here-document can be refused: write a script file and run it.
- `perf` is not allowed here unless the user allows it (`kernel.perf_event_paranoid`).
  Time code with `make bench`, or count cycles in the guest (`DEBUG=1`).
- `GROUPS=x command` passes nothing: bash reserves that name. Hence `KEX`.
- Don't rewrite a script bash is running, or edit what a background run uses.
- `tcpdump` in tap.sh's namespace can't be killed from this shell; it exits when its
  interface is deleted (`ip link del`). Use a packet socket in Python instead.
- tc: `action gact drop random netrand drop 100` drops everything. Use
  `gact pass random netrand drop 100`.
- Snap Firefox can't start through its launcher: `tools/ffcheck.py` runs the binary.
- `crontab` can't be written from Claude's shell. Use a systemd user timer.
- Hetzner's web console garbles `|` and `[`: use ssh. Give a load generator its own
  known-hosts file: a recycled cloud address has an old host key.
- WSL exports the machine's name as NAME to every shell: make ignores a NAME from the
  environment that equals the host name (not tested on WSL).
- `'$(VAR)'` in a recipe is not quoting: a `'` in the value silently ends it (a
  Content-Security-Policy lost its `'self'`). Pass user text through the environment
  (`export`, `"$$VAR"`), also from `k18` to make, whose command line expands a `$`.
- make can't take file names with spaces as prerequisites.

## nasm
- A non-local label ends the scope of `.local` labels. Read the first error.
- `K2`, `st4`, `XEND`, `XBEGIN`, `XTEST` are registers or instructions, not names.
- An `equ` used before it is defined costs passes until nasm gives up.
- A plain number is not addressed relative to rip; a label plus a number is.
- nasm deletes its output when it fails: with `-o /dev/stdout` as root that is the
  device, and the next build writes the image, key included, into a regular file of
  that name. Assemble into a file.
- The load address is a number too (`DELTA`): `org` needs it on the first pass, so
  anything that depends on where the code ends needs a separate assembly to find it.

## QEMU and the tests
- QEMU keeps the image open: rebuilding under a running VM changes nothing.
- make does not notice a changed `DEBUG`, `DHMAX` and the like (its `made` says what
  was built): use another `B=` or `-o` per set of variables.
- slirp is slow and serial: one connection in 20 waits a second when they arrive less
  than 2 ms apart, and it walks every socket. Load tests go over tap.
- Every guest processor polls: `top` shows 100% whatever the load.
- A hung test leaves a `qemu-system` spinning. Killing a load client leaves its sockets,
  and the forwarded port, in TIME-WAIT for a minute.
- netem drops a whole GSO packet as one loss, and a Linux client whose first flight is
  lost retries after 3 s, then 6 s: at 5% loss a handshake can exceed a 20 s timeout.
- For a rare failure, run the lossy test 16 times, and as many on the last commit.
- A test knob can break what it tests: forcing all upper bits of the initial sequence
  number removed the SYN cookie's meaning. Check a control far from the edge.
- A test's client is a TCP with its own rules: Linux accepts a RST only at exactly the
  next sequence number it expects, and a connection that only ever got a SYN-ACK is
  re-created by its next packet. Watch the wire, not the sockets.
- A new connection's answer must start at exactly its initial sequence number + 1: one
  client's cookies are multiples of 2^14 apart, and the old connection's look the same.
- Test whether clients are told apart with a small table: with millions of slots they
  never collide, and "every client is the same client" passed 30,000 connections.
- A test's server must not say "yes, for a year" by accident: random DHCP answers
  silenced the client they were meant to exercise, and the test read 150 of 13,000.
- A test that shows a byte can't be executed must execute a `ret` (anything else faults
  either way), in a site that begins right where the code ends (`tools/wxtest.sh`).
- `-device loader,addr=A,data=D,data-len=N` puts bytes in guest memory before the BIOS
  runs; `-action shutdown=pause` stops a machine with its memory still readable.
- Test ports are shared with the suite: a QEMU that failed to start looked like a
  machine that had halted. "It ended" must mean: by itself, with no output, status 0.
- A test written beside the code knows what the code knows. Vectors from elsewhere, and
  reviewers not told why a fix is right, found what such tests missed (a small-order
  X25519 point, a key file's pasted public key, two faults beside the slot race).

## Code
- Compare sequence numbers by the sign of their difference (`js`/`jns` after `sub`),
  never with `jl`/`jle`: those break where a segment straddles 2^31.
- `mulx` leaves 64 bits in rcx: `mov cl, n` after it is not a count.
- A register is not "still zero" after a call that returns something in it, or whose
  comment just says "clobbers esi" (`find` wrote an IPv6 client's identity through esi
  into the hash). A helper called from a waiting loop must not touch its registers.
- r8 to r15 are the crypto's scratch registers, secret until set: set a register before
  it goes into a frame (a DHCP REQUEST carried r9 as its server identifier).
- Memory we did not zero is not zero: the transmit lock in low memory; the page at
  0x8000, which the boot sector reads the image through, held its last piece, site
  included. Zero what is made executable first.
- BSS is per processor. Shared state goes in low memory. The table space must begin on
  a 2 MiB boundary.
- Shared state that changes in more than one step is changed by one processor only, or
  in one step: the DHCP client's three words were written by whichever processor got
  the answer. Frames that change it go to one processor (`drain`).
- A count is no bound for a later walk once another processor can change it in between
  (`find`: the free slots of a bucket). Every walk needs its own bound.
- A rare race is still a race: a host can take a processor away for milliseconds at any
  point. Close it, and make the test hold one side still (`RACE=n`, `tools/racetest.py`).
- A processor with no work must not do the idle work either: its share of a shared
  table belongs to another processor (`tidle`, with three processors).
- A processor has an interrupt table unless given an empty one: ask QEMU (`info
  registers -a`) what each has.
- No GPT on the disk: its backup belongs in the disk's last sector, which the image
  can't know and where `k18` keeps the machine's identity, and firmware that misses it
  writes one there (OVMF does). An MBR partition of type 0xEF is used instead.
- UEFI: where the image goes is not free while the firmware runs (OVMF holds 8 MiB to
  past 20 MiB), and its page tables are still in use after it exits: `src/efi.asm`
  copies the image last, paging off. `start` writes to its read-only pages before it
  sets CR0.WP, so WP must be clear on entry.
- An EFI application that returns an error to OVMF is started again, and what it
  allocated the first time is still taken.
- Check the sequence number before the ack: with any sequence number, a forged ack
  moved `C_ACK` and ended one response in ten thousand.
- Compare a length before subtracting from it: `sub ecx, 20` / `cmp ecx, 20` let an IP
  total length below 20 pass as 4 GiB, and one frame crashed the machine. What a router
  would have dropped still arrives from the same link (`tools/rawtest.py`).
- Bound an echoed length where it is read: a session ID over 32 bytes was echoed with
  lengths that wrapped at 256. A frame shorter than what is read of it exposes the
  previous frame: a short ARP request was answered from that.
- Find the key share by walking the ClientHello: extensions come in any order, and
  searching for its first four bytes failed once in two million handshakes.
- Clients send a ChangeCipherSpec record before their second ClientHello.
- What one timer sends unprompted, other code takes as a signal: the SYN-ACK resent
  after 0.25 s makes a client 300 ms away ack twice, and a "flight sent twice gives no
  round-trip sample" rule left exactly those clients without one. Test at the round
  trip the change is about (`DELAY=300`).
- Waiting to send is no reason not to receive: drain the device's ring from every
  waiting loop. Under overload, frames wait in deep rings of our own, not the device's.
- Whatever is random in a request is made new for each request: a renewal nobody
  answered repeated forever with the same transaction ID.
- rdrand's success flag proves nothing: some processors sold in 2019 returned all ones
  every time, with success. `rand` compares each draw with the previous one.
- A segment that ends past the edge of the client's window is not "mostly taken":
  Linux since 6.17 drops it whole while it has data unread. Rounding what may go up to
  whole records lost the last one of every burst that the window limited, which three
  acks later was a loss: half the window and `F_CA`, for good. Round down.
- A window update is an ack that repeats. Taken for one more sign of a loss already
  seen to, it was ignored, and a client that read again after a pause waited for our
  timer, up to 16 s. And the frame the timer kept is as old as its arming: let nothing
  new go by its window.
- A client can be further on than we expect it and mean it: a request we would not take
  yet (`tcp.busy`) leaves it there until it sends that again, and all its acks come as
  early segments. What an ack says of our data does not depend on where it comes from.

## Measuring
- Over tap, QEMU's packet path is the limit; on the server, the host's network path
  (bench/README.md). Neither can be seen from the guest.
- The load generator's `nstat` names the trouble: SynRetrans (a SYN or its answer
  lost), TCPTimeouts (data), TcpInErrs (a SYN-ACK of ours resent).
- A step at 1 s in the latencies is a SYN, at 200 ms a segment. A smooth tail is a queue.
- Two fetches over a lossy path say nothing: 6 MiB at 1% loss took 14 to 25 s with the
  same image. Use nine or more fetches each before changing a rule.
- A grade is what the grader says today: compare with a site that has it before
  writing down why.
- tlsfuzzer's scripts fail early on our shortcuts (`tools/tlsfuzz.py`). It shows that
  the server stays up, and another implementation checks every signature and tag.
- A connection that fails at once from here is ours: another program has the port. Use
  base ports below 32768.
- `rdrand` costs 3,530 cycles on a Zen 2, 288 on a Skylake server, 41 on an EPYC-Milan.
  `perf` charges it to the instructions after it.
- A routine timed in a loop of its own is not the routine in a handshake: P-256's
  addition took 715 or 799 cycles by what `make bench` timed before it. Time two
  versions in turn (`make bench` has the line), each several times, on one core.
- Where a jump lies can cost 6% on Skylake and nothing on Zen 2 (`HOT`); a mask after
  `HOT` can be stale while the routine happens to sit well. On AMD, where `vm` begins in
  a 64-byte line moves a signature by 5,000 cycles in `make bench`, yet made no
  difference under load on an EPYC-Rome server: check such gains under load.

## Operating
- A tool meant for cron must do nothing on most days, and say so.
- A key stays where it is made: only a request travels to the server.
- After a deploy, check the headers of every kind of answer (200, 404, 301, 405).
- Which certificates a chain can do without depends on other people's trust stores,
  not this machine's.
- Content-Type for extensions `pack.py` doesn't know comes from Python's own table, not
  /etc/mime.types: otherwise the same site packs differently on another machine.
- A rescue system's ssh host keys prove nothing, and neither does a key file (`openssl
  pkey -pubout` prints the public key written in it, unchecked): ask for a signature
  (`proves`). Until then, nothing secret goes to the machine.
- Taking a machine down is the last step that can still be refused: what can be known
  before is checked before; what can only be known after restarts the machine on a no.
- `dd of=FILE` truncates a file to what it writes but leaves a disk its length: use
  `conv=notrunc`, so a test with a file for a disk sees what a disk would.

## Tried and rejected
- Compressed EC point in the leaf (Firefox refuses); subjectAltName not critical with an
  empty subject (Chrome); empty issuer (curl, Firefox); CA and leaf with one serial (NSS).
- virtio multiqueue: the server's card has one queue pair.
- `pdep` to mask without touching the carry: slow on Zen 2.
- Ephemeral secrets derived from a boot key, or a key share reused for a time window:
  lower forward secrecy.
- Mixing the private key into every nonce through SHA-256: `stock` runs inside a
  handshake whose hash state it would need.
- Restricting acks to data and FIN segments: a forged ack still moved `C_ACK`.
- The SYN-ACK timer on every frame: under load it fired for clients whose answer was
  waiting in our ring. It runs when idle.
- Dropping SYNs first when a ring fills: the wait moves into the clients' SYN timers.
- A fixed 10 segments in flight instead of congestion control: 14 KB per round trip.
- The data timer in the SYNs' table: a SYN flood would push real timers out.
- Delaying the ack of a request for a long response: clients give up after seconds of
  unacknowledged data.
- A window that doubles past 64 KB without SACK: it loses dozens of segments where the
  path is narrower, recovered one per round trip. It grows slowly instead.
- Using a client's SACK information without keeping it: Linux bunches its acks, and
  D-SACK looks the same.
- Three bits for the client's window shift: Linux sends 10. Four bits.
- `vm` dispatching through a table of addresses (one call, one jump back): the indirect
  call is predicted worse than the jumps, and signatures were slower.
- A squaring with two carry chains throughout, as in OpenSSL: the same cycles, 75 bytes
  more (docs/internals.md, "The order of a program's operations").
- Squarings only in the X25519 programs: timed in turn with X25519, P-256's addition is
  the same (it only seemed slower in a loop of its own).
