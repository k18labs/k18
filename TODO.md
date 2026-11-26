# TODO

Ordered by priority. Performance and image size work comes first; protocol and tooling edge cases follow.

## 1. Handshake CPU and bulk-sealing performance

### Reduce `straight()` size and work

Target: about 77 fewer bytes and about 5,000 fewer uops per handshake in `straight()` (`step.inc`).

- `fadd19`, `fsub19`, `fsqr`, and `fmul1` preserve `edi`, `esi`, and `ebx`.
- `fmul` preserves `edi` and `ebx`, and sets `esi = ebx`.
- `straight()` currently emits a five-byte `mov reg, REGS + 32*r` before each of the 18 `STEP25519` calls. Track `(edi, esi, ebx)` across those calls to omit repeated loads: Z + T followed by Z - T, T3 + T2 followed by T3 - T2, `ebx = T1` surviving from operation 11 through operation 15, and `edi` on operations 5 and 16. Use two-byte `mov reg, reg` for squarings and chained operands. This loop runs 255 times per handshake.
- In `xdh`, start the ladder at bit 254 instead of 255 (RFC 7748 section 5). Clamping and `byte [rbx+31], 0x7F` always zero bit 255. `STEP25519` on `(1:0)` and `(u:1)` returns `(1:0)` and `(4u^2:4u) == (u:1)`, so the extra step is dead and costs about 370 cycles per handshake.

### Remove `loop` from hot loops on Skylake

Target: eliminate 3,076 microcoded loop iterations per handshake, about 15,000+ cycles or 4% of a roughly 400k-cycle server handshake on Skylake. On Skylake, `loop rel8` uses un-fused microcode at about 6–7 cycles per iteration, compared with about one cycle for fused `dec ecx; jnz`.

- `cswap`: four loops of 255 iterations (1,020 per handshake). Since `R_X` is below 4 GiB, replace `add rdi, 16; loop .s` (6 bytes) with `add edi, 16; dec ecx; jnz .s` (7 bytes), costing one byte.
- `hmac`: 128 loops of 14 iterations (1,792 per handshake). XOR `HB` in qwords or XMM registers, or use `dec ecx; jnz`, to remove the bytewise loops.
- `shaout`: eight loops of 33 iterations (264 per handshake). Replace `loop .o` with `dec ecx; jnz .o`, costing two bytes.

### Reuse sealing setup for bulk TSO records

Target: about 15% faster bulk sealing in `sendrun` and `seal`, for roughly 15–20 bytes of code.

`sendrun` seals up to 45 records back-to-back under the same `[rbp+C_KIV]`, and `bdrain -> prf` does not touch `RK` or `HTAB`. Each `seal` call currently runs `aeskey` and recomputes H..H^4 (`aes4` plus three serial `gh1` calls, about 250 cycles of `seal`'s 1,780 cycles). Add a `seal` entry point that reuses `RK` and `HTAB` for records 2–45.

## 2. Image size: nop elimination

Target: remove most of the 78–96 bytes of HOT padding by reordering standalone crypto routines.

- Every routine in `sha.asm`, `curves.asm`, and `aesgcm.asm` has no fallthrough into it except `shaend -> shablk` and `freeze -> put4`.
- Put narrow-mask `vm` (`HOT 0x03000000`, offsets 24 and 25 only) first to pin the mod-32 phase of everything after it within one byte across default, `IP=`, and `IP6=` builds.
- Interleave non-HOT routines (`sign`, `rand`, `stock`, `binv`, `hmac`, `expand`, `keys`, `sha256`, `ecinit`) to bridge directly into each HOT mask with near-zero nops. Target 50–70 bytes saved with no code changes.
- Trim small instructions where safe: in `aesgcm.asm`, change `mov r8, 0xC200000000000000` (10 bytes) to `push -62; pop r8; shl r8, 56` (8 bytes), saving two bytes; change `add rsi, 16` to `add esi, 16` because `SB` is below 4 GiB, saving one byte.

## 3. Protocol and tooling edge cases

### Port 80 pipelined-request delay

In `tcp.asm`, fix the 200 ms stall between `.quiet` and `.pwait`. If a second port 80 request arrives while a one-segment response (`P80_LEN <= MSS`, `F_DEFER = 0`, `P_MORE = 0`) is unacknowledged, `.pwait` parks it in `oohold` at `OO_SEQ = C_NXT` (kept for the ack). When the pure ACK arrives, `.inord` jumps to `.quiet`, which returns without checking `ooent`; the request remains stuck until the client's 200 ms TCP retransmission timer. Check `ooent` on this path and release the parked request promptly.

### IPv6 SYN-ACK MSS

In `seg.asm`, advertise MSS 1,220 instead of 1,440. The server caps its own IPv6 segments at 1,220 (the 1,280-byte IPv6 minimum MTU) and ignores ICMPv6 Packet Too Big, but currently advertises 1,440 with `sub byte [rbx+57], 20`. Advertising 1,220 (for example `mov word [rbx+56], 0xC404`, one byte larger) avoids 1.5 KB post-quantum ClientHello packets hitting PMTU black holes on PPPoE (1492), WireGuard (1420), and 1280-MTU tunnels.

### CLI edge cases

- `keynew`: `(( ${#1} > 64 )) || subj="/CN=$1"` puts `-n IP` into Subject CN. Let's Encrypt rejects IP CSRs with an IP in CN. Use `(( ${#1} > 64 )) || isip "$1" || subj="/CN=$1"`, or always use `subj=/`.
- `renew`: if a first `renew --force` build fails and `$cert/old/` had no previous `server.key`, `mv "$cert/old/"* "$cert/"` aborts under `set -e` before the host is rebooted out of rescue mode. Ensure cleanup and reboot still happen when the old-key glob is empty.

### Brotli selection in `tools/pack.py`

Evaluate brotli independently of the gzip `worth()` check. Some 1.5–3 KB assets can save a TCP record and at least 10% with brotli even when gzip falls just short. Also only add `br` when it reduces the number of wire segments; adding it for a one-byte win can add a duplicate response and 304 to `site.bin` without reducing segments.
