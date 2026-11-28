# Performance TODO

Ordered by measured opportunity. Baselines are from `bench/README.md`; they are starting
points for comparison, not promised gains.

## 1. Reduce random-number generation cost on slower supported CPUs

**Status: implementation merged in PR #22; optional Zen 2 and Skylake benchmarks are deferred.**

Target: reduce the roughly 42,000 cycles of `rdrand` work per handshake measured on Zen 2,
without weakening nonce freshness or the existing stuck/repeated-output health check.

A handshake draws twelve 64-bit values. One draw costs about 3,530 cycles on Zen 2, 288 on
the Skylake cx23, and 41 on EPYC Milan. Measure where the time goes on each supported CPU,
then evaluate batching or another hardware-backed approach. Any design that adds a software
generator needs a reviewed reseed and failure model before it is used for handshake secrets.

Compare full-handshake throughput and cycles per handshake on Zen 2 and Skylake before and
after. Keep the crypto vectors and constant-time checks passing, and verify that a stalled or
repeating hardware source still prevents a handshake from using weak randomness.

## 2. Recover multiple lost segments without waiting one round trip per loss

**Status: implementation and SACK cursor field fix merged in PRs #23 and #25.** The
6 MiB, 1% loss comparison improved from a 20.75 s
baseline median to 17.68 s on ARM64 WSL/QEMU TCG; this is an emulated result, not a cx23
measurement. The cursor uses unused AES-128 client-key bytes, separate from RTT and RTO state,
so connection-slot size is unchanged. CI transfer cases pass SHA-256 checks for queue-10,
large-queue, 0.25% and 1% loss, and reordering. Target-CPU timing is deferred.

Target: shorten large-transfer completion time on lossy paths while keeping connection state
small.

Before PR #23, k18 did not use SACK. When several segments were lost in one window, it repaired
them one round trip at a time. In the current 6 MiB tests, a 20 Mbit/s path with a 200-packet queue,
50 ms round trip, and 1% loss takes 14–19 seconds. Explore SACK or another compact way to
identify missing segments and selectively rebuild them from the image.

Measure completion time and retransmissions with the existing `tools/bneck.sh` cases. Include
single-loss, multiple-loss, reordering, and no-loss controls. Keep the per-connection memory
budget explicit and confirm recovery does not resend data the client already has.

## 3. Pace large response bursts for shallow queues

**Status: emulated evaluation complete; no sender change retained. Optional cx23 validation is deferred.**

Target: reduce loss and completion time on shallow-queue paths without reducing throughput on
well-provisioned paths.

The sender does not pace large bursts. The 6 MiB test takes 34 seconds with a 10-packet queue
and 50 ms round trip, compared with 4.3 seconds at 20 Mbit/s, a 60-packet queue, and the same
round trip. Evaluate pacing or a smaller burst size using the existing bottleneck tests before
changing the send path.

Compare the shallow-queue and lossy cases with the current 64-connection large-file result
(about 1.2 GB/s on the measured cx23). Keep changes only if they improve the constrained paths
without a material regression on the high-throughput path.

ARM64 Kali WSL/QEMU TCG queue-10 runs took 34.48 and 36.67 seconds; the 36.67 s run was a clean
baseline collected after restoring the sender. An
ACK-based burst cap took 113.42 seconds; one-tick pacing took 34.75 seconds; five-tick pacing
took 46.47 seconds. These timings are emulated and the experimental runs did not include a
verified file hash, so they are directional only. None showed a queue-10 gain worth keeping.
CI includes queue-10 and large-queue no-loss controls, sparse and 1% loss cases, and queue-60
reordering as correctness and file-integrity checks. Revisit only with a pacing signal
that can distinguish path capacity from delay and queue pressure, then remeasure against the
cx23 large-file result before retaining a change.

## 4. Reduce fresh short-record AES-GCM overhead

**Status: eight-block GHASH folding merged in PR #31. A same-run comparison found fresh
64-byte and 180-byte records about 11% slower; no short-record alternative has been tested.**

Target: keep the measured medium and large-record gains while reducing setup cost for short,
freshly sealed records.

On an Intel Xeon 6975P-C, the H^1..H^8 implementation improved fresh 512/1024/1418-byte
records by 1.0%/6.3%/7.8% and cached records of those sizes by 13.2%/15.4%/16.4%. Fresh
64-byte and 180-byte records slowed by 11% each. Cached 64-byte records were unchanged,
while cached 180-byte records improved by 5.2%. The combined handshake benchmark changed by
-0.3%, within noise. See [the same-run benchmark](https://github.com/k18labs/k18/actions/runs/46113754716).

Evaluate a smaller GHASH fold or reduced H-power setup for short records, with the path
selected only from public record length; retain the eight-block path for larger records if
the measurements support it. Compare fresh and cached 64/180/512/1024/1418-byte records and
the combined handshake on the same pinned CPU. Cover lengths around each dispatch and block
boundary, partial final blocks, and multi-group records with the independent AES-GCM tests,
Wycheproof, and constant-time checks. Keep a candidate only if the short-record gain exceeds
measurement noise without a material regression in larger records, bulk cached sealing,
handshake timing, or image size.
