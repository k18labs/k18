# Performance TODO

Ordered by measured opportunity. Baselines are from `bench/README.md`; they are starting
points for comparison, not promised gains.

## 1. Reduce random-number generation cost on slower supported CPUs

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

Target: shorten large-transfer completion time on lossy paths while keeping connection state
small.

k18 does not use SACK. When several segments are lost in one window, it repairs them one
round trip at a time. In the current 6 MiB tests, a 20 Mbit/s path with a 200-packet queue,
50 ms round trip, and 1% loss takes 14–19 seconds. Explore SACK or another compact way to
identify missing segments and selectively rebuild them from the image.

Measure completion time and retransmissions with the existing `tools/bneck.sh` cases. Include
single-loss, multiple-loss, reordering, and no-loss controls. Keep the per-connection memory
budget explicit and confirm recovery does not resend data the client already has.

## 3. Pace large response bursts for shallow queues

Target: reduce loss and completion time on shallow-queue paths without reducing throughput on
well-provisioned paths.

The sender does not pace large bursts. The 6 MiB test takes 34 seconds with a 10-packet queue
and 50 ms round trip, compared with 4.3 seconds at 20 Mbit/s, a 60-packet queue, and the same
round trip. Evaluate pacing or a smaller burst size using the existing bottleneck tests before
changing the send path.

Compare the shallow-queue and lossy cases with the current 64-connection large-file result
(about 1.2 GB/s on the measured cx23). Keep changes only if they improve the constrained paths
without a material regression on the high-throughput path.
