# Performance TODO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the three measured optimizations in `TODO-performance.md` without weakening the cryptographic or TCP security invariants.

**Architecture:** Deliver one independently reviewable PR per TODO item. Establish a baseline before each change, add focused regression and adversarial tests, then run the project suites and the relevant benchmarks before opening that PR. Keep an item unchecked until its PR is merged and the result is remeasured.

**Tech Stack:** NASM x86-64, C and Python test harnesses, Make, QEMU, GitHub Actions, `make bench`, `bench/run.sh`, and `tools/bneck.sh`.

**Spec:** `TODO-performance.md`

## Global Constraints

- Preserve fail-closed behavior when `rdrand` stalls or repeats; do not substitute unaudited randomness for handshake secrets.
- If software generation is warranted, use the AES-128 CTR_DRBG mechanism and state update/reseed rules in NIST SP 800-90A Rev. 1; seed only from the existing hardware source and keep per-CPU state independent.
- Preserve constant-time cryptographic behavior and validate optimized output against the existing independent crypto vectors.
- Keep TCP state bounded and ensure retransmission never acknowledges data the peer did not receive.
- Compare loss, reordering, shallow-queue, and unconstrained transfer behavior before and after network-path changes.
- Implement each TODO item in its own branch and PR; do not mark an item complete until its PR is merged.

## Review Focus

- RDRAND failure or repeated outputs: retain the stuck-generator fail-stop test and verify all returned draws are distinct from the prior draw.
- Concurrent CPUs consuming per-CPU entropy or retransmit state: verify isolation and bounded state.
- Malformed, duplicate, stale, or reordered TCP SACK data: reject or ignore safely without out-of-bounds memory access or false advancement of the acknowledged offset.
- Timer expiry and connection reuse during loss recovery: ensure stale retransmissions cannot leak data across connection slots.
- Timer arithmetic and burst limits under wraparound or high load: keep pacing bounded and avoid integer overflow or starvation.

---

### Task 1: Reduce handshake random-number generation cost

**Files:** `src/curves.asm`, `test/test_asm.c` or a focused test file, `test/bench.c`, and `TODO-performance.md`.

**Interfaces:** Preserve the `rand` contract: `rdi` points to the output, `ecx` is the number of 64-bit draws, and `rdi` advances by eight bytes per draw. Preserve fail-stop on a zero initial raw hardware draw and on any consecutive repeated raw hardware draw. Reseed every 64 generate requests at most, and reseed each AP after its copied BSS state is installed.

- [ ] Capture baseline RDRAND, full-handshake, and cycles-per-handshake results on available x86 CPUs; record CPU model and run conditions.
- [ ] Add an independent AES-128 CTR_DRBG known-answer test, cover request sizes used by callers, and add repeated/stalled-generator failure checks; run them to verify the regression checks are active.
- [ ] Implement the smallest hardware-backed batching change supported by the measured CPUs; keep retries and health checks for every individual draw.
- [ ] Run crypto vectors, constant-time checks, the RDRAND fail-stop and stall VM tests, multi-CPU handshake tests, and the full CI suite.
- [ ] Compare x86 benchmark results with the baseline and document measured results and any CPU-specific tradeoff.
- [ ] Commit, push, open a PR, and merge only after required checks are green.

### Task 2: Recover multiple lost segments without one RTT per loss

**Files:** To be pinned after tracing the current TCP sender, receive-option parser, retransmit data source, connection slot layout, and `tools/bneck.sh` harness.

- [ ] Specify a bounded SACK representation and parse behavior from the actual receive path; keep malformed option handling fail-safe.
- [ ] Add failing integration tests for one loss, multiple losses, duplicate/stale SACK blocks, reordering, and no-loss controls.
- [ ] Implement selective retransmission from the immutable image and prove connection-slot bounds and wraparound handling.
- [ ] Run the full TCP/TLS suites, fuzzing, and bneck comparisons; report memory per connection, completion time, and retransmissions.
- [ ] Security-review the diff, commit, open a PR, and merge only after required checks are green.

### Task 3: Pace large response bursts on shallow queues

**Files:** To be pinned after tracing the current send loop, timers, CPU clock units, and `tools/bneck.sh` queue model.

- [ ] Add failing tests for a shallow queue, a normal queue, delayed ACKs, timer wraparound, and multiple connections competing for send time.
- [ ] Implement a bounded pacing or burst-cap mechanism using existing clock and per-connection state where safe.
- [ ] Run the full transport suites and compare shallow-queue, lossy, and unconstrained throughput results against the baseline.
- [ ] Security-review the diff, commit, open a PR, and merge only after required checks are green.
