# Next Performance Optimizations Implementation Plan

> **For agentic workers:** Steps are tracked here; each change is independently tested and reviewed.

**Goal:** Measure the next crypto and image-layout optimization candidates, retain only safe changes with a repeatable benefit, and submit focused PRs.

**Architecture:** Extend the existing host-side assembly benchmark and add an opt-in x86 A/B runner. Evaluate SIMD HMAC, wider GHASH folding, cached setup for single-record sends, and HOT layout permutations independently. Keep each implementation isolated and require crypto, constant-time, protocol, and image checks before proposing it.

**Tech Stack:** NASM x86-64, C benchmark harness, Python build/test tools, GitHub Actions on Ubuntu x86-64.

**Spec:** User-approved next improvements discussed in chat on 2026-11-28.

## Global Constraints

- Preserve TLS 1.3 AES-128-GCM and HMAC-SHA256 outputs exactly.
- Keep secret-independent control flow and addresses; require existing Valgrind constant-time checks.
- Compare A/B candidates on the same x86 runner and report the processor model and raw results.
- Do not retain a code optimization without measurable benefit and full relevant regression checks.
- Submit a focused PR for each retained change; merge only after required CI passes.

## Review Focus

- HMAC vector reads/writes must cover exactly the 64-byte pad and preserve the 32-byte key plus zero padding.
- GHASH folding must account for every block and keep the final partial-block/length-block behavior unchanged.
- Any per-connection seal cache must not cause key/IV confusion, stale schedule reuse, reentrancy problems, or added key-dependent leakage.
- Layout search must preserve only the two documented fallthrough pairs and test default, IPv4, and IPv6 builds.

## Tasks

### Task 1: Benchmark baseline and A/B runner

- [x] Add HMAC, additional GCM record sizes, and fresh-versus-cached seal timing to the native benchmark.
- [x] Add a manually triggered x86 workflow that builds both refs on one runner and stores raw benchmark output.
- [x] Run baseline self-comparison and verify the runner end to end (AMD EPYC 7763,
  pinned logical CPU 0; workflow exit 0, artifact uploaded; median/MAD output produced).

### Task 2: SIMD HMAC pad transforms

- [x] Add correctness coverage for HMAC lengths 0, 1, 31, 32, 33, 55, 56, 63, and 64 bytes.
- [x] Implement fixed-width pad transforms after same-run A/B showed an improvement.
- [x] Run crypto vectors, constant-time checks, and full CI; PR #30 merged.

### Task 3: Eight-block GHASH experiment

- [x] Add benchmarks for short and long records.
- [x] Implement H^1..H^8 setup and eight-block folding after same-run A/B showed gains for larger cached records.
- [x] Run AES-GCM boundary/Wycheproof tests, constant-time checks, and full CI; PR #31 merged.

### Task 4: Single-record sealing setup reuse

- [x] Compare fresh `seal` with `seal_cached`; trace the single-record send path to determine whether a one-entry cache can hit.
- [x] Reject a cache: the ordinary request path alternates client-key decryption and server-key encryption through the same per-CPU RK/HTAB scratch, so a one-entry cache is displaced on each direction change. `sendrun` already uses `seal_cached` for consecutive records under one key.
- [x] Retain no cache code. Per the user's direction that target-host benchmarking is not needed currently, no end-to-end NIC benchmark was collected; a two-entry cache was not justified by the available evidence and would add more key schedule state.

### Task 5: HOT layout search

- [x] Measure image sizes and HOT alignment across default, IPv4, and IPv6 builds.
- [x] Search all six routine orderings and validate them with the assembler alignment checker; no ordering improved all variants, so none was retained.
- [x] No routine-order PR was warranted. Separately, PR #32 corrected HOT phases after GHASH folding introduced boundary jumps; the merged mask clears the full HOT list in all three build variants.

## Results

- **HMAC, PR #30:** five alternating same-run samples on Intel Xeon 6975P-C showed HMAC-SHA256 improvements of 8.6% (50-byte message) and 7.2% (64-byte message); combined handshake timing was unchanged. Full CI and review passed. Merged as `c8b280f`.
- **GHASH, PR #31:** on Intel Xeon 6975P-C, cached 512/1024/1418-byte records improved 13.2%/15.4%/16.4%; fresh 64/180-byte records regressed 11.0% each, while fresh 512/1024/1418-byte records improved 1.0%/6.3%/7.8%. Combined handshake timing changed by -0.3%. The PR description records the small-record tradeoff. Full CI and review passed. Merged as `d11b12d`.
- **Single-record cache:** no cache was retained for the call-path and scratch-state reasons above. The end-to-end server path was not benchmarked; this remains a limit on workload-specific conclusions.
- **Layout search:** six routine permutations were built in default, IPv4, and IPv6 variants. No ordering reduced image size across all variants. The two best no-warning orders were A/B measured on Intel Xeon 6975P-C and AMD EPYC 9V74; neither had a balanced performance gain.
- **HOT phase correction, PR #32:** same-run AMD EPYC 7763 comparison showed handshake crypto effectively unchanged (161572 to 161569 cycles, -0.0%) and isolated HMAC/SHA slowdowns of 3.3–5.0%; this runner does not model Skylake boundary-jump behavior, so no general speedup is claimed. Default, IPv4, and IPv6 builds and full HOT checks passed; fresh review found no semantic or security changes. Full CI passed before merge. Merged as `beb4fd3`.
