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

- [ ] Add correctness coverage for HMAC message lengths at the boundaries and full 64-byte input.
- [ ] Implement fixed-width pad transforms only if same-run A/B results improve.
- [ ] Run crypto vectors, constant-time checks, and full CI; submit a focused PR.

### Task 3: Eight-block GHASH experiment

- [ ] Add benchmarks for short and long records.
- [ ] Implement H^1..H^8 setup and eight-block folding behind a validated path only if results improve.
- [ ] Run AES-GCM boundary/Wycheproof tests, constant-time checks, and full CI; submit a focused PR.

### Task 4: Single-record sealing setup reuse

- [ ] Measure `seal` versus `seal_cached` and the end-to-end single-record send path.
- [ ] Design a cache only if measurements justify it and key lifetime, processor ownership, and invalidation can be proved.
- [ ] If safe and beneficial, add explicit cache-miss, key-change, and reuse tests; otherwise document why no code change is retained.

### Task 5: HOT layout search

- [ ] Measure current image sizes and HOT padding across default, IPv4, and IPv6 builds.
- [ ] Search safe routine orderings and validate all candidates with the existing assembler alignment checker.
- [ ] Submit a focused PR only if all variants improve without changing behavior.
