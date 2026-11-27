# Performance TODO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new actionable performance TODO list based on measured k18 bottlenecks.

**Architecture:** Create one top-level performance TODO document that follows the existing prioritized style and cites the benchmark baselines in prose. Keep `TODO.md` and runtime code unchanged.

**Tech Stack:** Markdown, Git.

**Spec:** `docs/superpowers/specs/2026-11-27-performance-todo-design.md`

## Global Constraints

- Keep priorities, measured targets, and implementation constraints in the style of `TODO.md`.
- Include only the approved areas: RNG cost, TCP loss recovery, and pacing on shallow queues.
- Treat current benchmark numbers as baselines, not promised gains.
- Preserve the RNG health checks and nonce freshness; evaluate TCP changes against connection-state and throughput costs.
- Make no code or CI changes.

## Review Focus

- Completed backlog item repeated as future work: verify against current TODO and merged history.
- Baseline copied without its hardware/path conditions: include the conditions from `bench/README.md`.
- Unmeasured improvement presented as guaranteed: phrase each target as a measurement or an investigation.
- RNG optimization implying weaker randomness: explicitly retain health checks and freshness.
- TCP recovery or pacing improving one case while harming another: require both lossy/shallow-queue and high-throughput comparisons.

---

### Task 1: Add the performance TODO list

**Files:**
- Create: `TODO-performance.md`
- Reference: `TODO.md`
- Reference: `bench/README.md`

**Interfaces:**
- Consumes: Current performance baselines and constraints documented in `bench/README.md`.
- Produces: A prioritized standalone list covering RNG cost, selective loss recovery, and pacing/burst sizing.

- [ ] **Step 1: Draft the three priorities**

Use the measured RNG costs (12 draws per handshake; 3,530 cycles per 64 bits on Zen 2 and 288 on Skylake), the 6 MiB lossy-path timing (14–19 seconds at 20 Mbit/s, 50 ms RTT, 1% loss), and the shallow-queue timing (34 seconds with a 10-packet queue and 50 ms RTT). Include implementation constraints and a measurable comparison for each.

- [ ] **Step 2: Review for overlap and unsupported claims**

Compare the new items with `TODO.md` and merged work. Confirm every number and condition matches `bench/README.md`; phrase unmeasured benefits as goals to test.

- [ ] **Step 3: Check the document diff**

Run: `git diff --check`
Expected: no whitespace errors. Review the Markdown against the approved design.

- [ ] **Step 4: Commit and push for review**

```bash
git add TODO-performance.md docs/superpowers/specs/2026-11-27-performance-todo-design.md docs/superpowers/plans/2026-11-27-performance-todo.md
git commit -m "docs: add performance optimization TODO"
git push -u origin <feature-branch>
```

Open a pull request against `main`; do not change runtime code in this work.
