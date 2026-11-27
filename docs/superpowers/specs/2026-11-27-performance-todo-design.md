# Performance TODO design

## Intent

Add a focused list of future k18 performance work, grounded in current benchmark notes. Keep
the existing `TODO.md` intact because it also tracks earlier protocol, tooling, and governance
work.

## Goals

- Create `TODO-performance.md` in the style of the existing prioritized TODO: priorities,
  measured baselines, concrete targets, and implementation constraints.
- Include only work supported by current repository measurements: random-number generation
  cost, TCP loss recovery for large transfers, and pacing on shallow queues.
- Preserve the security and memory constraints already documented for k18.

## Non-goals

- Implement any runtime optimization in this change.
- Reclassify, remove, or mark completed items in `TODO.md`.
- Promise performance gains before a change is measured on representative hardware.

## Approaches

- Append to `TODO.md`: keeps a single file, but mixes the next optimization backlog with
  earlier work that has since been completed.
- Add `TODO-performance.md` (selected): makes the new priorities easy to review without
  rewriting or reclassifying the existing list.

## Proposed contents

1. Measure and reduce `rdrand` cost on slower supported CPUs while preserving per-handshake
   randomness health checks and nonce freshness.
2. Explore selective loss recovery for large transfers, using the existing lossy-path
   measurements and retaining the small per-connection state target.
3. Evaluate pacing or burst-size changes for shallow queues, measuring both completion time
   under loss and high-throughput regressions.

## Delivery

Commit the design and new list on a feature branch, open a pull request, and push it to
`k18labs/k18`. Do not implement code changes as part of this documentation task.
