#!/bin/sh
# Compare two k18 revisions on the same pinned x86-64 runner.
set -eu

base_ref=${1:?usage: bench/compare.sh BASELINE_BRANCH_OR_SHA CANDIDATE_BRANCH_OR_SHA}
candidate_ref=${2:?usage: bench/compare.sh BASELINE_BRANCH_OR_SHA CANDIDATE_BRANCH_OR_SHA}
root=$(git rev-parse --show-toplevel)
out=${OUT_DIR:-"$root/benchmark-results"}
if [ "$(uname -m)" != x86_64 ]; then
    echo "native x86-64 runner required; got $(uname -m)" >&2
    exit 1
fi
tmp=$(mktemp -d)
mkdir -p "$out"

cleanup() {
    git -C "$root" worktree remove --force "$tmp/base" >/dev/null 2>&1 || true
    git -C "$root" worktree remove --force "$tmp/candidate" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

resolve_ref() {
    ref=$1
    if printf '%s\n' "$ref" | grep -Eq '^[0-9a-fA-F]{40}$'; then
        git -C "$root" fetch --no-tags origin "$ref"
        git -C "$root" rev-parse --verify "$ref^{commit}"
    elif git -C "$root" check-ref-format --branch "$ref" >/dev/null 2>&1; then
        git -C "$root" fetch --no-tags origin "+refs/heads/$ref:refs/remotes/origin/$ref"
        git -C "$root" rev-parse --verify "refs/remotes/origin/$ref^{commit}"
    else
        echo "expected a branch name or full 40-character commit SHA: $ref" >&2
        return 2
    fi
}
base_sha=$(resolve_ref "$base_ref")
candidate_sha=$(resolve_ref "$candidate_ref")
git -C "$root" worktree add --detach "$tmp/base" "$base_sha" >/dev/null
git -C "$root" worktree add --detach "$tmp/candidate" "$candidate_sha" >/dev/null

cpu=$(python3 -c 'import os; print(min(os.sched_getaffinity(0)))')
{
    printf 'CPU: '; grep -m1 'model name' /proc/cpuinfo | sed 's/^[^:]*: *//'
    printf 'Pinned logical CPU: %s\nBaseline: %s\nCandidate: %s\n' "$cpu" "$base_sha" "$candidate_sha"
} | tee "$out/metadata.txt"

make -C "$tmp/base" B=build build/bench_asm
make -C "$tmp/candidate" B=build build/bench_asm

# Alternate run order to reduce drift from cloud-runner frequency and thermal changes.
for run in 1 2 3 4 5; do
    if [ $((run % 2)) -eq 1 ]; then
        order='base candidate'
    else
        order='candidate base'
    fi
    for side in $order; do
        dir="$tmp/$side"
        printf '\n=== %s run %s ===\n' "$side" "$run" | tee -a "$out/results.txt"
        taskset -c "$cpu" "$dir/build/bench_asm" | tee "$out/$side-$run.txt" | tee -a "$out/results.txt"
    done
done

python3 - "$out" <<'PY'
import glob
import re
import statistics
import sys
from pathlib import Path

root = Path(sys.argv[1])
pattern = re.compile(r"^(.+?)\s+([0-9.]+) us\s+([0-9]+) cycles\s+MAD ([0-9]+) cycles$")
values = {side: {} for side in ("base", "candidate")}
for side in values:
    for filename in glob.glob(str(root / f"{side}-*.txt")):
        for line in Path(filename).read_text().splitlines():
            match = pattern.match(line)
            if match:
                values[side].setdefault(match.group(1), []).append(int(match.group(3)))

rows = []
for name in sorted(values["base"]):
    if name not in values["candidate"]:
        raise SystemExit(f"benchmark missing from candidate: {name}")
    before = statistics.median(values["base"][name])
    after = statistics.median(values["candidate"][name])
    rows.append((name, before, after, 100 * (after / before - 1)))
if not rows:
    raise SystemExit("no benchmark rows parsed")
with (root / "summary.txt").open("w") as f:
    f.write("Benchmark | baseline cycles | candidate cycles | change\n")
    for name, before, after, change in rows:
        f.write(f"{name} | {before:.0f} | {after:.0f} | {change:+.1f}%\n")
print((root / "summary.txt").read_text(), end="")
PY
