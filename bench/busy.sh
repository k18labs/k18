#!/usr/bin/env bash
# bench/busy.sh IP [ENV...]: how busy is each of k18's processors while bench runs? For an
# image built with DEBUG=2 (its page on port 80 then ends in the turns its polling loop made
# with nothing to do, and the time). Run where run.sh runs. First three seconds of nothing,
# for the rate that means idle; then bench with ENV, e.g.
#   ./busy.sh 10.0.0.2 PLAIN=1 DST=10.0.0.2:80 P=8 W=64 KA=1000000
# and for each processor that answered before and after, the share of the time in between
# (bench's second of warm-up included) that it was not idle. Making nonces for signatures
# counts as busy: a processor that has just booted, or has just made many handshakes, is busy
# with that for a moment even when nothing comes in.
IP=$1; shift
cd "$(dirname "$0")" || exit 1
ulimit -n 1000000
pages() { for i in 1 2 3 4 5 6 7 8; do curl -s --max-time 5 http://$IP/ | tr -d '\n'; echo; done | sort -u; }
i0=$(pages); sleep 3; i1=$(pages)
a=$(pages)
[ $# -gt 0 ] && env "$@" ./build/bench | sed 's/^.* T=[0-9]*: //'
b=$(pages)
python3 - "$i0" "$i1" "$a" "$b" <<'EOF'
import sys


def parse(t):  # the page's last 24 characters: six counters; its first two hex digits: which processor
    out = {}
    for line in t.split():
        h = line[-24:]
        out.setdefault(int(h[1], 16), []).append((int(h[20:24], 16), int(h[12:16], 16)))
    return out


def rate(a, b, cpu):  # idle turns per cycle between the last fetch before and the first after
    t0, n0 = max(a[cpu])
    t1, n1 = min(b[cpu])
    dt = (t1 - t0) % 65536
    return ((n1 - n0) % 65536) * 4096 / (dt * 2**24) if dt else None, dt * 2**24


i0, i1, a, b = (parse(x) for x in sys.argv[1:5])
for cpu in sorted(set(i0) & set(i1) & set(a) & set(b)):
    idle, _ = rate(i0, i1, cpu)
    got, cycles = rate(a, b, cpu)
    if idle and got is not None:
        print(f"processor {cpu}: {100 * (1 - got / idle):.0f}% busy over {cycles / 1e9:.1f} thousand million cycles "
              f"(idle: a turn in {1 / idle:.0f} cycles)")
EOF
