#!/usr/bin/env bash
# Run build/tapc on the host, inside ./tap.sh: PER connections from one source IP, every one
# verifying the certificate, all held open and all fetched over at the end.
# Usage: sudo ./tap.sh ./taprunc.sh [PER] [BASE_PORT] [W]   (default: 64512 connections, the
# ports from 1024 up). W > 1 uses W source IPs, which only works with an image that keeps a
# slot table per client IP: this one has one slot per client port. V6=1 in front: over
# IPv6 (an image built with IP6=fd00:15::15), from fd00:15::32 and on.
cd "$(dirname "$0")"
PER=${1:-64512} BASE=${2:-1024} W=${3:-1}
export B=${B:-build}
[[ -x $B/tapc && $B/tapc -nt tools/tapc.c ]] || gcc -O2 -o "$B/tapc" tools/tapc.c -lssl -lcrypto || exit 1
ulimit -n $((PER + 200)) || exit 1
D=$(mktemp -d)
mem() { awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo; }
( while sleep 15; do
    A=$(mem)
    if [ "$A" -lt 1800 ]; then echo "  [memory guard: $A MiB left, stopping workers]"; pkill -x tapc; break; fi
  done ) &
MON=$!
PIDS=()
NET=10.0.2.
[[ -n ${V6:-} ]] && NET=fd00:15::
for ((w=0; w<W; w++)); do
  "$B/tapc" "$NET$((32+w))" "$BASE" "$PER" www/index.html "$D" "$w" "$W" > >(tee -a "$D/out") &
  PIDS+=($!)
done
wait "${PIDS[@]}"
kill $MON 2>/dev/null
sleep 0.2
CONN=$(awk '/^RESULT/ { if ($7 == $9) n += $9; else bad = 1 } END { print bad ? 0 : n + 0 }' "$D/out")
SIZE=$(stat -c %s "$B/os.bin")
python3 -c "print(f'SCORE {$CONN / ($SIZE / 1024):.1f}  = $CONN connections / $SIZE bytes (over tap)')"
rm -rf "$D"
