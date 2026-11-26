#!/usr/bin/env bash
# A response on its way through a path that is narrower than the window (tools/bneck.sh):
# 6 MiB through 20 Mbit/s with a queue of 60 packets and a round trip of 50 ms, and through
# 5 Mbit/s with a queue of 30 and a round trip of 100 ms, twice each. They must arrive as
# they are, and in no more than 8 s and 20 s: about what a window of 64 KB and no more
# takes there (5.2 s and 13.1 s, measured with the image that had no window scaling; this
# one takes 4.3 s and 12.4 s). A sender that lets a large window loose on such a path, or
# mends what is lost a timer at a time, takes 20 s and more for the first.
cd "$(dirname "$0")/.." || exit 1
export B=${B:-build-bn}
mkdir -p "$B"
python3 tools/mksite.py "$B/www" 6 >/dev/null || exit 1
make -s B="$B" SITE="$B/www" NOTSO=1 >/dev/null || { echo "BUILD FAILED"; exit 1; }
bad=0
shape() {  # rate, queue, delay, seconds allowed
  local out
  out=$(BRATE=$1 BQUEUE=$2 BDELAY=$3 timeout 200 unshare -Urn ./tap.sh tools/bneck.sh /big.bin 2 2>&1 | grep '^/big.bin')
  while read -r line; do
    t=$(sed -n 's/^\/big.bin: \([0-9.]*\) s.*/\1/p' <<<"$line")
    if [[ -n $t && $line != *"NOT THE FILE"* ]] && python3 -c "import sys; sys.exit(0 if float('$t') <= $4 else 1)"; then
      echo "ok   $1 Mbit/s, a queue of $2, $((2 * $3)) ms: $t s (no more than $4)"
    else
      echo "FAIL $1 Mbit/s, a queue of $2, $((2 * $3)) ms: ${line:-nothing came}"; bad=1
    fi
  done <<<"$out"
}
shape 20 60 25 8
shape 5 30 50 20
exit $bad
