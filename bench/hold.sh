#!/usr/bin/env bash
# bench/hold.sh tls|plain N IP: open N connections to the server with tapc (from the
# directory that has build/tapc, build/ca.pem, build/name and www/index.html), each TLS
# connection with the chain and the name verified, and hold them. Prints "all open" and how
# many failed; then waits until the file /tmp/bar/go exists (time to look at the server:
# its memory, say), fetches the page over every connection and prints tapc's summary.
# 60,000 is what one client address has ports for.
#
# (tapc waits at a barrier for the other workers of a larger test; we play the second one.)
ulimit -n 1000000
rm -rf /tmp/bar; mkdir -p /tmp/bar
export B=build NOMARK=1 INFLIGHT=256 TIMEOUT=60
if [ "$1" = plain ]; then export PLAIN=1 DST=$3:80; else export DST=$3:443; fi
./build/tapc 0.0.0.0 2000 "$2" www/index.html /tmp/bar 0 2 > /tmp/bar/out 2>&1 &
while [ ! -e /tmp/bar/opened.0 ]; do sleep 0.5; done
echo "all open: $(grep -c FAILED /tmp/bar/out) failed"
grep FAILED /tmp/bar/out | head -5
while [ ! -e /tmp/bar/go ]; do sleep 0.5; done
touch /tmp/bar/opened.1
while [ ! -e /tmp/bar/verified.0 ]; do sleep 0.5; done
touch /tmp/bar/verified.1
sleep 1
grep FAILED /tmp/bar/out | tail -n +6 | head -5
tail -1 /tmp/bar/out | cut -c1-120
