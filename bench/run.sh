#!/usr/bin/env bash
# bench/run.sh IP [SECONDS]: the measurements, run on a load generator next to the server
# (from the directory that has build/bench): new connections a second and requests a
# second, over TLS 1.3 (X25519, AES-128-GCM, a full handshake each time, the certificate
# not verified: that is the client's time, not the server's) and over plain HTTP, at
# three numbers of connections in flight.
IP=$1
T=${2:-15}
ulimit -n 1000000
run() {
  local name=$1; shift
  printf '%-34s ' "$name"
  env "$@" T=$T ./build/bench | sed 's/^.* T=[0-9]*: //'
  sleep 3
}
run "https, new connections, 64"   DST=$IP:443 P=8 W=8
run "https, new connections, 512"  DST=$IP:443 P=8 W=64
run "https, new connections, 4096" DST=$IP:443 P=8 W=512
# (as a browser asks: two key shares, X25519MLKEM768 in front, 1.5 KB of ClientHello in two segments)
run "https, new, two key shares, 512" DST=$IP:443 P=8 W=64 KEX='*X25519MLKEM768:*X25519'
run "https, keep-alive, 64"        DST=$IP:443 P=8 W=8 KA=1000000
run "https, keep-alive, 512"       DST=$IP:443 P=8 W=64 KA=1000000
run "http, new connections, 64"    PLAIN=1 DST=$IP:80 P=8 W=8
run "http, new connections, 512"   PLAIN=1 DST=$IP:80 P=8 W=64
run "http, new connections, 4096"  PLAIN=1 DST=$IP:80 P=8 W=512
run "http, keep-alive, 64"         PLAIN=1 DST=$IP:80 P=8 W=8 KA=1000000
run "http, keep-alive, 512"        PLAIN=1 DST=$IP:80 P=8 W=64 KA=1000000
