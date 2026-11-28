#!/usr/bin/env bash
# A bottleneck between the guest and the client, for looking at what a response on its
# way does when the path is narrower than the window: so many Mbit/s with a queue of so
# many packets towards the client, and a delay each way. Run inside tap.sh's namespace:
#
#   B=build-bn unshare -Urn ./tap.sh tools/bneck.sh [PATH] [N]
#       (an image with a large file first: python3 tools/mksite.py build-bn/www 6 &&
#        make B=build-bn SITE=build-bn/www NOTSO=1)
#   BRATE=20 (Mbit/s)  BQUEUE=60 (packets)  BDELAY=25 (ms each way)  BLOSS=0 (% lost besides)
#   BREORDER=0% (optional)  BSEED=7 (if supported by the installed tc/netem)
#   CAP=file: capture at the client (tools/tl.py FILE then prints the download's timeline)
#
# It fetches PATH (default /big.bin) N times (3) and says how long each took, client-side
# out-of-order and DSACK counters, and how many packets the bottleneck dropped so far.
# These Linux counters describe the client; k18's TCP sender is its own stack. Use CAP to
# inspect k18 retransmissions with tools/tl.py. (tap - bridge - a veth pair, the bottleneck
# on its near end;
# the client's addresses move to the far end. Use an image built with NOTSO=1: a frame is
# then a segment, and the queue counts what a real one would. Not with tap.sh's own
# DELAY, LOSS or REORDER.)
set -euo pipefail
B=${B:-build-site}
RATE=${BRATE:-20} QUEUE=${BQUEUE:-60} DELAY=${BDELAY:-25} LOSSP=${BLOSS:-0} SEED=${BSEED:-} REORDER=${BREORDER:-}
ip link add vA type veth peer name vB
ip link add br0 type bridge
ip link set br0 type bridge stp_state 0 forward_delay 0
# Save all addresses before clearing the TAP. Deleting its primary IPv4 address
# first can also remove its secondary addresses when promote_secondaries is off.
mapfile -t CLIENT_ADDRS < <(ip -4 -o addr show dev k2t | awk '{print $4}')
ip -4 addr flush dev k2t scope global
for a in "${CLIENT_ADDRS[@]}"; do ip addr add "$a" dev vB; done
ip link set k2t master br0
ip link set vA master br0
for d in br0 vA vB k2t; do ip link set $d up; ethtool -K $d tso off gso off gro off >/dev/null 2>&1; done
L=
[[ $LOSSP != 0 ]] && L="loss $LOSSP%"
S=(); [[ -n $SEED ]] && S=(seed "$SEED")
R=(); [[ -n $REORDER && $REORDER != 0% ]] && R=(reorder "$REORDER" gap "${BGAP:-5}")
tc qdisc add dev vA root netem rate "${RATE}mbit" delay "${DELAY}ms" limit "$QUEUE" $L "${R[@]}" "${S[@]}"   # towards the client
tc qdisc add dev vB root netem delay "${DELAY}ms" limit 10000                         # and back
sleep 1
# (tcpdump is ended by taking its interface away: under its AppArmor profile a signal may not reach it)
if [[ -n ${CAP:-} ]]; then tcpdump -Z root -U -n -i vB -s 80 -w "$CAP" 'tcp port 443' >/dev/null 2>&1 & sleep 1; fi
NAME=$(cat "$B/name"); P=${1:-/big.bin}; N=${2:-3}
CA=(); [[ -s $B/ca.pem ]] && CA=(--cacert "$B/ca.pem")
WANT=$(python3 -c "import json; print(json.load(open('$B/site.json'))['paths']['$P']['sha256'])")
TMP=$(mktemp)
tcpstats() {
  nstat -az 2>/dev/null | awk '$1 ~ /^(TcpExtTCPOFOQueue|TcpExtTCPDSACKOldSent|TcpExtTCPDSACKOfoSent)$/ {print $1, $2}'
}
for _ in $(seq 1 "$N"); do
  declare -A BEFORE=()
  while read -r k v; do BEFORE["$k"]=$v; done < <(tcpstats)
  if ! T=$(curl -s --max-time 120 "${CA[@]}" --interface 10.0.2.32 --connect-to "$NAME:443:10.0.2.15:443" -o "$TMP" -w '%{time_total} s, %{speed_download} B/s' "https://$NAME$P"); then
    echo "$P: download failed"
    exit 1
  fi
  if [[ $(sha256sum < "$TMP" | cut -d' ' -f1) != "$WANT" ]]; then
    echo "$P: $T BUT NOT THE FILE"
    exit 1
  fi
  TCP=()
  while read -r k v; do TCP+=("$k=$((v-${BEFORE[$k]:-0}))"); done < <(tcpstats)
  echo "$P: $T; client TCP ${TCP[*]}; bottleneck qdisc drops=$(tc -s qdisc show dev vA | sed -n 's/.*dropped \([0-9]*\).*/\1/p')"
done
rm -f "$TMP"
if [[ -n ${CAP:-} ]]; then sleep 0.5; ip link del vA 2>/dev/null; sleep 0.5; fi
