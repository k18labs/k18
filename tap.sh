#!/usr/bin/env bash
# Boot the image on a tap interface instead of slirp and run a command against it: a real
# Ethernet segment (ARP, the host's own traffic, random initial sequence numbers), and no
# slirp walking every open socket. No root needed inside a throwaway namespace:
# Usage: [B=build] [KVM=1] [SMP=1] [MEM=n] [LOSS=1] [REORDER=25] [DELAY=20] [MTU=n] unshare -Urn ./tap.sh COMMAND [ARGS...]   e.g. ... ./taprunc.sh 2000 1024 4
# (The VM has 2 processors and 256 MiB unless SMP and MEM say otherwise.)
# The host is 10.0.2.2 plus 10.0.2.32-63; the guest is 10.0.2.15: the address its image was
# built with, or the one it is given here by tools/dhcpd.py. DHCPD='COMMAND' in front runs
# another DHCP server in its place; DHCPD=none runs none, and then COMMAND is not kept
# waiting for the guest to answer (it is the server: tools/dhcptest.py), unless STATIC=1
# says that the image has its address (so that such a one is seen to need no server).
# An image with an IPv6 address (make IP6=fd00:15::15: the tests') has the host at
# fd00:15::2 and fd00:15::32 to ::63 as well.
set -euo pipefail
cd "$(dirname "$0")"
export B=${B:-build}
IMG=${IMG:-$B/os.bin}
PORT= source tools/vm.sh
TAP=k2t

ip link del "$TAP" 2>/dev/null || true
ip tuntap add dev "$TAP" mode tap
if [[ -s $B/ip6 ]]; then
  sysctl -q "net.ipv6.conf.$TAP.accept_ra=0" 2>/dev/null || true
  ip -6 addr add fd00:15::2/64 dev "$TAP" nodad
  for i in $(seq 32 63); do ip -6 addr add "fd00:15::$i/64" dev "$TAP" nodad; done
else
  sysctl -q "net.ipv6.conf.$TAP.disable_ipv6=1" 2>/dev/null || true
  ip link set "$TAP" multicast off
fi
ip addr add 10.0.2.2/24 dev "$TAP"
for i in $(seq 32 63); do ip addr add "10.0.2.$i/24" dev "$TAP"; done
ip link set "$TAP" up
# LOSS=n: drop n% of the packets in each direction (host -> guest by netem, guest -> host by
# an ingress filter), and MTU=n sets the tap's MTU (a small one splits the client's segments;
# once the guest answers: a DHCP message is 328 bytes, and no network has to carry less
# than 576)
if [[ -n ${LOSS:-} ]]; then
  tc qdisc add dev "$TAP" root netem loss "$LOSS%"
  tc qdisc add dev "$TAP" handle ffff: ingress
  tc filter add dev "$TAP" parent ffff: protocol ip u32 match u32 0 0 action gact pass random netrand drop $((100 / LOSS))
  tc filter add dev "$TAP" parent ffff: protocol ipv6 u32 match u32 0 0 action gact pass random netrand drop $((100 / LOSS))
fi
# REORDER=n: n% of the packets to the guest overtake the others, which are held 5 ms (not with LOSS)
[[ -n ${REORDER:-} ]] && tc qdisc add dev "$TAP" root netem delay 5ms reorder "$REORDER%"
# DELAY=n: what goes to the guest takes n ms (a round trip of that length; not with LOSS or REORDER)
[[ -n ${DELAY:-} ]] && tc qdisc add dev "$TAP" root netem delay "${DELAY}ms" limit 100000
DPID=
case ${DHCPD-} in
  none) ;;
  "") python3 tools/dhcpd.py "$TAP" >/dev/null 2>&1 & DPID=$!;;
  *) bash -c "$DHCPD" >/dev/null 2>&1 & DPID=$!;;
esac
LOG=$(mktemp)
# MON=path: QEMU's monitor on that unix socket (to ask a guest that hangs where it is)
qemu "${IMG%os.bin}disk.img" "tap,ifname=$TAP,script=no,downscript=no" ${MON:+-monitor unix:$MON,server,nowait} >"$LOG" 2>&1 &
export QEMU_PID=$!
trap 'kill $QEMU_PID $DPID 2>/dev/null || true; wait $QEMU_PID 2>/dev/null || true; ip link del '"$TAP"' 2>/dev/null || true; rm -f "$LOG"' EXIT
[[ ${DHCPD-} == none && -z ${STATIC:-} ]] && { "$@"; exit; }

CURL=(curl -s --max-time 3 -o /dev/null --interface 10.0.2.32 --connect-to "$NAME:443:10.0.2.15:443")
[[ -s $B/ca.pem ]] && CURL+=(--cacert "$B/ca.pem")
up=
for _ in $(seq 1 40); do
  if "${CURL[@]}" "https://$NAME/"; then up=1; break; fi
  sleep 0.25
done
[[ -n "$up" ]] || { echo "FAIL: guest not answering over tap (verified fetch)"; cat "$LOG"; exit 1; }
[[ -n ${MTU:-} ]] && ip link set "$TAP" mtu "$MTU"
"$@"
