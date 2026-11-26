#!/usr/bin/env bash
# The image's DHCP client (an image without an address of its own: make without IP=), over tap.
#   unshare -Urn tools/dhcptest.sh        against a server that does what the test wants, right
#                                         and wrong: tools/dhcptest.py has the list (a minute)
#   unshare -Urn tools/dhcptest.sh real   against a server that is not ours, dnsmasq: the image
#                                         must get its address from it and serve on it; a
#                                         lease is two minutes there, so a minute later it must
#                                         have asked to keep the address, have been told yes,
#                                         and still serve (80 s). IFTHERE=1 in front: that
#                                         there is no dnsmasq is no failure (the suite's way).
#   (QEMU's own DHCP server is the third: every test that does not go over tap.)
cd "$(dirname "$0")/.." || exit 1
export B=${B:-build}
[[ -s $B/ip ]] && { echo "FAIL: $B is an image with an address of its own ($(cat "$B/ip"))"; exit 1; }
if [[ ${1:-} != real && -z ${DHCPREAL_IN:-} ]]; then
  exec env DHCPD=none ./tap.sh python3 tools/dhcptest.py "$@"
fi
if [[ -z ${DHCPREAL_IN:-} ]]; then
  if ! command -v dnsmasq >/dev/null; then echo "${IFTHERE:+ok: }not run: no dnsmasq"; [[ -n ${IFTHERE:-} ]]; exit; fi
  LOG=$(mktemp)
  trap 'rm -f "$LOG"' EXIT
  DHCPREAL_IN=$LOG DHCPD="dnsmasq --no-daemon --conf-file=/dev/null --port=0 --user=root --pid-file= --leasefile-ro --no-ping \
    --interface=k2t --bind-interfaces --dhcp-range=10.0.2.15,10.0.2.15,2m --log-dhcp --log-facility=$LOG" ./tap.sh tools/dhcptest.sh real
  exit
fi
# (inside tap.sh: the image has answered a verified fetch, so it has its address)
NAME=$(cat "$B/name")
CURL=(curl -s --max-time 3 -o /dev/null --interface 10.0.2.32 --connect-to "$NAME:443:10.0.2.15:443")
[[ -s $B/ca.pem ]] && CURL+=(--cacert "$B/ca.pem")
bad=0
check() { if [[ $2 == ok ]]; then echo "ok   $1"; else echo "FAIL $1"; bad=1; fi; }
acks() { grep -c 'DHCPACK(k2t) 10.0.2.15' "$DHCPREAL_IN"; }
check "dnsmasq gave it its address, and it serves on it" "$([[ $(acks) == 1 ]] && echo ok)"
for _ in $(seq 1 75); do [[ $(acks) -ge 2 ]] && break; sleep 1; done
check "half the lease later it asked to keep the address, and dnsmasq said yes" "$([[ $(acks) == 2 && $(grep -c 'DHCPREQUEST(k2t) 10.0.2.15' "$DHCPREAL_IN") == 2 &&
  $(grep -c -E 'DHCP(DISCOVER|NAK)' "$DHCPREAL_IN") == 1 ]] && echo ok)"
check "and it still serves" "$("${CURL[@]}" "https://$NAME/" && echo ok)"
[[ $bad == 0 ]] && echo "all ok" || { echo "FAILED"; sed 's/^/    /' "$DHCPREAL_IN" | grep -E 'DHCP[A-Z]+\(' ; }
exit $bad
