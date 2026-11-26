#!/usr/bin/env bash
# The regression runs, a few at a time, one line each: what CLAUDE.md's Workflow asks for
# after a change to TLS, TCP, the tables, the driver or the polling loops.
#
#   tools/suite.sh [JOBS] [name...]      (default: 4 at a time, all of them)
#   SMP=1 tools/suite.sh                 (the VMs have 2 processors unless SMP says otherwise)
#
# A run is "ok" only if every connection in it worked. The logs stay in $LOGS (default: a
# directory in /tmp that the last line names). Runs that overflow rings on purpose
# (raw1m_20k) can time out a few connections in a million when the host is this busy: run
# such a one alone (`tools/suite.sh 1 raw1m_20k`) before believing it. Rare failures
# (1 in thousands of lossy handshakes) need many runs: `tools/suite.sh 4 real_loss3
# real_loss3 real_loss3 ...` does not repeat a name; loop over it instead.
cd "$(dirname "$0")/.." || exit 1
JOBS=${1:-4}
shift
WANT=" $* "
LOGS=${LOGS:-$(mktemp -d /tmp/k18-suite.XXXXXX)}
mkdir -p "$LOGS"

# (The clients offer the suites in OpenSSL's own order, AES-256-GCM, ChaCha20-Poly1305,
# AES-128-GCM, and get the last: ours.)
RUN='unshare -Urn ./tap.sh ./taprunc.sh 500 1024 4'
TLS="$RUN"
declare -A T
T[measure]='./measure.sh'
T[measure_tcg]='KVM=0 PORT=8453 ./measure.sh'
# the same disk started by UEFI firmware (src/efi.asm; OVMF has to be there: tools/vm.sh),
# and one whose image is longer than 2 MiB
T[measure_efi]='EFI=1 PORT=8533 ./measure.sh'
T[site_efi]='EFI=1 NOBUILD=1 PORT=8543 tools/sitetest.sh'
T[browsers]='./browsers.sh'
T[tls]="$TLS"
T[tls_loss3]="LOSS=3 $TLS"
T[tls_mtu300_loss3]="MTU=300 LOSS=3 $TLS"
T[tls_reorder]="REORDER=25 $TLS"
T[plain]='PLAIN=1 INFLIGHT=64 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
T[plain_loss3]='PLAIN=1 INFLIGHT=64 LOSS=3 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
T[plain_mtu300_loss3]='PLAIN=1 INFLIGHT=64 MTU=300 LOSS=3 unshare -Urn ./tap.sh ./taprunc.sh 2000 1024 4'
T[plain_reorder]='PLAIN=1 INFLIGHT=64 REORDER=25 unshare -Urn ./tap.sh ./taprunc.sh 2000 1024 4'
# the same clients twice (same addresses, ports, sequence numbers), not having closed
T[twice]='unshare -Urn ./tap.sh sh -c "build/rawc 200000 && build/rawc 200000"'
T[twice_reorder]='REORDER=25 unshare -Urn ./tap.sh sh -c "build/rawc 50000 && build/rawc 50000"'
T[raw1m]='unshare -Urn ./tap.sh build/rawc 1000000'
T[raw1m_20k]='unshare -Urn ./tap.sh build/rawc 1000000 20000'
T[raw_4g]='MEM=4096 unshare -Urn ./tap.sh build/rawc 2000000'
T[tls_4g]="MEM=4096 $TLS"
T[churn]='B=build-small FLOOD=20000 unshare -Urn ./tap.sh python3 tools/churn.py'
T[churn_idle]='B=build-small-idle unshare -Urn ./tap.sh python3 tools/churn.py 64 3000'
# a connection that has long been quiet gives way when there is no room, and only then
# (an image in which "long" is two minutes; three minutes)
T[idle]='B=build-small-idle1 unshare -Urn ./tap.sh python3 tools/idletest.py'
T[real_measure]='B=build-real CERT=cert-real PORT=8463 ./measure.sh'
T[real_loss3]="B=build-real LOSS=3 $TLS"
T[real_mtu300_loss3]="B=build-real MTU=300 LOSS=3 $TLS"
T[real_reorder]="B=build-real REORDER=25 $TLS"
# clients that have to be asked for an x25519 key share (HelloRetryRequest)
T[hrr]="KEX=P-256:X25519 $TLS"
T[hrr_loss3]="KEX=P-256:X25519 LOSS=3 $TLS"
T[hrr_mtu300_loss3]="KEX=P-256:X25519 MTU=300 LOSS=3 $TLS"
T[hrr_reorder]="KEX=P-256:X25519 REORDER=25 $TLS"
T[real_hrr_loss3]="KEX=P-256:X25519 B=build-real LOSS=3 $TLS"
# an image as for a real site: a DNS name, port 80 redirects, HSTS
REDIR='B=build-redir CERT=cert-redir NAME=k18.test P80=redirect HSTS=63072000'
T[redirect]="$REDIR PORT=8473 ./measure.sh"
T[raw_redirect]='B=build-redir unshare -Urn ./tap.sh build/rawc 200000'
# Sequence numbers that go round: images whose every connection begins within 1 MiB below
# 2^31 or 2^32 (make ISNTOP=n), so one in 500 crosses it in our flight (hence the many
# connections), and every fetch of the large file does; and two that begin within 32 KiB
# (those not with loss: see tools/sitetest.sh)
T[tls_isn31]="B=build-isn31 unshare -Urn ./tap.sh ./taprunc.sh 8000 1024 4"
T[tls_isn32]="B=build-isn32 unshare -Urn ./tap.sh ./taprunc.sh 8000 1024 4"
T[tls_isn31_loss3]="B=build-isn31 LOSS=3 $TLS"
T[plain_isn32_loss3]='B=build-isn32 PLAIN=1 INFLIGHT=64 LOSS=3 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
T[real_isn31_loss3]="B=build-real-isn31 LOSS=3 $TLS"
T[real_isn32_reorder]="B=build-real-isn32 REORDER=25 $TLS"
SITE='NOBUILD=1 unshare -Urn tools/sitetest.sh tap'
T[site_wrap31]="B=build-wrap31 $SITE"
T[site_wrap32]="B=build-wrap32 $SITE"
T[site_wrap31_loss3]="LOSS=3 B=build-wrapl31 $SITE quick"
T[site_wrap32_loss3]="LOSS=3 B=build-wrapl32 $SITE quick"
# a connection's keys are not used for more records than they should be (here: 2^10 and 2^6)
T[site_keylife]="KEYLIFE=10 STLIFE=6 B=build-keylife ONLY='share of records' $SITE"
# a client that vanishes in the middle of a file is given up after a minute or two, and one
# that only stops reading is not (three minutes)
T[site_gone]="GONE=1 ONLY=vanishes $SITE"
# a slot that another processor takes while its connection's timer has it in hand: before
# the timer has said "in use", and after (tools/racetest.py; three to four minutes each)
T[race1]='unshare -Urn tools/racetest.sh 1'
T[race2]='unshare -Urn tools/racetest.sh 2'
# the one free slot of a bucket gone between being counted and being taken (five seconds)
T[race3]='unshare -Urn tools/racetest.sh 3'
# of three processors two take frames, and the third is at rest (tools/cputest.py asks QEMU)
T[cpus3]='rm -f /tmp/k18mon.c3; SMP=3 MON=/tmp/k18mon.c3 unshare -Urn ./tap.sh python3 tools/cputest.py; rc=$?; rm -f /tmp/k18mon.c3; exit $rc'
# from outside: tlsfuzzer's conversations (tools/tlsfuzz.sh; not run where ext/ has not been
# fetched), and real ClientHellos damaged at random (tools/hellofuzz.py)
T[tlsfuzz]='IFTHERE=1 unshare -Urn tools/tlsfuzz.sh'
T[hellofuzz]='unshare -Urn ./tap.sh python3 tools/hellofuzz.py'
# frames that no router would pass on: lengths that say less than there must be, and the like
T[rawframes]='unshare -Urn ./tap.sh python3 tools/rawtest.py'
# segments in a client's name whose ack is not the client's: nothing of them is taken (tools/acktest.py)
T[ack]='unshare -Urn ./tap.sh python3 tools/acktest.py'
# An image's address: the default image has none and asks for one (DHCP). Over tap that is
# tools/dhcpd.py's to give, through QEMU's own network QEMU's; here against a server that
# answers right and wrong as the test wants (tools/dhcptest.py), the same on four
# processors, and against dnsmasq (not run where there is none). And an image built with
# an address of its own, which asks nobody.
T[dhcp]='unshare -Urn tools/dhcptest.sh'
T[dhcp_smp4]='SMP=4 unshare -Urn tools/dhcptest.sh'
T[dhcp_dnsmasq]='IFTHERE=1 unshare -Urn tools/dhcptest.sh real'
T[static_measure]='B=build-static IP=10.0.2.15 PORT=8493 ./measure.sh'
T[static_tls_loss3]="B=build-static LOSS=3 DHCPD=none STATIC=1 $TLS"
T[static_plain]='B=build-static DHCPD=none STATIC=1 PLAIN=1 INFLIGHT=64 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
# IPv6: an image built with an IPv6 address (IP6=fd00:15::15; the tap then has fd00:15::2
# and ::32 to ::63). Frame by frame (tools/v6test.py: what a neighbour's question gets,
# what gets nothing, 3,000 frames with wrong lengths); the clients of the runs above over
# IPv6 (V6=1), with loss, reordering, the least a link of IPv6 may carry, a flight of two
# segments, a second ClientHello; four addresses with the same ports into a table of
# 1,024 slots (what stands for an address in a slot must tell them apart); the site of
# many files; and the same image over IPv4.
T[v6]='B=build-site6 unshare -Urn ./tap.sh python3 tools/v6test.py'
T[tls6]="B=build-v6 V6=1 $TLS"
T[tls6_loss3]="B=build-v6 V6=1 LOSS=3 $TLS"
T[tls6_mtu1280_loss3]="B=build-v6 V6=1 MTU=1280 LOSS=3 $TLS"
T[tls6_reorder]="B=build-v6 V6=1 REORDER=25 $TLS"
T[plain6]='B=build-v6 V6=1 PLAIN=1 INFLIGHT=64 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
T[plain6_loss3]='B=build-v6 V6=1 PLAIN=1 INFLIGHT=64 LOSS=3 unshare -Urn ./tap.sh ./taprunc.sh 4000 1024 4'
T[real6_loss3]="B=build-real6 V6=1 LOSS=3 $TLS"
T[real6_reorder]="B=build-real6 V6=1 REORDER=25 $TLS"
T[hrr6_loss3]="KEX=P-256:X25519 B=build-v6 V6=1 LOSS=3 $TLS"
T[small6]='B=build-small6 V6=1 unshare -Urn ./tap.sh ./taprunc.sh 150 1024 4'
T[site6]="V6=1 B=build-site6 $SITE"
T[site6_loss3]="V6=1 LOSS=3 B=build-site6 $SITE"
T[site6_reorder]="V6=1 REORDER=25 B=build-site6 $SITE"
T[v6_tls4_loss3]="B=build-v6 LOSS=3 $TLS"
T[site4_v6_loss3]="LOSS=3 B=build-site6 $SITE quick"
# the tool: ./k18 pack and ./k18 run; and its way onto a machine that is k18's alone (./k18
# publish, deploy, renew), with a machine that is made up (tools/hosttest.sh)
T[k18]='PORT=8513 tools/k18test.sh'
T[host]='unshare -Urn tools/hosttest.sh'
# only code is executed, and neither code nor site is written (tools/wxtest.sh)
T[wx]='tools/wxtest.sh'
# a site of many files, one of them large (tools/sitetest.sh): every path, every kind of client
T[site]='NOBUILD=1 tools/sitetest.sh'
T[site_tap]="$SITE"
T[site_loss3]="LOSS=3 $SITE"
T[site_mtu600_loss3]="MTU=600 LOSS=3 $SITE quick"
T[site_reorder]="REORDER=25 $SITE"
# the same where the card does not cut frames into segments for us (as through QEMU's own
# network, but over tap, with loss): a segment a frame
T[site_notso_loss3]="B=build-site-notso LOSS=3 $SITE quick"
# a large file through a path narrower than the window: no slower than a window of 64 KB was
T[bneck]='tools/bnecktest.sh'
# the image is the same bytes whoever makes it, and without its key what anybody can make (tools/repro.sh)
T[repro]='tools/repro.sh'
# a round trip of 300 ms and nothing lost: nothing is sent twice (the timer goes by the round trip)
T[rtt]='B=build-site DELAY=300 unshare -Urn ./tap.sh python3 tools/rtttest.py'
ORDER="measure measure_tcg measure_efi browsers tls tls_loss3 tls_mtu300_loss3 tls_reorder twice twice_reorder plain plain_loss3 plain_mtu300_loss3
  plain_reorder raw1m raw1m_20k raw_4g tls_4g churn churn_idle idle real_measure real_loss3
  real_mtu300_loss3 real_reorder hrr hrr_loss3 hrr_mtu300_loss3
  hrr_reorder real_hrr_loss3 redirect raw_redirect tls_isn31 tls_isn32 tls_isn31_loss3
  plain_isn32_loss3 real_isn31_loss3 real_isn32_reorder site_wrap31 site_wrap32 site_wrap31_loss3
  site_wrap32_loss3 site_keylife site_gone race1 race2 race3 cpus3 tlsfuzz hellofuzz rawframes ack dhcp dhcp_smp4 dhcp_dnsmasq
  static_measure static_tls_loss3 static_plain v6 tls6 tls6_loss3 tls6_mtu1280_loss3 tls6_reorder plain6 plain6_loss3
  real6_loss3 real6_reorder hrr6_loss3 small6 site6 site6_reorder v6_tls4_loss3 k18 host wx site site_efi site_tap site_loss3 site_mtu600_loss3
  site_reorder
  site_notso_loss3 site6_loss3 site4_v6_loss3 bneck rtt repro"

# the images and clients first (not in parallel)
[[ -f cert-real/server.pem ]] || python3 tools/mkchain.py cert-real >/dev/null || exit 1
make -s all >/dev/null || { echo "BUILD FAILED"; exit 1; }
make -s B=build-small CAP=1024 >/dev/null || { echo "BUILD FAILED (small)"; exit 1; }
make -s B=build-small-idle CAP=1024 IDLE=0 >/dev/null || { echo "BUILD FAILED (small-idle)"; exit 1; }
make -s B=build-small-idle1 CAP=1024 IDLE=1 >/dev/null || { echo "BUILD FAILED (small-idle1)"; exit 1; }
make -s B=build-real CERT=cert-real >/dev/null || { echo "BUILD FAILED (real)"; exit 1; }
make -s B=build-static IP=10.0.2.15 >/dev/null || { echo "BUILD FAILED (static)"; exit 1; }
make -s B=build-v6 IP6=fd00:15::15 >/dev/null && make -s B=build-real6 CERT=cert-real IP6=fd00:15::15 >/dev/null &&
  make -s B=build-small6 CAP=1024 IP6=fd00:15::15 >/dev/null || { echo "BUILD FAILED (IPv6)"; exit 1; }
env $REDIR make -s >/dev/null || { echo "BUILD FAILED (redirect)"; exit 1; }
make -s B=build-isn31 ISNTOP=0x7FF00000 >/dev/null && make -s B=build-isn32 ISNTOP=0xFFF00000 >/dev/null || { echo "BUILD FAILED (isn)"; exit 1; }
make -s B=build-real-isn31 CERT=cert-real ISNTOP=0x7FF00000 >/dev/null && make -s B=build-real-isn32 CERT=cert-real ISNTOP=0xFFF00000 >/dev/null || { echo "BUILD FAILED (real isn)"; exit 1; }
for w in "wrap31 0x7FFF8000 17" "wrap32 0xFFFF8000 17" "wrapl31 0x7FF00000 12" "wrapl32 0xFFF00000 12"; do
  set -- $w
  mkdir -p build-$1 && python3 tools/mksite.py build-$1/www >/dev/null && make -s B=build-$1 SITE=build-$1/www ISNTOP=$2 ISNBITS=$3 >/dev/null || { echo "BUILD FAILED (wrap)"; exit 1; }
done
mkdir -p build-keylife && python3 tools/mksite.py build-keylife/www >/dev/null && make -s B=build-keylife SITE=build-keylife/www KEYLIFE=10 STLIFE=6 >/dev/null || { echo "BUILD FAILED (keylife)"; exit 1; }
mkdir -p build-site && python3 tools/mksite.py build-site/www >/dev/null && make -s B=build-site SITE=build-site/www >/dev/null || { echo "BUILD FAILED (site)"; exit 1; }
mkdir -p build-site6 && python3 tools/mksite.py build-site6/www >/dev/null && make -s B=build-site6 SITE=build-site6/www IP6=fd00:15::15 >/dev/null || { echo "BUILD FAILED (site, IPv6)"; exit 1; }
mkdir -p build-site-notso && python3 tools/mksite.py build-site-notso/www >/dev/null && make -s B=build-site-notso SITE=build-site/www NOTSO=1 >/dev/null || { echo "BUILD FAILED (site, no TSO)"; exit 1; }
[[ -x build/rawc && build/rawc -nt tools/rawc.c ]] || gcc -O2 -o build/rawc tools/rawc.c || exit 1
for b in build build-real build-static build-v6 build-real6 build-small6 build-small build-small-idle build-isn31 build-isn32 build-real-isn31 build-real-isn32; do
  [[ -x $b/tapc && $b/tapc -nt tools/tapc.c ]] || gcc -O2 -o $b/tapc tools/tapc.c -lssl -lcrypto || exit 1
done

verdict() {  # name, exit code -> one line
  local n=$1 rc=$2 f=$LOGS/$1.log v=FAIL note=
  case $n in
    measure*|real_measure|static_measure|redirect) grep -q '^PASS' "$f" && v=ok; note=$(grep -m1 -E '^(PASS|FAIL)' "$f");;
    browsers) [[ $rc == 0 ]] && grep -q 'refused OK' "$f" && v=ok; note=$(tr '\n' ';' <"$f" | tail -c 120);;
    raw*|twice*) [[ $rc == 0 ]] && ! grep -q -E ' [1-9][0-9]* (reset|timed out)' "$f" && v=ok
       note=$(grep '^RAW total' "$f" | tail -1 | cut -c1-80)
       note="$note; $(grep -o '[0-9]* reset, [0-9]* timed out' "$f" | tr '\n' ';')";;
    churn*|idle|race*|cpus3|tlsfuzz|hellofuzz|rawframes|ack|dhcp*|v6) [[ $rc == 0 ]] && v=ok; note=$(tail -1 "$f" | cut -c1-110);;
    wx) [[ $rc == 0 ]] && v=ok; note="$(grep -c '^ok' "$f") of 18 ok; $(grep -m1 '^FAIL' "$f")";;
    bneck) [[ $rc == 0 ]] && v=ok; note="$(grep -c '^ok' "$f") of 4 ok; $(grep -m1 '^FAIL' "$f" | cut -c1-80)";;
    rtt) [[ $rc == 0 ]] && v=ok; note=$(tr '\n' ';' <"$f" | cut -c1-150);;
    repro) [[ $rc == 0 ]] && v=ok; note="$(grep -c '^ok' "$f") of 6 ok; $(grep -m1 '^FAIL' "$f" | cut -c1-90)";;
    k18) [[ $rc == 0 ]] && v=ok; note="$(grep -c '^ok' "$f") of 24 ok; $(grep -m1 '^FAIL' "$f")";;
    host) [[ $rc == 0 ]] && v=ok; note="$(grep -c '^ok' "$f") of 24 ok; $(grep -m1 '^FAIL' "$f" | cut -c1-90)";;
    site*) [[ $rc == 0 ]] && grep -q '^ok' "$f" && grep -q '^all ok' "$f" && v=ok; note="$(grep -c '^ok' "$f") checks ok; $(grep -m2 '^FAIL' "$f" | cut -c1-90 | tr '\n' ';')";;
    *) note=$(grep '^SCORE' "$f"); [[ $note == SCORE* && $note != "SCORE 0.0"* ]] && ! grep -q FAILED "$f" && v=ok
       note="${note#*= }; $(grep -c FAILED "$f") failed; $(grep -m1 -o 'open_s [0-9.]*' "$f")";;
  esac
  printf '%-20s %-4s %s\n' "$n" "$v" "$note"
}

running=0
for n in $ORDER; do
  [[ $WANT == "  " || $WANT == *" $n "* ]] || continue
  ( t0=$(date +%s); bash -c "${T[$n]}" >"$LOGS/$n.log" 2>&1; rc=$?; echo "$(verdict "$n" $rc)  [$(( $(date +%s) - t0 )) s]" ) &
  running=$((running + 1))
  if (( running >= JOBS )); then wait -n; running=$((running - 1)); fi
done
wait
echo "logs: $LOGS"
