#!/usr/bin/env bash
# The site test: an image with tools/mksite.py's site in it (in $B, default build-site: 80
# files, one of 1.5 MiB, so the image is over 1 MiB and everything else sits higher) must
# serve every path as tools/pack.py made it, to every kind of client tools/sitecheck.py
# plays.
#   tools/sitetest.sh [quick]                   through QEMU's own network
#   tools/sitetest.sh tap [quick]               over tap (run it as: unshare -Urn tools/sitetest.sh tap),
#                                               where LOSS=3, REORDER=25, MTU=600, SMP=n mean what they
#                                               mean to ./tap.sh, and V6=1: over IPv6
# BIG=n: the large file has n MiB (default 1.5). ISNTOP=n ISNBITS=b: an image whose initial
# sequence numbers all begin with n's top b bits (default 12): with 0x7FF00000 or
# 0xFFF00000 every connection crosses 2^31 or 2^32 within 1 MiB of what we send; with more
# bits sooner, but then not with loss (the SYN cookie checks that many bits less, and a
# connection whose first segment was lost can be begun by its second). KEYLIFE=n: an image
# whose connections may seal 2^n records (make KEYLIFE=n), and the check that they don't
# seal more; STLIFE=n: the same for 2^n records from the client. NOTSO=1: an image that sends a segment a frame also over tap, where the card
# would cut frames into segments for it (a control for the runs that do).
# SUITES=TLS_AES_128_GCM_SHA256: what the checker's clients offer (by themselves they
# offer OpenSSL's three and get the one of them that is ours, AES-128-GCM).
cd "$(dirname "$0")/.." || exit 1
export B=${B:-build-site}
if [[ -z ${NOBUILD:-} ]]; then
  mkdir -p "$B"
  python3 tools/mksite.py "$B/www" ${BIG:-1.5} >/dev/null || exit 1
  make -s B="$B" SITE="$B/www" CERT="${CERT:-cert}" ISNTOP="${ISNTOP:-}" ISNBITS="${ISNBITS:-}" KEYLIFE="${KEYLIFE:-}" STLIFE="${STLIFE:-}" NOTSO="${NOTSO:-}" BIGSH="${BIGSH:-}" IP6="${V6:+fd00:15::15}" >/dev/null || { echo "BUILD FAILED"; exit 1; }
fi
if [[ -n ${SUITES:-} ]]; then         # (OpenSSL's own way to be told: Python's ssl has no other)
  TMP=$(mktemp)
  printf 'openssl_conf = c\n[c]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nCiphersuites = %s\n' "$SUITES" > "$TMP"
  export OPENSSL_CONF=$TMP
fi
if [[ ${1:-} == tap ]]; then
  shift
  trap 'rm -f ${TMP:-}' EXIT
  if [[ -n ${V6:-} ]]; then      # (over IPv6: an image built with IP6=fd00:15::15)
    ./tap.sh env HOST=fd00:15::15 PORT=443 SRC=fd00:15::32 T="${T:-40}" python3 tools/sitecheck.py "$@"
    exit $?
  fi
  ./tap.sh env HOST=10.0.2.15 PORT=443 SRC=10.0.2.32 T="${T:-40}" python3 tools/sitecheck.py "$@"
  exit $?
fi
PORT=${PORT:-8483}
IMG=$B/os.bin
source tools/vm.sh
boot
PORT=$PORT python3 tools/sitecheck.py "$@"
