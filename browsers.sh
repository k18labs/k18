#!/usr/bin/env bash
# Browser check (slower than measure.sh; run after protocol/cert changes). No certificate
# error is bypassed anywhere: the browsers must accept the chain and the name.
#  1. Firefox (via Marionette), our CA imported into a throwaway profile: must render the page
#  2. Chrome, trusting our CA (HOME points at a throwaway NSS database with it):
#     must render the page, and its net-log must show no certificate error flags
#  3. Chrome without our CA: must refuse (so step 2 proves something)
# With a real certificate in cert/ nothing is imported and step 3 is skipped.
set -euo pipefail
cd "$(dirname "$0")"
PORT=${PORT:-8444}
export B=${B:-build}
IMG=${1:-$B/os.bin}
[[ $# -gt 0 ]] || make -s all B="$B" CERT="${CERT:-cert}" >/dev/null
EXPECT=$(head -c 20 www/index.html)
TMP=$(mktemp -d)
source tools/vm.sh
boot

mkdir -p "$TMP/home" "$TMP/nohome"
python3 -I tools/ffcheck.py "$URL" $B/ca.pem "$EXPECT"
[[ -s $B/ca.pem ]] && python3 -I tools/nssdb.py "$TMP/home/.pki/nssdb" $B/ca.pem

chrome() { HOME="$TMP/$1" timeout 60 google-chrome --headless=new --no-sandbox --user-data-dir="$TMP/c$1" \
  --host-resolver-rules="MAP ${NAME} 127.0.0.1" "${@:2}" --dump-dom "$URL" 2>/dev/null; }

if chrome home --log-net-log="$TMP/netlog.json" | grep -qF "$EXPECT"; then echo "chrome page: OK"
else echo "chrome page: FAIL"; python3 -I tools/certerr.py "$TMP/netlog.json" "$NAME" || true; exit 1; fi
if FLAGS=$(python3 -I tools/certerr.py "$TMP/netlog.json" "$NAME"); then echo "chrome cert errors: $FLAGS OK"
else echo "chrome cert errors: $FLAGS -> FAIL"; exit 1; fi

if [[ -s $B/ca.pem ]]; then
  if chrome nohome | grep -qF "$EXPECT"; then echo "chrome without our CA: loaded the page -> FAIL"; exit 1
  else echo "chrome without our CA: refused OK"; fi
fi
