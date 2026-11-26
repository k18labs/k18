#!/usr/bin/env bash
# Build, boot in QEMU, fetch the page with curl (which verifies the certificate chain and the
# name: no -k), report image size.
# Usage: ./measure.sh [image]   (default: build the asm image -> build/os.bin)
set -euo pipefail
cd "$(dirname "$0")"

PORT=${PORT:-8443}
IMG=${1:-}
export B=${B:-build}
if [[ -z "$IMG" ]]; then
  make -s all B="$B" CERT="${CERT:-cert}" >/dev/null     # (NAME, IP, SITE, P80, HSTS: from the environment)
  IMG=$B/os.bin
fi
EXPECT=$(cat www/index.html)
source tools/vm.sh
boot

BODY=$("${CURL[@]}" "$URL") || { echo "FAIL: curl exit $? (verified fetch of $URL)"; cat "$QEMU_LOG"; exit 1; }
if [[ "$BODY" != "$EXPECT" ]]; then
  echo "FAIL: got '${BODY}'"
  exit 1
fi
# second and third request on fresh connections, plus keep-alive reuse
for _ in 1 2; do
  B2=$("${CURL[@]}" "$URL" "${URL}index.html") || { echo "FAIL: repeat"; exit 1; }
  [[ "$B2" == "$EXPECT"$'\n'"$EXPECT" ]] || { echo "FAIL: keep-alive got '$B2'"; exit 1; }
done
# Our one cipher, AES-128-GCM, wherever the client names it (a keep-alive request too)
while read -r OFFER; do
  V=$("${CURL[@]}" -v --tls13-ciphers "$OFFER" "$URL" "${URL}index.html" 2>&1) || { echo "FAIL: a client that offers $OFFER"; exit 1; }
  [[ "$V" == *"SSL connection using TLSv1.3 / TLS_AES_128_GCM_SHA256 /"* && "$V" == *"$EXPECT"*"$EXPECT"* ]] || { echo "FAIL: a client that offers $OFFER did not get AES-128-GCM, or not the page twice"; exit 1; }
done <<'ORDERS'
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
ORDERS
# a client whose key share is for another curve is asked for one for ours, and gets it
V=$("${CURL[@]}" -v --curves secp256r1:x25519 "$URL" 2>&1) || { echo "FAIL: no HelloRetryRequest"; exit 1; }
[[ "$V" == *"/ x25519 /"*"$EXPECT"* ]] || { echo "FAIL: after a HelloRetryRequest, not x25519 or not the page"; exit 1; }
# a client that can't be served is told why: one without TLS 1.3, one without our cipher
# (ChaCha20-Poly1305 alone, or with AES-256-GCM)
V=$("${CURL[@]}" -v --tls-max 1.2 "$URL" 2>&1) && { echo "FAIL: served a client without TLS 1.3"; exit 1; }
[[ "$V" == *"alert protocol version"* ]] || { echo "FAIL: no \"protocol version\" alert for a TLS 1.2 client"; exit 1; }
for C in TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384; do
  V=$("${CURL[@]}" -v --tls13-ciphers $C "$URL" 2>&1) && { echo "FAIL: served a client that offers only $C"; exit 1; }
  [[ "$V" == *"alert handshake failure"* ]] || { echo "FAIL: no \"handshake failure\" alert for a client that offers only $C"; exit 1; }
done
# port 80: the same page over plain HTTP, fresh and keep-alive; or, in an image built with
# P80=redirect, everybody is sent to the site's https address
if [[ $(head -c 12 "$B/page80.bin") == "HTTP/1.1 301" ]]; then
  H=$(curl -s --max-time 10 -o /dev/null -w '%{http_code} %{redirect_url} ' "http://127.0.0.1:$HPORT/" "http://127.0.0.1:$HPORT/a/b?c") || { echo "FAIL: curl exit $? (plain HTTP)"; exit 1; }
  [[ "$H" == "301 https://$NAME/ 301 https://$NAME/ " ]] || { echo "FAIL: port 80 does not redirect: '$H'"; exit 1; }
else
  H=$(curl -s --max-time 10 "http://127.0.0.1:$HPORT/" "http://127.0.0.1:$HPORT/x") || { echo "FAIL: curl exit $? (plain HTTP)"; exit 1; }
  [[ "$H" == "$EXPECT"$'\n'"$EXPECT" ]] || { echo "FAIL: plain HTTP got '$H'"; exit 1; }
fi
# with HSTS=seconds, every response over TLS says so
if [[ -n ${HSTS:-} ]]; then
  "${CURL[@]}" -I "$URL" | grep -q "^Strict-Transport-Security: max-age=$HSTS" || { echo "FAIL: no Strict-Transport-Security"; exit 1; }
fi
# what is not there is said to be not there, and a request for the head gets the head
[[ $("${CURL[@]}" -o /dev/null -w '%{http_code}' "${URL}x") == 404 ]] || { echo "FAIL: no 404 for an unknown path"; exit 1; }
[[ $("${CURL[@]}" -I "$URL" | tr -d '\r' | grep -c -E '^(HTTP/1.1 200 OK|Content-Length: [0-9]+)$') == 2 ]] || { echo "FAIL: HEAD"; exit 1; }
# and nobody who doesn't trust our CA gets in (the chain is checked, not waved through)
if [[ -s $B/ca.pem ]] && "${NOCA[@]}" -o /dev/null "$URL"; then
  echo "FAIL: curl accepted the certificate without our CA"; exit 1
fi
# forged, replayed and malformed input is ignored and harms nobody
OUT=$(PORT=$PORT python3 tools/abuse.py) || { echo "FAIL: hostile-client checks"; echo "$OUT"; exit 1; }
# what a scanner asks (each version, cipher suite and group by itself) gets a handshake or
# an alert that says why not
CAF=
[[ -s $B/ca.pem ]] && CAF=$B/ca.pem
OUT=$(tools/tlsprobe.sh "127.0.0.1:$PORT" $CAF) || { echo "FAIL: a scanner's questions"; echo "$OUT" | grep FAIL; exit 1; }

SIZE=$(stat -c %s "$IMG")
echo "PASS  image=$IMG  size=${SIZE} bytes"
LST=${IMG%.bin}.lst
if [[ -f "$LST" ]]; then
  echo "--- largest routines/data (bytes) ---"
  python3 tools/sizes.py "$LST" 14
fi
