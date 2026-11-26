#!/usr/bin/env bash
# tlsprobe.sh HOST[:PORT] [CAFILE]: what a scanner asks a TLS server, one question at a
# time (openssl s_client), and what the server says: each protocol version, each TLS 1.3
# cipher suite, each group for the key share alone and with x25519 behind it. A server
# should answer every one with a handshake or with an alert that says why not; "no answer"
# or anything else is what scanners call intolerance. Exit 1 if there is any of that, or
# if something is served that should not be (or the other way round).
T=${1:-127.0.0.1:8443}
[[ $T == *:* ]] || T=$T:443
CA=${2:-}
bad=0
ask() {  # what we expect ("ok" or the alert's name), a label, s_client's options
  local want=$1 label=$2 out got
  shift 2
  out=$(timeout 10 openssl s_client -connect "$T" ${CA:+-CAfile "$CA"} "$@" </dev/null 2>&1)
  if grep -q "Verification: OK\|Verify return code: 0 (ok)" <<<"$out" && grep -q "^New, TLSv1.3" <<<"$out"; then
    got=ok
  elif [[ $out =~ alert\ ([a-z\ ]+) ]]; then
    got=${BASH_REMATCH[1]}
    got=${got%%:*}
  elif grep -q "no protocols available\|unsupported protocol\|no ciphers available" <<<"$out"; then
    echo "skip $label (this openssl can't ask that)"
    return
  else
    got="no answer ($(grep -m1 -i "error\|errno" <<<"$out" | cut -c1-60))"
  fi
  if [[ $got == "$want"* ]]; then echo "ok   $label: $got"; else echo "FAIL $label: $got (expected: $want)"; bad=1; fi
}
ask "protocol version" "TLS 1.0" -tls1
ask "protocol version" "TLS 1.1" -tls1_1
ask "protocol version" "TLS 1.2" -tls1_2
ask "protocol version" "TLS 1.2, old ciphers" -tls1_2 -cipher 'ALL:@SECLEVEL=0'
ask ok "TLS 1.3" -tls1_3
ask ok "TLS 1.3, TLS_AES_128_GCM_SHA256" -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
ask "handshake failure" "TLS 1.3, TLS_CHACHA20_POLY1305_SHA256 alone" -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
ask "handshake failure" "TLS 1.3, TLS_AES_256_GCM_SHA384 alone" -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
ask ok "TLS 1.3, TLS_AES_256_GCM_SHA384 and ours" -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
takes() {  # the cipher suite that must come of it, a label, s_client's options
  local want=$1 label=$2 got
  shift 2
  got=$(timeout 10 openssl s_client -connect "$T" ${CA:+-CAfile "$CA"} -tls1_3 "$@" </dev/null 2>&1 | sed -n 's/^New, TLSv1.3, Cipher is //p')
  if [[ $got == "$want" ]]; then echo "ok   $label: $got"; else echo "FAIL $label: ${got:-no handshake} (expected: $want)"; bad=1; fi
}
takes TLS_AES_128_GCM_SHA256 "TLS 1.3, the suites in OpenSSL's order"
takes TLS_AES_128_GCM_SHA256 "TLS 1.3, ChaCha20-Poly1305 before AES-128-GCM" -ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
takes TLS_AES_128_GCM_SHA256 "TLS 1.3, AES-128-GCM before ChaCha20-Poly1305" -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
for g in P-256 P-384 P-521 X448 ffdhe2048 X25519MLKEM768; do
  ask "handshake failure" "TLS 1.3, group $g alone" -tls1_3 -groups $g
  ask ok "TLS 1.3, a share for $g, x25519 offered too" -tls1_3 -groups $g:X25519
done
ask ok "TLS 1.3, group X25519" -tls1_3 -groups X25519
ask ok "TLS 1.3 or less, as a browser asks" -groups X25519MLKEM768:X25519:P-256
exit $bad
