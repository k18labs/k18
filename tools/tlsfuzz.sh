#!/usr/bin/env bash
# tlsfuzzer against a running image: the scripts for TLS 1.3 that apply to a server like
# ours, some two thousand conversations, most of them wrong in one place. Each script goes
# through tools/tlsfuzz.py, which says what is taken for granted and how silence counts.
#
#   unshare -Urn tools/tlsfuzz.sh          over tap, against build/ (make first); 5 minutes
#   unshare -Urn tools/tlsfuzz.sh NAME...  only the scripts whose names have NAME in them
#
# What must hold: the server still serves after every script (and its QEMU has not been
# reset: a fault is the machine's end); the conversations that a server like ours must
# get right come out right (tlslite-ng, which is not our code, checks our signature, our
# Finished and every record); and those that fail are the ones listed here, each for a
# reason that docs/internals.md has under "Shortcuts that remain". A conversation that
# fails and is not listed fails this test: `go` has, behind a script's name, a pattern
# for the names of the conversations that may fail, and why.
# Not run, because they are about what we don't have: client certificates
# (certificate-request, certificate-verify, post-handshake-auth, the *-compression ones),
# tickets and PSKs (session-resumption, count-tickets, psk_*), other signatures (rsa*,
# pkcs, eddsa*, mldsa, *brainpool*), other groups (ffdhe*, mlkem, dhe-shared-secret-padding),
# a server's own KeyUpdate, TLS 1.3 switched off (non-support), an echo server (lengths),
# and the one that times signatures over hours (minerva).
cd "$(dirname "$0")/.." || exit 1
export B=${B:-build}
if [[ -z ${TLSFUZZ_IN:-} ]]; then
  if [[ ! -d ext/tlsfuzzer || ! -d ext/py/tlslite ]]; then   # (IFTHERE=1, the suite's way: that is no failure)
    echo "${IFTHERE:+ok: }not run: no ext/tlsfuzzer (tools/outside.sh fetch)"; [[ -n ${IFTHERE:-} ]]; exit
  fi
  exec env TLSFUZZ_IN=1 ./tap.sh tools/tlsfuzz.sh "$@"
fi
WANT=("$@")
LOGS=${LOGS:-$(mktemp -d /tmp/k18-tlsfuzz.XXXXXX)}
bad=0
alive() {
  curl -s --max-time 5 -o /dev/null --interface 10.0.2.32 --connect-to "$(cat "$B/name"):443:10.0.2.15:443" \
    ${CA:+--cacert "$CA"} "https://$(cat "$B/name")/" && kill -0 "$QEMU_PID" 2>/dev/null
}
CA=; [[ -s $B/ca.pem ]] && CA=$B/ca.pem
go() {  # script, pattern of the conversations that may fail, why; NOSWAP=1 in front: see tlsfuzz.py
  local s=$1 t
  if (( ${#WANT[@]} )); then t=; for w in "${WANT[@]}"; do [[ $s == *$w* ]] && t=1; done; [[ -n $t ]] || return; fi
  ALLOW=$2 timeout 600 python3 tools/tlsfuzz.py "test-tls13-$s" -h 10.0.2.15 -p 443 >"$LOGS/$s.log" 2>&1
  local rc=$? line
  line=$(tail -1 "$LOGS/$s.log")
  if [[ $rc == 0 ]] && alive; then echo "ok   ${line}${3:+ ($3)}"; else
    echo "FAIL ${line} [$LOGS/$s.log]"; grep '^NOT EXPECTED' "$LOGS/$s.log" | head -5; bad=1
    alive || { echo "FAIL the server no longer answers"; exit 1; }
  fi
}
go conversation ''
go symetric-ciphers 'check connection with TLS_(AES_256_GCM_SHA384|AES_128_CCM|CHACHA20_POLY1305)' 'the four suites that are not ours'
go hrr ''
go ccs ''
go multiple-ccs-messages ''
go empty-alert ''
go unencrypted-alert ''
go finished-plaintext ''
go finished '.*TLS_(AES_256_GCM_SHA384|CHACHA20_POLY1305_SHA256)|padding - cipher TLS_AES_128_GCM_SHA256' 'not our suite; a record of more than 4 KB'
go invalid-ciphers ''
go nociphers ''
go no-unknown-groups ''
go record-padding 'set-max-length-padding' 'a record of more than 4 KB'
go record-layer-limits 'too big|max size' 'a record of more than 4 KB'
go zero-length-data 'zero-len(gth)? app data .*(interleaved in handshake|large padding)|zero-length app data( with padding)?$' \
  'a ClientHello in two records; a record of more than 4 KB; a request in pieces: "GET /" alone has no Host line, and gets the 400 and the end'
go zero-content-type 'zero content type( and padding)? during application data' 'its "GET /" is a request to us, and answered'
go connection-abort 'After NewSessionTicket' 'no tickets'
go keyupdate '(?!sanity)' 'no KeyUpdate: a client that changes its keys is not understood'
go keyshare-omitted 'key_share extension omitted|empty key_share extension' 'asked for a key share where a server is to refuse'
go legacy-version 'version \(' 'legacy_version is not looked at'
go ecdsa-support 'Test with ecdsa_sha(1|224)' 'signature_algorithms is not looked at'
go signature-algorithms '(?!sanity)' 'signature_algorithms is not looked at; a ClientHello of more than 4 KB'
go shuffled-extentions 'HRR reversed order of|.*unassigned extensions' 'the two ClientHellos are not compared; a ClientHello of more than 4 KB'
go large-number-of-extensions '.*unassigned extensions' 'a ClientHello of more than 4 KB'
go unrecognised-groups '(?!sanity)' 'a ClientHello of more than 4 KB'
go version-negotiation 'fallback from TLS|TLS 1\.[0-9]+ in client hello legacy field' 'no TLS 1.2 to fall back to'
go serverhello-random '(?!sanity)' 'no TLS 1.2, and one group'
go 0rtt-garbage 'handshake with (invalid )?0-RTT|undecryptable record later in handshake together with early_data' 'early data in records of more than 4 KB; no TLS 1.2'
NOSWAP=1 go crfg-curves 'sanity|.*(x448|secp)|(empty|too small|too big) x25519 key share' \
  'groups that are not ours; asked again where a server is to refuse'
NOSWAP=1 go ecdhe-curves 'sanity - (secp|x448)|secp|x448|x25519 - (point at infinity|right-truncated key_share|key share from other curve|right 0-padded key_share)' \
  'groups that are not ours; asked again where a server is to refuse'
alive || { echo "FAIL the server no longer answers"; exit 1; }
[[ $bad == 0 ]] && echo "all ok: the server answers after all of it (logs: $LOGS)" || echo "FAILED (logs: $LOGS)"
exit $bad
