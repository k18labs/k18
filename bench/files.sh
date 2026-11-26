#!/usr/bin/env bash
# bench/files.sh IP [all]: the rows about files (bench/README.md), run on a load generator
# next to the server, from the directory that has this script: wrk, 8 s a row (D=8s), for
# a server that has the site of tools/mksite.py. Each large row twice: with OpenSSL's own
# order of cipher suites (of which k18 takes AES-128-GCM and nginx AES-256-GCM) and
# with AES-128-GCM alone (what browsers put first). Behind each row, what this side's TCP
# counted meanwhile: its own segments sent again and timeouts (requests that waited), and
# segments that came early (something before them was lost or late). With "all": also a
# file that is packed compressed too, and a request for a page the client has (304).
IP=$1
cd "$(dirname "$0")" || exit 1
ulimit -n 1000000
cat > aes.cnf <<'CNF'
openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
Ciphersuites = TLS_AES_128_GCM_SHA256
CNF
row() {  # name, aes or -, wrk's arguments
  local name=$1 conf=$2 out; shift 2
  nstat -n >/dev/null 2>&1
  if [[ $conf == aes ]]; then out=$(OPENSSL_CONF=$PWD/aes.cnf wrk "$@" 2>&1); else out=$(wrk "$@" 2>&1); fi
  printf '%-40s %10s req/s %10s/s  %s%s\n' "$name" "$(awk '/Requests\/sec/{print $2}' <<<"$out")" "$(awk '/Transfer\/sec/{print $2}' <<<"$out")" \
    "$(grep -E 'Socket errors|Non-2xx' <<<"$out" | tr -s ' ' | tr '\n' ';')" \
    "$(nstat 2>/dev/null | awk '/TcpExtTCPOFOQueue|TcpRetransSegs|TcpExtTCPTimeouts/{printf "%s=%s ", substr($1,4), $2}')"
  sleep 2
}
D=${D:-8s}
row "page, 64 connections"             - -t8 -c64 -d$D https://$IP/
row "page, 512"                        - -t8 -c512 -d$D https://$IP/
row "14 KB, 64 (OpenSSL's order)"      - -t8 -c64 -d$D https://$IP/size/14000.bin
row "14 KB, 64 (AES-128-GCM)"          aes -t8 -c64 -d$D https://$IP/size/14000.bin
row "1.5 MiB, 64 (OpenSSL's order)"    - -t8 -c64 -d$D https://$IP/big.bin
row "1.5 MiB, 8 (OpenSSL's order)"     - -t8 -c8 -d$D https://$IP/big.bin
row "1.5 MiB, 64 (AES-128-GCM)"        aes -t8 -c64 -d$D https://$IP/big.bin
row "1.5 MiB, 8 (AES-128-GCM)"         aes -t8 -c8 -d$D https://$IP/big.bin
row "1.5 MiB, 1 (AES-128-GCM)"         aes -t1 -c1 -d$D https://$IP/big.bin
if [[ ${2:-} == all ]]; then
  row "200 KB of text, 64, as it is"   aes -t8 -c64 -d$D https://$IP/docs/list.txt
  row "the same to who takes brotli"   aes -t8 -c64 -d$D -H 'Accept-Encoding: gzip, deflate, br, zstd' https://$IP/docs/list.txt
  row "the page, 64, to who has it"    aes -t8 -c64 -d$D -H "If-None-Match: $(curl -sk -D - -o /dev/null https://$IP/ | tr -d '\r' | sed -n 's/^ETag: //p')" https://$IP/
fi
