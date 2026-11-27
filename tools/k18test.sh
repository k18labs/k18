#!/usr/bin/env bash
# The tool itself, as far as it goes without a server. ./k18 pack a folder for a name, with
# a certificate from elsewhere (here: one that signs itself, good for 60 days), HSTS and a
# header of its own; ./k18 run it; what comes back is the site, verified, with those
# headers, and port 80 sends everybody to the name. What it made is for its owner's eyes
# only. ./k18 renew does nothing while the certificate has 30 days left, and when it has
# not (or with --force) makes a new key and a request here and would then go to the
# server (--dry-run stops it there): the old key is still in its place. A second name
# (--san) is served if the certificate is for it, is asked for by renew, and is in the
# certificate that is made when there is none. A file that gets shorter by it is packed
# compressed as well and goes that way to a client that says it takes that; one that has
# the file already is told so; with --no-compress there is none of the first.
# (./k18 deploy, and renew's part on the server, need a server: docs/server.md. One thing
# of deploy --grub is seen here, with an ssh that is made up: a machine that answers but
# not to us is said to, with what ssh said, and is not reset.)
cd "$(dirname "$0")/.." || exit 1
PORT=${PORT:-8513}
OUT=build-k18test CERT=cert-k18test
mkdir -p $OUT $CERT
python3 tools/mksite.py $OUT/www 0.1 >/dev/null || exit 1
# (a certificate for two names, the second one first, with between 40 and 61 days left,
# and nothing else in its folder)
if [[ -e $CERT/ca.pem ]] || ! openssl x509 -checkend $((40 * 86400)) -noout -in $CERT/server.pem >/dev/null 2>&1 ||
   openssl x509 -checkend $((61 * 86400)) -noout -in $CERT/server.pem >/dev/null 2>&1 ||
   ! openssl x509 -checkhost also.k18cli.test -noout -in $CERT/server.pem 2>/dev/null | grep -q "does match"; then
  rm -f $CERT/ca.pem
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $CERT/server.key -out $CERT/server.pem \
    -days 60 -subj /CN=k18cli.test -addext subjectAltName=DNS:also.k18cli.test,DNS:k18cli.test 2>/dev/null || { echo "FAIL openssl"; exit 1; }
fi
# (a header as a Content-Security-Policy has them: with quotes, and here with what a shell or make would read)
KEPT="X-Kept: default-src 'self'; \$(exit 1) \$5 \`exit 1\` \"q\""
mkdir -p $OUT/bin
REAL_MAKE="$(command -v make)"
cat > $OUT/bin/make <<'EOF'
#!/bin/sh
if [ "${HCLOUD_TOKEN+x}" = x ] || [ "${SSH_KEY+x}" = x ]; then
  echo "FAIL build secrets reached make" >&2
  exit 1
fi
exec "$K18_REAL_MAKE" "$@"
EOF
chmod +x $OUT/bin/make
HCLOUD_TOKEN=synthetic-cloud-token SSH_KEY=synthetic-private-key K18_REAL_MAKE="$REAL_MAKE" \
  PATH="$OUT/bin:$PATH" ./k18 pack $OUT/www -n k18cli.test --san also.k18cli.test -c $CERT -o $OUT \
  --hsts 300 --header 'X-Test: yes' --header "$KEPT" > $OUT/pack.out 2>&1 || { echo "FAIL k18 pack"; exit 1; }
grep -q "of system" $OUT/pack.out || { echo "FAIL k18 pack said: $(cat $OUT/pack.out)"; exit 1; }
./k18 run $OUT -p $PORT > $OUT/run.out 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT
CURL=(curl -s --max-time 5 --cacert $CERT/server.pem --connect-to "k18cli.test:$PORT:127.0.0.1:$PORT")
for _ in $(seq 1 40); do
  "${CURL[@]}" -o /dev/null "https://k18cli.test:$PORT/" && break
  sleep 0.25
done
bad=0
check() { if [[ $2 == ok ]]; then echo "ok   $1"; else echo "FAIL $1"; bad=1; fi; }
H=$("${CURL[@]}" -D - -o $OUT/big.got "https://k18cli.test:$PORT/big.bin" | tr -d '\r')
check "the large file comes back as it is" "$(cmp -s $OUT/big.got $OUT/www/big.bin && echo ok)"
check "with the headers asked for" "$([[ $H == *"Strict-Transport-Security: max-age=300"* && $H == *"X-Test: yes"* ]] && echo ok)"
check "  one of them with quotes and dollar signs in it, which are as they were given" "$([[ $H == *$'\n'"$KEPT"$'\n'* ]] && echo ok)"
H=$("${CURL[@]}" -D - -o /dev/null "https://k18cli.test:$PORT/nothing/here" | tr -d '\r')
check "an unknown path too, but for the one about caching" "$([[ $H == "HTTP/1.1 404 "*"Strict-Transport-Security: max-age=300"* && $H == *"X-Test: yes"* &&
  $H == *"X-Content-Type-Options: nosniff"* && $H != *"Cache-Control"* ]] && echo ok)"
H=$("${CURL[@]}" -D - -o /dev/null "https://k18cli.test:$PORT/docs" | tr -d '\r')$("${CURL[@]}" -X POST -D - -o /dev/null "https://k18cli.test:$PORT/" | tr -d '\r')
check "a folder's redirect and the no to POST say HTTPS only as well" "$([[ $H == "HTTP/1.1 301 "*"Strict-Transport-Security: max-age=300"*"HTTP/1.1 405 "*"Strict-Transport-Security: max-age=300"* ]] && echo ok)"
H=$(curl -s --max-time 5 -D - -o /dev/null "http://127.0.0.1:$((PORT + 1000))/" | tr -d '\r')
check "port 80 does not" "$([[ $H == "HTTP/1.1 301 "* && $H != *"Strict-Transport-Security"* ]] && echo ok)"
check "a folder's page at its name" "$("${CURL[@]}" "https://k18cli.test:$PORT/docs/" | cmp -s - $OUT/www/docs/index.html && echo ok)"
check "the same under its second name" "$(curl -s --max-time 5 --cacert $CERT/server.pem --connect-to "also.k18cli.test:$PORT:127.0.0.1:$PORT" \
  "https://also.k18cli.test:$PORT/docs/" | cmp -s - $OUT/www/docs/index.html && echo ok)"
check "and not under one the certificate is not for" "$(curl -s --max-time 5 --cacert $CERT/server.pem --connect-to "other.k18cli.test:$PORT:127.0.0.1:$PORT" \
  -o /dev/null "https://other.k18cli.test:$PORT/docs/"; [[ $? == 60 ]] && echo ok)"
H=$("${CURL[@]}" -H 'Accept-Encoding: gzip' -D - -o /dev/null "https://k18cli.test:$PORT/docs/list.txt" | tr -d '\r')
check "a file that packs smaller goes compressed to a client that takes that" "$([[ $H == *"Content-Encoding: gzip"*"Vary: Accept-Encoding"* ]] &&
  "${CURL[@]}" --compressed "https://k18cli.test:$PORT/docs/list.txt" | cmp -s - $OUT/www/docs/list.txt && echo ok)"
check "and as it is to one that does not say so" "$("${CURL[@]}" -D $OUT/list.head "https://k18cli.test:$PORT/docs/list.txt" | cmp -s - $OUT/www/docs/list.txt &&
  ! grep -q Content-Encoding $OUT/list.head && echo ok)"
E=$(sed -n 's/^ETag: //p' <<<"$H")
check "a client that has it already is told so ($E)" "$([[ -n $E && $("${CURL[@]}" -H 'Accept-Encoding: gzip' -H "If-None-Match: $E" -o /dev/null -w '%{http_code} %{size_download}' \
  "https://k18cli.test:$PORT/docs/list.txt") == "304 0" ]] && echo ok)"
R=$(curl -s --max-time 5 -o /dev/null -w '%{http_code} %{redirect_url}' "http://127.0.0.1:$((PORT + 1000))/docs/")
check "port 80 sends everybody to the name ($R)" "$([[ $R == "301 https://k18cli.test/" ]] && echo ok)"
P="$(stat -c %a $OUT/os.bin) $(stat -c %a $OUT/disk.img) $(stat -c %a $OUT/regs.inc) $(stat -c %a $CERT/server.key) $(stat -c %a $OUT)"
check "image, disk, key and their folder are their owner's alone ($P)" "$([[ $P == "600 600 600 600 700" ]] && echo ok)"
check "how it was packed is kept for renew" "$(grep -q 'X-Test' $OUT/pack.conf && grep -q '^hsts=300$' $OUT/pack.conf && grep -q '^p80=redirect$' $OUT/pack.conf &&
  grep -q '^sans=also.k18cli.test$' $OUT/pack.conf && echo ok)"
check "pack says nothing about names when the certificate has them all" "$(grep -q "is not for" $OUT/pack.out || echo ok)"
# renew: 192.0.2.1 is nobody's address; none of this may so much as try to reach it
K0=$(sha256sum < $CERT/server.key)
T0=$(date +%s)
R=$(./k18 renew 192.0.2.1 $OUT 2>&1)
check "renew does nothing while the certificate has 30 days left" "$([[ $? == 0 && $R == *"nothing to do"* ]] && echo ok)"
R=$(./k18 renew 192.0.2.1 $OUT --days 90 --dry-run 2>&1)
check "with less left than it is told to keep, it would ask for one, for both names (${R:0:60}...)" \
  "$(grep -Eq 'would ask Let.s Encrypt for a certificate for DNS:k18cli.test,DNS:also.k18cli.test.*subject=.*CN *= *k18cli.test' <<<"$R" && echo ok)"
R=$(./k18 renew 192.0.2.1 $OUT --force --dry-run 2>&1)
check "and with --force" "$([[ $R == *"would ask Let's Encrypt"* ]] && echo ok)"
R=$(./k18 renew 192.0.2.1 $OUT --force --dry-run --email 'me@k18cli.test;id' 2>&1)
check "an address for Let's Encrypt with something in it that a shell reads is refused" "$([[ $? != 0 && $R == *"an address like"* ]] && echo ok)"
check "none of that took time, touched the key or left anything behind" \
  "$([[ $(( $(date +%s) - T0 )) -le 3 && $(sha256sum < $CERT/server.key) == "$K0" && -z $(ls -A $CERT | grep -v -E '^server\.(key|pem)$') ]] && echo ok)"
# A name the certificate lacks: pack says so, renew says so and does nothing (cron may
# run it), and --force would ask for it.
R=$(./k18 pack $OUT/www -n k18cli.test --san also.k18cli.test --san third.k18cli.test -c $CERT -o $OUT --hsts 300 --header 'X-Test: yes' 2>&1)
check "pack says which name the certificate is not for" "$([[ $R == *"is not for: third.k18cli.test"* ]] && echo ok)"
R=$(./k18 renew 192.0.2.1 $OUT 2>&1)
check "renew says so too, and does nothing" "$([[ $? == 0 && $R == *"nothing to do"*"not for: third.k18cli.test"* ]] && echo ok)"
R=$(./k18 renew 192.0.2.1 $OUT --force --dry-run 2>&1)
check "with --force it would ask for all three" "$([[ $R == *"for DNS:k18cli.test,DNS:also.k18cli.test,DNS:third.k18cli.test "* ]] && echo ok)"
# No certificate at all: one is made under a private CA, for every name, the first one first.
OUT2=build-k18test2 CERT2=cert-k18test2
rm -rf $CERT2
./k18 pack $OUT/www -n k18priv.test --san also.k18priv.test --san 192.0.2.7 -c $CERT2 -o $OUT2 > $OUT2.out 2>&1
check "a certificate made here is for all its names ($(cat $OUT2/name 2>/dev/null))" "$([[ $(cat $OUT2/name) == k18priv.test ]] && ! grep -q "is not for" $OUT2.out &&
  openssl verify -CAfile $OUT2/ca.pem -verify_hostname also.k18priv.test $CERT2/server.pem >/dev/null 2>&1 &&
  openssl verify -CAfile $OUT2/ca.pem -verify_ip 192.0.2.7 $CERT2/server.pem >/dev/null 2>&1 &&
  ! openssl verify -CAfile $OUT2/ca.pem -verify_hostname other.k18priv.test $CERT2/server.pem >/dev/null 2>&1 && echo ok)"
rm -f $OUT2.out
# An IP address is a SAN, never a Subject CN (Let's Encrypt rejects IP CNs).
OUT3=build-k18iptest
mkdir -p $OUT3
sed 's/^name=.*/name=192.0.2.7/' $OUT/pack.conf > $OUT3/pack.conf
R=$(./k18 renew 192.0.2.1 $OUT3 --force --dry-run 2>&1)
check "an IP address stays in SAN and out of the Subject CN ($R)" \
  "$([[ $R == *'IP:192.0.2.7'* && $R != *'CN'*'192.0.2.7'* ]] && echo ok)"
# A failed first forced renewal has no old key to restore, but still must start the old image.
OUT4=build-k18renew-fail CERT4=cert-k18renew-fail
rm -rf $OUT4 $CERT4
mkdir -p $OUT4 $CERT4 $OUT4/bin $CERT4/test-ca
printf 'site=/no/such/k18-test-site\nname=renew.k18cli.test\nip=\ncert=%s\np80=redirect\nhsts=0\ncache=600\nheaders=\nsans=\ncompress=1\nip6=\n' \
  "$(pwd)/$CERT4" > $OUT4/pack.conf
printf 'test image' > $OUT4/os.bin
printf 'renew.k18cli.test\n' > $OUT4/name
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout $CERT4/test-ca/key.pem -out $CERT4/test-ca/ca.pem -days 2 -subj /CN=k18-renew-test-ca 2>/dev/null
cat > $OUT4/bin/ssh <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *'touch /run/k18.hold'*) exit 0;;
  *'certbot certonly'*)
    d=$(mktemp -d)
    trap 'rm -rf "$d"' EXIT
    cat > "$d/request.csr"
    openssl x509 -req -in "$d/request.csr" -CA "$K18_TEST_CA/ca.pem" \
      -CAkey "$K18_TEST_CA/key.pem" -CAcreateserial -copy_extensions copy \
      -days 1 -out "$d/cert.pem" 2>/dev/null || exit 1
    cat "$d/cert.pem"
    exit 0;;
  *) printf '%s\n' "$*" >> "$K18_TEST_SSH_LOG"; cat >/dev/null; exit 0;;
esac
EOF
chmod +x $OUT4/bin/ssh
cat > $OUT4/bin/make <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x $OUT4/bin/make
cat > $OUT4/bin/curl <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x $OUT4/bin/curl
K18_TEST_CA="$(pwd)/$CERT4/test-ca" K18_TEST_SSH_LOG="$(pwd)/$OUT4/ssh.log" \
  PATH="$(pwd)/$OUT4/bin:$PATH" ./k18 renew 192.0.2.1 $OUT4 --grub --force --staging > $OUT4/renew.out 2>&1
RENEW_RC=$?
check "a failed first renewal still starts the old image ($(tail -n 2 $OUT4/renew.out | tr '\n' ' '))" \
  "$([[ $RENEW_RC != 0 && -s $OUT4/ssh.log ]] && grep -q 'cat > /boot/k18.bin.new' $OUT4/ssh.log && echo ok)"
# --no-compress: every file once, as it is; and renew would pack it that way again
./k18 pack $OUT/www -n k18priv.test -c $CERT2 -o $OUT2 --no-compress > /dev/null 2>&1
check "with --no-compress nothing is packed twice" "$(! grep -q 'Content-Encoding' $OUT2/site.json && grep -q '^compress=0$' $OUT2/pack.conf &&
  grep -q 'Content-Encoding' $OUT/site.json && grep -q '^compress=1$' $OUT/pack.conf && [[ $(stat -c %s $OUT2/site.bin) -lt $(stat -c %s $OUT/site.bin) ]] && echo ok)"
# --grub: a server whose ssh answers, but with other host keys than the ones we know for its address, is not reset
mkdir -p $OUT/bin
printf '#!/bin/sh\necho "@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @" >&2\necho "Host key verification failed." >&2\nexit 255\n' > $OUT/bin/ssh
chmod +x $OUT/bin/ssh
rm -f $OUT/was-reset
R=$(PATH=$OUT/bin:$PATH ./k18 deploy 192.0.2.7 $OUT --grub --reset "touch $OUT/was-reset" 2>&1)
check "deploy --grub: a server that answers ssh with host keys we do not know for it is left alone, and that is what is said (${R:0:70}...)" \
  "$([[ $? != 0 && $R == *"answers, but not to us: Host key verification failed."* && ! -e $OUT/was-reset ]] && echo ok)"
exit $bad
