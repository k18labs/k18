#!/usr/bin/env bash
# The tool's way onto a machine that is k18's alone (k18 publish, k18 deploy, k18 renew),
# as far as it goes without a host:
#
#   unshare -Urn tools/hosttest.sh        (two and a half minutes)
#
# The machine is made up. Its disk is a file; its rescue system is this shell, with the
# few commands that would touch a real machine replaced (lsblk, blockdev, blkdiscard,
# reboot, apt-get, and certbot, which here is a certificate authority of our own that
# signs what it is asked for); ssh to it is a script (K18_SSH) that reaches that shell
# while the machine is "in its rescue system", and nothing otherwise; and "start from the
# disk" boots the file in QEMU, with its ports 443 and 80 at 127.0.0.1 of this otherwise
# empty network. What a host's rescue system does with the same commands is not seen here:
# docs/server.md says what was seen at Hetzner.
#
# What must hold: a machine that has a Linux on its disk is not written to unless told how
# it gets into its rescue system, and one that nothing vouches for is not touched without
# --first; then it is given a new key and a certificate, the site, and serves it. The
# next publish finds the key on the machine's own disk, keeps key and certificate, and
# changes the site; with --if-due it does nothing and touches nothing while the
# certificate has long to go, and gets a new key and certificate when it has not. A
# machine whose disk does not hold the key of the certificate the site has just shown is
# sent nothing and started as it was: one with another key, with none, with the site's
# certificate where the key should be, or with a key file that has the site's public half
# pasted in (the last two have the right fingerprint, and nothing else). If no
# certificate comes, the machine is started as it was. k18 deploy and k18 renew do the
# same for an image packed here, and hold the machine to the key they have for it.
# A certificate on the machine's disk that nobody believes (a private CA's) is not kept
# by k18 publish, unless with --staging; and a rescue system that calls its disk what
# no disk is called gets no command with that name in it.
cd "$(dirname "$0")/.." || exit 1
ip link set lo up 2>/dev/null || { echo "FAIL: run it as: unshare -Urn tools/hosttest.sh"; exit 1; }
M=$(mktemp -d /tmp/k18-host.XXXXXX)
trap '[[ -f $M/qemu.pid ]] && kill "$(cat "$M/qemu.pid")" 2>/dev/null; rm -rf "$M"' EXIT
mkdir -p "$M/bin" "$M/b" "$M/site"
HERE=$PWD
bad=0
check() { if [[ $2 == ok ]]; then echo "ok   $1"; else echo "FAIL $1"; bad=1; fi; }

# The certificate authority that stands in for Let's Encrypt, and is all that is believed here
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$M/ca.key" -out "$M/ca.pem" -days 365 \
  -subj "/CN=k18 test CA" -addext basicConstraints=critical,CA:TRUE 2>/dev/null || { echo "FAIL openssl"; exit 1; }
export SSL_CERT_FILE=$M/ca.pem CURL_CA_BUNDLE=$M/ca.pem

# The machine: a disk of 64 MiB with something on it, and a Linux that lives there
truncate -s 64M "$M/disk"
echo "a Linux" | dd of="$M/disk" conv=notrunc 2>/dev/null
echo linux > "$M/state"
echo 90 > "$M/certdays"
echo 0 > "$M/certbots"
: > "$M/b/ip"; echo x > "$M/b/name"

cat > "$M/ssh" <<EOF
#!/usr/bin/env bash
# ssh [-o OPTION]... root@HOST COMMAND: the machine's root shell, while there is one
while [[ \$1 == -o ]]; do shift 2; done
shift
case \$(cat "$M/state") in rescue|linux) ;; *) exit 255;; esac
PATH="$M/bin:\$PATH" exec bash -c "\$*"
EOF
cat > "$M/rescue" <<EOF
#!/usr/bin/env bash
# what a host's "into the rescue system" does: whatever ran is gone, a Linux in memory is up
[[ -f "$M/qemu.pid" ]] && kill "\$(cat "$M/qemu.pid")" 2>/dev/null
rm -f "$M/qemu.pid"
echo rescue > "$M/state"
EOF
cat > "$M/bin/lsblk" <<EOF
#!/usr/bin/env bash
case "\$*" in
  "-dnpo NAME,TYPE,RM") if [[ -f "$M/odd" ]]; then echo "$M/di;k disk 0"; else echo "$M/disk disk 0"; fi
                        [[ -f "$M/two" ]] && echo "$M/disk2 disk 0";;
  "-nro MOUNTPOINT $M/disk") [[ \$(cat "$M/state") == linux ]] && echo /;;
  *) echo "lsblk \$*?" >&2; exit 1;;
esac
exit 0
EOF
cat > "$M/bin/blockdev" <<EOF
#!/usr/bin/env bash
[[ \$1 == --getsize64 ]] && stat -c %s "\$2"
EOF
cat > "$M/bin/blkdiscard" <<EOF
#!/usr/bin/env bash
n=\$(stat -c %s "\$2") && : > "\$2" && truncate -s "\$n" "\$2"
EOF
cat > "$M/bin/reboot" <<EOF
#!/usr/bin/env bash
# the machine starts from its disk
echo disk > "$M/state"
cd "$HERE" && B="$M/b" source tools/vm.sh
( qemu "$M/disk" "user,hostfwd=tcp:127.0.0.1:443-:443,hostfwd=tcp:127.0.0.1:80-:80" >/dev/null 2>&1 & echo \$! > "$M/qemu.pid" )
EOF
cat > "$M/bin/apt-get" <<EOF
#!/usr/bin/env bash
exit 0
EOF
cat > "$M/bin/certbot" <<EOF
#!/usr/bin/env bash
# certbot certonly ... --csr FILE ... --fullchain-path FILE: the request, signed by our CA
while ((\$#)); do
  case \$1 in --csr) csr=\$2; shift;; --fullchain-path) out=\$2; shift;; esac
  shift
done
echo \$((\$(cat "$M/certbots") + 1)) > "$M/certbots"
[[ -f "$M/nocert" ]] && exit 1
openssl x509 -req -in "\$csr" -CA "$M/ca.pem" -CAkey "$M/ca.key" -CAcreateserial -copy_extensions copyall \
  -days "\$(cat "$M/certdays")" -out "\$out" 2>/dev/null
EOF
chmod +x "$M/ssh" "$M/rescue" "$M/bin"/*
export K18_SSH=$M/ssh
N=k18pub.test
page() { curl -s --max-time 5 --connect-to "$1:443:127.0.0.1:443" "https://$1/"; }
cert() { timeout 5 openssl s_client -connect 127.0.0.1:443 -servername $N </dev/null 2>/dev/null | openssl x509 -noout "$@"; }
image() { head -c $((8 << 20)) "$M/disk" | sha256sum; }
k18() { ./k18 "$@" > "$M/out" 2>&1; RC=$?; [[ -z ${V:-} ]] || sed 's/^/     | /' "$M/out"; }   # (V=1: what the tool says)
came() { for _ in $(seq 1 80); do [[ $(page $N) == "$1" ]] && return; sleep 0.25; done; echo "     (the machine did not come back with $1)"; }
idblock() { dd of="$M/disk" bs=65536 seek=1023 conv=notrunc 2>/dev/null; }      # (the disk's last 64 KiB: who the machine is)
said() { grep -q -- "$1" "$M/out"; }

echo "<p>one</p>" > "$M/site/index.html"
was=$(image)
k18 publish "$M/site" 127.0.0.1 -n $N --first
check "a machine with a Linux on its disk is not written to unless told how it gets into its rescue system" \
  "$([[ $RC != 0 && $(image) == "$was" && $(cat "$M/state") == linux ]] && said "lives on the disk" && echo ok)"
k18 publish "$M/site" 127.0.0.1 -n $N --san www.$N --rescue "$M/rescue"
check "nor is it touched while nothing would vouch for it there (no site shows a certificate)" \
  "$([[ $RC != 0 && $(image) == "$was" && $(cat "$M/state") == linux ]] && said "nothing would vouch" && echo ok)"
k18 publish "$M/site" 127.0.0.1 -n $N --san www.$N --rescue "$M/rescue" --first
check "with --first it is given a new key, a certificate and the site, and serves it" \
  "$([[ $RC == 0 && $(page $N) == "<p>one</p>" && $(cat "$M/certbots") == 1 ]] && echo ok)"
check "  under its second name too" "$([[ $(page www.$N) == "<p>one</p>" ]] && said "https://www.$N/ too" && echo ok)"
check "  and nothing of it is left here" "$(! ls -d /dev/shm/k18.* "${TMPDIR:-/tmp}"/k18.?????? >/dev/null 2>&1 && echo ok)"
fp=$(cert -fingerprint)

echo "<p>two</p>" > "$M/site/index.html"
k18 publish "$M/site" 127.0.0.1 -n $N --san www.$N --rescue "$M/rescue"
check "the next publish finds the key on the machine's disk: the site changes, key and certificate stay" \
  "$([[ $RC == 0 && $(page $N) == "<p>two</p>" && $(cert -fingerprint) == "$fp" && $(cat "$M/certbots") == 1 ]] && said "the same machine" && echo ok)"

pid=$(cat "$M/qemu.pid")
k18 publish "$M/site" 127.0.0.1 -n $N --san www.$N --rescue "$M/rescue" --if-due
check "--if-due: nothing is done, and nothing touched, while the certificate has long to go" \
  "$([[ $RC == 0 && $(cat "$M/qemu.pid") == "$pid" ]] && kill -0 "$pid" && said "nothing to do" && echo ok)"
k18 publish "$M/site" 127.0.0.1 -n $N --san www.$N --san more.$N --rescue "$M/rescue" --if-due
check "  but a name it lacks is reason enough: a new key and certificate" \
  "$([[ $RC == 0 && $(cert -fingerprint) != "$fp" && $(cat "$M/certbots") == 2 && $(page more.$N) == "<p>two</p>" ]] && echo ok)"
echo 20 > "$M/certdays"
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue" --days 100
key=$(cert -pubkey | sha256sum)
check "a certificate that ends within --days gets its successor (here: one that lasts 20)" \
  "$([[ $RC == 0 && $(cat "$M/certbots") == 3 ]] && ! cert -checkend $((21 * 86400)) >/dev/null && echo ok)"
echo 90 > "$M/certdays"
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue" --if-due
check "  and so does that one on the next --if-due, with a new key" \
  "$([[ $RC == 0 && $(cat "$M/certbots") == 4 && $(cert -pubkey | sha256sum) != "$key" ]] && cert -checkend $((60 * 86400)) >/dev/null && echo ok)"

touch "$M/nocert"
echo "<p>three</p>" > "$M/site/index.html"
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue" --days 100
came "<p>two</p>"
check "if no certificate comes, the machine is started as it was" \
  "$([[ $RC != 0 && $(page $N) == "<p>two</p>" ]] && said "as it was" && echo ok)"
rm "$M/nocert"

k18 publish "$M/site" 127.0.0.1 -n $N
check "a machine that is running is not reached without --rescue" "$([[ $RC != 0 && $(page $N) == "<p>two</p>" ]] && said "not in its rescue system" && echo ok)"

# What answers in the rescue system is not our machine: its disk has another key; none;
# the site's certificate where the key should be; a key file with the site's public half
# pasted in. (The last two say the right thing to whoever only asks which key they are.)
was=$(image)
mkdir -p "$M/other"
tail -c 65536 "$M/disk" > "$M/id.ours"
timeout 5 openssl s_client -connect 127.0.0.1:443 -servername $N </dev/null 2>/dev/null | openssl x509 > "$M/other/site.pem"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$M/other/server.key" -out "$M/other/server.pem" \
  -days 30 -subj "/CN=$N" 2>/dev/null
refused() {   # what the check is called, what the tool must have said
  k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue"
  came "<p>two</p>"
  check "$1" "$([[ $RC != 0 && $(image) == "$was" && $(page $N) == "<p>two</p>" ]] && said "$2" && said "started as it was" && echo ok)"
}
{ echo "k18 identity"; cat "$M/other/server.key" "$M/other/server.pem"; } | idblock
refused "a machine whose disk has another key than the site has just shown is sent nothing, and started as it was" "does not have the key"
head -c 65536 /dev/zero | idblock
refused "  nor one whose disk has none" "has no key at the end of its disk"
{ echo "k18 identity"; sed '1s/$/\r/' "$M/other/site.pem"; cat "$M/other/site.pem"; } | idblock
refused "  nor one that has the site's certificate where the key should be" "has no key at the end of its disk"
# (a key in the form that says its public half in so many bytes at its end: 65 of them, here the site's)
openssl ecparam -genkey -name prime256v1 -noout -outform DER 2>/dev/null | head -c -65 > "$M/other/spliced.der"
openssl x509 -pubkey -noout -in "$M/other/site.pem" | openssl pkey -pubin -outform DER | tail -c 65 >> "$M/other/spliced.der"
openssl ec -inform DER -in "$M/other/spliced.der" -out "$M/other/spliced.key" 2>/dev/null
{ echo "k18 identity"; cat "$M/other/spliced.key" "$M/other/site.pem"; } | idblock
refused "  nor one whose key file has the site's public half and another secret" "has no key at the end of its disk"
check "    (which has the fingerprint of the site's key, as far as openssl says)" \
  "$([[ $(openssl pkey -in "$M/other/spliced.key" -pubout -outform DER 2>/dev/null | sha256sum) == $(openssl x509 -pubkey -noout -in "$M/other/site.pem" | openssl pkey -pubin -outform DER | sha256sum) ]] && echo ok)"
idblock < "$M/id.ours"

touch "$M/two"; truncate -s 64M "$M/disk2"
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue"
came "<p>two</p>"
check "a machine with two disks: which is to be k18's has to be said (and it is started as it was)" "$([[ $RC != 0 && $(page $N) == "<p>two</p>" ]] && said "several disks" && echo ok)"
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue" --disk "$M/disk"
check "  and with --disk it is that one" "$([[ $RC == 0 && $(page $N) == "<p>three</p>" && $(sha256sum < "$M/disk2") == $(head -c 64M /dev/zero | sha256sum) ]] && echo ok)"
rm "$M/two"
# (what the far side says its disk is called becomes part of commands for it)
touch "$M/odd" "$M/di;k"
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue"
came "<p>three</p>"
check "a rescue system that calls its disk what no disk is called is sent nothing (and the machine started as it was)" \
  "$([[ $RC != 0 && $(page $N) == "<p>three</p>" ]] && said "which no disk is" && echo ok)"
rm "$M/odd"

# An image packed here, with a private CA of its own: k18 deploy, and k18 renew
D=k18dep.test
unset SSL_CERT_FILE CURL_CA_BUNDLE
dpage() { curl -s --max-time 5 --cacert "$M/o/ca.pem" --connect-to "$D:443:127.0.0.1:443" "https://$D/"; }
k18 pack "$M/site" -n $D -c "$M/c" -o "$M/o" && k18 deploy 127.0.0.1 "$M/o" --rescue "$M/rescue"
CURL_CA_BUNDLE=$M/ca.pem came "<p>three</p>"
check "k18 deploy: an image with another key than the machine has is not written without --first" \
  "$([[ $RC != 0 ]] && said "does not have the key" && echo ok)"
k18 deploy 127.0.0.1 "$M/o" --rescue "$M/rescue" --first
check "  with --first it is, and serves" "$([[ $RC == 0 && $(dpage) == "<p>three</p>" ]] && echo ok)"
echo "<p>four</p>" > "$M/site/index.html"
k18 pack "$M/site" -n $D -c "$M/c" -o "$M/o" && k18 deploy 127.0.0.1 "$M/o" --rescue "$M/rescue"
check "  and the next one needs no --first: the machine has the key of the certificate it showed" \
  "$([[ $RC == 0 && $(dpage) == "<p>four</p>" ]] && said "the same machine" && echo ok)"
export SSL_CERT_FILE=$M/ca.pem CURL_CA_BUNDLE=$M/ca.pem
k18 renew 127.0.0.1 "$M/o" --rescue "$M/rescue" --force
check "k18 renew: a new key and a certificate from the authority, packed as before, written and served" \
  "$([[ $RC == 0 && $(page $D) == "<p>four</p>" && ! -e $M/c/ca.pem && -f $M/c/old/server.key ]] && echo ok)"
k18 renew 127.0.0.1 "$M/o" --rescue "$M/rescue"
check "  and nothing while that one has long to go" "$([[ $RC == 0 ]] && said "nothing to do" && kill -0 "$(cat "$M/qemu.pid")" && echo ok)"

# A machine whose disk holds a certificate that nobody believes: an image packed here
# with a private CA's, good until 2049 (and for a name that is an IPv6 address as well).
# k18 publish keeps that only where no better is asked for (--staging).
unset SSL_CERT_FILE CURL_CA_BUNDLE
k18 pack "$M/site" -n $N --san ::1 -c "$M/c2" -o "$M/o2" && k18 deploy 127.0.0.1 "$M/o2" --rescue "$M/rescue" --first
check "k18 deploy: a name that is an IPv6 address is fetched as one" "$([[ $RC == 0 ]] && said "https://\[::1\]/ too" && echo ok)"
export SSL_CERT_FILE=$M/ca.pem CURL_CA_BUNDLE=$M/ca.pem
n=$(cat "$M/certbots")
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue" --first --staging
check "k18 publish --first --staging keeps a certificate that nobody believes, and says that it did not check it" \
  "$([[ $RC == 0 && $(cat "$M/certbots") == "$n" ]] && ! page $N >/dev/null && said "does not check the certificate" && echo ok)"
k18 publish "$M/site" 127.0.0.1 -n $N --rescue "$M/rescue" --first
check "  and without --staging gets one that is believed, with a new key" \
  "$([[ $RC == 0 && $(cat "$M/certbots") == $((n + 1)) && $(page $N) == "<p>four</p>" ]] && echo ok)"

[[ $bad == 0 ]] && echo "all ok" || { echo "FAILED (the tool's last words:)"; sed 's/^/    /' "$M/out"; }
exit $bad
