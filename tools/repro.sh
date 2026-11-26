#!/usr/bin/env bash
# Is an image what the source makes of what goes into it, whoever makes it, wherever?
#
#   tools/repro.sh                  (seconds; the suite's `repro`) The same site, certificate and
#       settings are made into an image twice: in two folders, under another umask, in
#       another time zone and language, the site's files copied in another order. The
#       two must be the same bytes. Made a third time without the key (make KEYLESS=1:
#       from the certificate alone), the image must differ in the key's 32 bytes and in
#       nothing else, and its OUT/made must say the same three hashes. And the system
#       part, made a fourth time from OUT/made and the certificate alone (below), must
#       be the system part of the first.
#   tools/repro.sh system MADE CHAIN.pem
#       The system part of somebody else's image, made again here: MADE is that image's
#       OUT/made (what its owner publishes: no secret is in it), CHAIN.pem the
#       certificates its server shows (openssl s_client -showcerts). The source is this
#       checkout (MADE says which commit it was), the assembler has to be the one MADE
#       names. Says whether the bytes are the same; the site is not needed for it, nor
#       the programs that compressed it: of the site the system knows ten numbers, and
#       MADE has them.
cd "$(dirname "$0")/.." || exit 1
bad=0
check() { if [[ $2 == ok ]]; then echo "ok   $1"; else echo "FAIL $1"; bad=1; fi; }
T=$(mktemp -d /tmp/k18-repro.XXXXXX)
trap 'rm -rf "$T"' EXIT

# system MADE CHAIN DIR: the system part as MADE describes it, assembled in DIR; says its sha256
system() {
  local made=$1 chain=$2 d=$3 kv k v defs def
  mkdir -p "$d/cert" "$d/b"
  cp "$chain" "$d/cert/server.pem"
  { echo "; from $made"
    for kv in $(sed -n 's/^site.inc: //p' "$made"); do
      k=${kv%%=*} v=${kv#*=}
      [[ $k =~ ^(SITE_LEN|PT_MASK|AT_OFF|A_404|A_405|A_400|P80_OFF|P80_LEN|ETAG_AT|ETAG_LEN)$ && $v =~ ^[0-9]+$ ]] || { echo "repro.sh: what is '$kv' in $made?" >&2; return 1; }
      if [[ $k == SITE_LEN ]]; then echo "%assign $k $v"; else echo "$k equ $v"; fi
    done; } > "$d/b/site.inc"
  : > "$d/b/site.bin"
  KEYLESS=1 CERT="$d/cert" python3 tools/gen.py "$d/b" >/dev/null || return 1
  defs=()
  for def in $(sed -n 's/^defines: //p' "$made"); do      # (somebody else's words: -DNAME or -DNAME=number, nothing else)
    [[ $def =~ ^-D[A-Za-z0-9_]+(=[0-9A-Fa-fx]+)?$ ]] || { echo "repro.sh: what is '$def' in $made?" >&2; return 1; }
    defs+=("$def")
  done
  nasm -f bin "${defs[@]}" -I"$d/b/" -Isrc/ -o "$d/b/os.bin" src/os.asm || return 1
  sha256sum < "$d/b/os.bin" | cut -d' ' -f1
}

if [[ ${1:-} == system ]]; then
  [[ -f ${2:-} && -f ${3:-} ]] || { sed -n '2,/^cd /{/^cd /!p}' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
  want=$(sed -n 's/^  the system .*: //p' "$2")
  got=$(system "$2" "$3" "$T/s") || exit 1
  asm=$(sed -n 's/^assembler: //p' "$2")
  [[ $asm == "$(nasm -v)" ]] || echo "(the assembler here is '$(nasm -v)'; that image's was '$asm')"
  [[ $(sha256sum < "$T/s/b/gen.inc" | cut -d' ' -f1) == $(sed -n 's/^chain: //p' "$2") ]] || echo "(the certificates in $3 are not the chain that image was made with)"
  if [[ $got == "$want" ]]; then echo "the same: the system part $2 speaks of is what this source makes ($got)"; exit 0; fi
  echo "NOT the same: $2 says $want, this source makes $got"
  exit 1
fi

# The same twice, differently
mkdir -p "$T/one" "$T/a/much/longer/path/two" "$T/site" "$T/site2" "$T/cert"
python3 tools/mksite.py "$T/site" 0.1 >/dev/null || exit 1
( cd "$T/site" && find . -type f | sort -r | while read -r f; do mkdir -p "$T/site2/$(dirname "$f")"; cp "$f" "$T/site2/$f"; done )
SET="NAME=k18repro.test SAN=www.k18repro.test P80=redirect HSTS=300 IP6=fd00:15::15"
make -s B="$T/one" CERT="$T/cert" SITE="$T/site" $SET >/dev/null || { echo "FAIL the build"; exit 1; }
( umask 027; TZ=Pacific/Kiritimati LC_ALL=C LANG=tr_TR.UTF-8 make -s B="$T/a/much/longer/path/two" CERT="$T/cert" SITE="$T/site2" $SET >/dev/null ) || { echo "FAIL the build"; exit 1; }
check "the image is the same bytes, made twice (another folder, umask, time zone, language, order of files)" \
  "$(cmp -s "$T/one/os.bin" "$T/a/much/longer/path/two/os.bin" && cmp -s "$T/one/disk.img" "$T/a/much/longer/path/two/disk.img" && echo ok)"
# Without the key
mkdir -p "$T/pub" "$T/three"
cp "$T/cert/server.pem" "$T/pub/"
make -s B="$T/three" CERT="$T/pub" SITE="$T/site" KEYLESS=1 $SET >/dev/null || { echo "FAIL the build without the key"; exit 1; }
at=$(sed -n 's/^key: .* at //p' "$T/one/made")
diff=$(cmp -l "$T/one/os.bin" "$T/three/os.bin" | awk -v at="$at" '{ n++; if ($1 <= at || $1 > at + 32) out = 1 } END { print n + 0, out + 0 }')
check "made from the certificate alone, it differs in the key's 32 bytes and nowhere else" "$([[ ${diff% *} -ge 24 && ${diff% *} -le 32 && ${diff#* } == 0 ]] && echo ok)"
check "  and both say the same of themselves without the key (OUT/made: three hashes)" \
  "$([[ -n $(grep '^  the image' "$T/one/made") && $(grep '^  the' "$T/one/made") == $(grep '^  the' "$T/three/made") ]] && echo ok)"
check "  the one that has no key says so" "$(grep -q '^key: none' "$T/three/made" && ! grep -q '^key: none' "$T/one/made" && echo ok)"
# The system part from what OUT/made says
got=$(system "$T/one/made" "$T/pub/server.pem" "$T/four")
check "the system part, made again from OUT/made and the certificates alone, is the same bytes" \
  "$([[ -n $got && $got == $(sed -n 's/^  the system .*: //p' "$T/one/made") ]] && echo ok)"
sed -i 's/^site.inc: SITE_LEN=\([0-9]*\)/site.inc: SITE_LEN=\1 PT_MASK=1/; s/ PT_MASK=[0-9]*//2' "$T/one/made"
got=$(system "$T/one/made" "$T/pub/server.pem" "$T/five")
check "  and is not, if one of the ten numbers is another" "$([[ -n $got && $got != $(sed -n 's/^  the system .*: //p' "$T/one/made") ]] && echo ok)"
[[ $bad == 0 ]] && echo "all ok" || echo "FAILED"
exit $bad
