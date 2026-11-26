#!/usr/bin/env bash
# What the tests "from outside" run with, fetched into ext/ (not in git; 150 MB), each at
# the version these tests were written against:
#   - Project Wycheproof's test vectors            make outside   (test/outside.py)
#   - Valgrind (Ubuntu's package, unpacked: no root) make ct        (test/ct.c)
#   - tlsfuzzer, with tlslite-ng and ecdsa          tools/tlsfuzz.sh
#     tools/outside.sh fetch
# Needs git, pip, apt and dpkg-deb, and the network.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ ${1:-} == fetch ]] || { sed -n '2,8p' "$0"; exit 1; }
mkdir -p ext
cd ext
get() {  # folder, repository, commit
  mkdir -p "$1"
  ( cd "$1"
    [[ -d .git ]] || { git init -q; git remote add origin "$2"; }
    [[ $(git rev-parse -q --verify HEAD) == "$3" ]] || { git fetch -q --depth 1 origin "$3"; git checkout -q FETCH_HEAD; } )
  echo "ext/$1: $3"
}
get wycheproof https://github.com/C2SP/wycheproof.git 65ca494727a52944c204441c860b039e6786b99b
get tlsfuzzer https://github.com/tlsfuzzer/tlsfuzzer.git 607cfc2b76644a9d99c0bb4242685007810631a9
[[ -d py/tlslite && -d py/ecdsa ]] || pip install --quiet --target py --break-system-packages 'tlslite-ng==0.9.0b2' 'ecdsa==0.19.2'
echo "ext/py: tlslite-ng 0.9.0b2, ecdsa 0.19.2"
if [[ ! -x valgrind/usr/bin/valgrind ]]; then
  mkdir -p deb valgrind
  ( cd deb && apt download valgrind >/dev/null )
  dpkg-deb -x deb/valgrind_*.deb valgrind
fi
echo "ext/valgrind: $(VALGRIND_LIB=$PWD/valgrind/usr/libexec/valgrind valgrind/usr/bin/valgrind --version)"
