#!/usr/bin/env bash
# The test of what happens when a slot changes hands while its connection's timer has it
# in hand (tools/racetest.py has the story): an image with 32 slots in which "long quiet"
# is two minutes and the timer stops at the point in question (make RACE=N IDLE=1 CAP=32),
# with tools/mksite.py's site in it, over tap, on two processors or more.
#   unshare -Urn tools/racetest.sh 1     the slot is taken before the timer says "in use"
#   unshare -Urn tools/racetest.sh 2     and after
#   unshare -Urn tools/racetest.sh 3     another thing two processors can do to each other: the
#                                        one free slot of a bucket is gone between being counted
#                                        and being taken (make RACE=3 CAP=16; any number of
#                                        processors: the image does it to itself; 5 s)
cd "$(dirname "$0")/.." || exit 1
N=${1:-1}
if [[ ${SMP:-2} == 1 && $N != 3 ]]; then echo "ok: (one processor: nobody to take a slot from under its timer)"; exit 0; fi
export B=${B:-build-race$N}
mkdir -p "$B"
python3 tools/mksite.py "$B/www" >/dev/null || exit 1
if [[ $N == 3 ]]; then    # (a bucket in each table, and nothing to wait for)
  make -s B="$B" SITE="$B/www" CERT="${CERT:-cert}" RACE=3 CAP=16 >/dev/null || { echo "BUILD FAILED"; exit 1; }
  MON=/tmp/k18mon.r3.$$
  trap 'rm -f "$MON"' EXIT
  MON=$MON ./tap.sh python3 tools/racetest.py 3
  exit $?
fi
make -s B="$B" SITE="$B/www" CERT="${CERT:-cert}" RACE="$N" IDLE=1 CAP=32 >/dev/null || { echo "BUILD FAILED"; exit 1; }
exec env DELAY=20 ./tap.sh python3 tools/racetest.py "$N"
