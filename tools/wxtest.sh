#!/usr/bin/env bash
# That only code is executed and neither code nor site is written is checked by doing each
# of the things that must not be possible, once, in an image built to do just that after
# it has set everything up (make WXTEST=n: write to the code, run the stack, write to the
# site, run the site, run a packet buffer, run what lies right behind the code, run what
# lay in front of it). Each must be the machine's end: a fault, and with no handlers a
# reset, which makes this QEMU quit. An image that does none of them (WXTEST=0) must stay
# up and serve.
# What is run is a byte that says "return", so that memory which could be run would give
# the machine back and it would go on: the first such byte of the site, and its last (of
# a site of over 1 MiB, whose end lies in large pages); a byte put right behind the code
# for this; and a byte put at 1 MiB before the image was loaded, a few bytes above it
# (`start` zeroes what lies between). The site is run twice: the test's own of 80 files,
# and one of a single small file, all of which lies in the first page behind the code.
# And what a loader left where the other processors start, in a page that can be executed
# (12: the boot sector reads the image through that page): if anything is left of it, the
# machine goes on.
# The controls: the same images with the page behind the code left executable and what
# loaders left not zeroed (make WXOPEN=1) must go on, or these runs would show nothing.
# That there are no handlers is checked too (6, and 7 on another processor): a fault while
# page 0, where the frame in hand lies, holds what reads as an interrupt gate to our own
# code. A processor whose table of handlers is at address 0 (the one a BIOS leaves, and
# the one a processor is started up with) goes on from where the gate says; one that was
# told it has none (`start`, `apstart`) can't.
# And two hardware random-source failures must never produce a response: a repeated output
# (8) resets the machine; a source which never succeeds (13) stalls before the server starts.
#   tools/wxtest.sh          (SMP=n for other machines than 2 processors; PORT=n for other
#                            ports than 8520 and up; EFI=1: started by UEFI firmware)
cd "$(dirname "$0")/.." || exit 1
export B=build-wx
mkdir -p $B/www $B/one
python3 tools/mksite.py $B/www >/dev/null || exit 1
printf '<!doctype html>\n<title>caf\xc3\xa9</title>\n<p>One small file.\n' > $B/one/index.html
WHAT=("none of it" "writing to the code" "running the stack" "writing to the site" "running the site" "running a packet buffer"
  "a fault where the frame in hand names a handler" "the same on another processor"
  "a random number generator that says the same twice" "running the end of a long site"
  "running what lies right behind the code" "running what lay in front of the code"
  "something left in the page where the other processors start" "an RDRAND source that never succeeds")
P0=${PORT:-8520}
bad=0
i=0
# run N SITE OPEN: the image that does N, with that site (and, OPEN=1, as the control has it): served? how did QEMU end?
run() {
  local n=$1 site=$2 open=$3 pad=
  make -s -B B=$B SITE=$B/$site WXTEST=$n WXOPEN=$open >/dev/null 2>&1 || { echo "BUILD FAILED (WXTEST=$n)"; exit 1; }
  if [[ $n == 11 && $(cat $B/delta) == -DDELTA=0 ]]; then     # (an image at 1 MiB exactly has nothing in front of it: 64 bytes more of code move it)
    make -s -B B=$B SITE=$B/$site WXTEST=$n WXOPEN=$open WXPAD=1 >/dev/null 2>&1 && [[ $(cat $B/delta) != -DDELTA=0 ]] || { echo "BUILD FAILED (WXTEST=$n, WXPAD)"; exit 1; }
  fi
  i=$((i + 1))
  PORT=$((P0 + i))
  HPORT=$((P0 + 1000 + i))
  IMG=$B/os.bin
  source tools/vm.sh
  LOG=$(mktemp)
  # (a "return" at 1 MiB, there before anything is loaded: QEMU puts it into the memory it starts with)
  qemu "$B/disk.img" "$(slirp)" -device loader,addr=0x100000,data=0xC3,data-len=1 >"$LOG" 2>&1 &
  pid=$!
  served=no
  for _ in $(seq 1 40); do
    kill -0 $pid 2>/dev/null || break
    if "${CURL[@]}" --connect-timeout 0.25 --max-time 0.5 -o /dev/null "$URL"; then served=yes; break; fi
    sleep 0.25
  done
  # how it ended: by itself and without a word (the machine started over: -no-reboot), or not at all, or as a QEMU that could not run
  ended=running
  if ! kill -0 $pid 2>/dev/null; then
    wait $pid && [[ ! -s $LOG ]] && ended=reset || ended="QEMU failed: $(head -c 200 "$LOG" | tr '\n' ' ')"
  fi
  kill $pid 2>/dev/null
  wait $pid 2>/dev/null
  rm -f "$LOG"
}
end() {    # N SITE NOTE: that run must be the machine's end
  run "$1" "$2" ""
  [[ $served == no && $ended == reset ]] && echo "ok   ${WHAT[$1]}$3 is the machine's end" || { echo "FAIL ${WHAT[$1]}$3: not the machine's end (served: $served; $ended)"; bad=1; }
}
run 0 www ""
[[ $served == yes ]] && echo "ok   an image that does ${WHAT[0]} serves" || { echo "FAIL the image that does ${WHAT[0]} does not serve ($ended)"; bad=1; }
for n in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if [[ $n == 7 && ${SMP:-2} == 1 ]]; then echo "ok   (${WHAT[$n]}: this machine has no other)"; continue; fi
  end $n www ""
done
run 13 www ""
[[ $served == no && $ended == running ]] && echo "ok   a stalled RDRAND source never serves" || { echo "FAIL a stalled RDRAND source served or reset unexpectedly (served: $served; $ended)"; bad=1; }
end 4 one " (a site of one small file, in the first page behind the code)"
for c in "4 one" "10 one" "11 one" "12 www"; do
  set -- $c
  if [[ $1 == 12 && ${EFI:-} == 1 ]]; then echo "ok   (no control for ${WHAT[12]}: started by OVMF, EFI=1, that page is empty as it comes)"; continue; fi
  run $1 $2 1
  [[ $served == yes ]] && echo "ok   the control: in an image left open, ${WHAT[$1]} is not the machine's end" || { echo "FAIL the control: ${WHAT[$1]} was the machine's end in an image left open (served: $served; $ended)"; bad=1; }
done
exit $bad
