# Sourced by the scripts that start QEMU: `qemu DISK NETDEV [EXTRA...]` is the machine
# (shaped like the server: Q35, modern virtio-net behind a root port, virtio-scsi disk;
# SMP processors, default 2, MEM MiB, default 256; KVM unless KVM=0 or /dev/kvm is not
# there; EFI=1: with UEFI firmware in place of the BIOS, OVMF, which is where OVMF says or
# where Debian puts it). When PORT is set, also sets HPORT, URL, CURL and NOCA, and `boot`
# starts QEMU on user networking and waits for it.

B=${B:-build}
NAME=$(cat "$B/name")
GUEST=$(cat "$B/ip")                                    # the address the image was built with,
GUEST=${GUEST:-10.0.2.15}                               # or the one QEMU's DHCP server will give it
ACCEL=(-cpu max)
if [[ ${KVM:-1} == 1 && -w /dev/kvm ]]; then ACCEL=(-accel kvm -cpu host); fi
FIRM=()
if [[ ${EFI:-} == 1 ]]; then FIRM=(-bios "${OVMF:-/usr/share/ovmf/OVMF.fd}"); fi

if [[ -n ${PORT:-} ]]; then
  HPORT=${HPORT:-$((PORT + 1000))}                      # where the guest's port 80 is forwarded to
  URL="https://${NAME}:${PORT}/"
  CURL=(curl -s --max-time 10 --connect-to "${NAME}:${PORT}:127.0.0.1:${PORT}")
  NOCA=("${CURL[@]}")                                   # the same, trusting only the system's roots
  if [[ -s $B/ca.pem ]]; then CURL+=(--cacert "$B/ca.pem"); fi
fi

qemu() {
  local disk=$1 net=$2; shift 2
  exec qemu-system-x86_64 -nodefaults -display none -no-reboot -machine q35 \
    -smp "${SMP:-2}" "${ACCEL[@]}" -m "${MEM:-256}" "${FIRM[@]}" "$@" \
    -drive "file=$disk,format=raw,if=none,id=d0,snapshot=on" -netdev "$net,id=n0" \
    -device pcie-root-port,id=rp1,chassis=1 -device virtio-net-pci,bus=rp1,netdev=n0,disable-legacy=on,romfile= \
    -device pcie-root-port,id=rp2,chassis=2 -device virtio-scsi-pci,bus=rp2 -device scsi-hd,drive=d0
}

slirp() {
  echo "user,net=${GUEST%.*}.0/24,host=${GUEST%.*}.2,hostfwd=tcp:127.0.0.1:${PORT}-${GUEST}:443,hostfwd=tcp:127.0.0.1:${HPORT}-${GUEST}:80"
}

boot() {
  QEMU_LOG=$(mktemp)
  qemu "${IMG%os.bin}disk.img" "$(slirp)" >"$QEMU_LOG" 2>&1 &
  QEMU_PID=$!
  trap 'kill $QEMU_PID 2>/dev/null || true; rm -rf "$QEMU_LOG" ${TMP:-}' EXIT
  for _ in $(seq 1 40); do
    "${CURL[@]}" -o /dev/null "$URL" && return 0
    sleep 0.25
  done
  return 0   # the caller's first real request reports the failure
}
