#!/usr/bin/env bash
# Start $B/os.bin (default build-hz) on a server that runs Linux with GRUB, once: any later
# reset boots Linux again. Delegates to `./k18 deploy --grub`.
# Usage: B=build-hz tools/deploy.sh [root@]a.b.c.d [--reset 'COMMAND']
set -euo pipefail
cd "$(dirname "$0")/.."
exec ./k18 deploy "${1#root@}" "${B:-build-hz}" --grub "${@:2}"
