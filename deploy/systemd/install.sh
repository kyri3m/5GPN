#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="${1:-}"
DEST_DIR="${2:-/etc/systemd/system}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "$BASE_DIR" == /* && "$BASE_DIR" != *$'\n'* ]] || { echo "usage: $0 /absolute/install/path [unit-dir]" >&2; exit 2; }
mkdir -p "$DEST_DIR"
for src in "$SRC_DIR"/*.service; do
  dst="$DEST_DIR/${src##*/}"
  python3 - "$src" "$dst" "$BASE_DIR" <<'PY'
import os, sys, tempfile
src, dst, base = sys.argv[1:]
data = open(src, encoding='utf-8').read().replace('@BASE_DIR@', base)
fd, tmp = tempfile.mkstemp(prefix='.unit-', dir=os.path.dirname(dst))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o644); os.replace(tmp, dst)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
done
if [[ -d "$BASE_DIR" ]] && command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$DEST_DIR"/*.service
fi
