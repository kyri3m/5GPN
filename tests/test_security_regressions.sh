#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
importer="${root}/rules-import.py"
quick="${root}/quick-install.sh"

fail() { echo "$1" >&2; exit 1; }

body="$(cat "$install")"
quick_body="$(cat "$quick")"

# Host/port values from node links must never be interpolated into a shell.
[[ "$body" != *'bash -c "exec 3<>/dev/tcp/${host}/${port}"'* ]] || \
  fail "exit reachability still interpolates node host into bash -c"
[[ "$body" == *'python3 - "$host" "$port"'* ]] || \
  fail "exit reachability must pass host/port as Python argv"

# The installer must never silently replace the machine resolver configuration.
[[ "$body" != *'cat > /etc/resolv.conf'* ]] || \
  fail "installer must not overwrite /etc/resolv.conf"
[[ "$body" != *'nameserver 1.1.1.1
nameserver 8.8.8.8'* ]] || \
  fail "installer must not inject public DNS into /etc/resolv.conf"

# Remote rule imports are HTTPS-only; local files and internal URL schemes are rejected.
if python3 "$importer" --check-url file:///etc/hosts >/dev/null 2>&1; then
  fail "rules importer accepted file:// URL"
fi
if python3 "$importer" --check-url http://127.0.0.1/ >/dev/null 2>&1; then
  fail "rules importer accepted non-HTTPS/private URL"
fi

# Quick installer must install this fork, not the unrelated upstream project.
[[ "$quick_body" == *'REPO="kyri3m/5GPN"'* ]] || \
  fail "quick installer points at the wrong repository"
[[ "$quick_body" == *'DIR="${PGW_SRC_DIR:-/root/5GPN}"'* ]] || \
  fail "quick installer default directory is inconsistent"

echo "security regressions policy OK"
