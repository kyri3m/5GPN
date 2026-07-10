#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/sniproxy.conf" <<'EOF'
user pxout
resolver {
    nameserver 22.22.22.22
    mode ipv4_only
}
listener 80 {
    proto http
}
EOF

python3 - "$root/install.sh" "$tmp/rewrite.py" <<'PY'
import sys
text=open(sys.argv[1], encoding="utf-8").read()
start='python3 - /etc/sniproxy.conf "$nameservers" <<\'PYEOF\'\n'
assert start in text
code=text.split(start,1)[1].split('\nPYEOF',1)[0]
open(sys.argv[2], 'w', encoding='utf-8').write(code+'\n')
PY

nameservers=$'    nameserver 22.22.22.22\n    nameserver 8.8.8.8'
python3 "$tmp/rewrite.py" "$tmp/sniproxy.conf" "$nameservers"
python3 "$tmp/rewrite.py" "$tmp/sniproxy.conf" "$nameservers"
grep -q 'nameserver 22.22.22.22' "$tmp/sniproxy.conf"
grep -q 'nameserver 8.8.8.8' "$tmp/sniproxy.conf"
grep -q 'mode ipv4_only' "$tmp/sniproxy.conf"
[[ "$(grep -c '^resolver {$' "$tmp/sniproxy.conf")" -eq 1 ]] || { echo "resolver block duplicated" >&2; exit 1; }
[[ "$(grep -c 'nameserver 22.22.22.22' "$tmp/sniproxy.conf")" -eq 1 ]] || { echo "nameserver duplicated" >&2; exit 1; }

grep -q 'os.replace(candidate, path)' "$tmp/rewrite.py" || { echo "rewrite is not atomic" >&2; exit 1; }
echo "sniproxy DNS rewrite idempotency OK"
