#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/in.conf" <<'EOF'
AND,((DOMAIN,a.example),(DOMAIN-SUFFIX,b.example)),Proxy
OR,((DOMAIN,c.example),(DOMAIN-SUFFIX,d.example)),Proxy
FINAL,direct
EOF
python3 "$root/rules-import.py" "$tmp/in.conf" > "$tmp/out" 2> "$tmp/err"
! grep -q 'a.example\|b.example' "$tmp/out" || { echo "AND was incorrectly widened into OR" >&2; exit 1; }
grep -q 'c.example' "$tmp/out" || { echo "OR member missing" >&2; exit 1; }
grep -q 'd.example' "$tmp/out" || { echo "OR member missing" >&2; exit 1; }
grep -q 'and_dropped=1' "$tmp/err" || { echo "AND rejection was not reported" >&2; exit 1; }

python3 - "$root/rules-import.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("rules_import", sys.argv[1])
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
try:
    mod.detect_format(b"binary", "https://example.com/rules.srs")
except ValueError as exc:
    assert ".srs" in str(exc)
else:
    raise SystemExit("rules-import accepted unsupported SRS")
PY

echo "logical rule import semantics OK"
