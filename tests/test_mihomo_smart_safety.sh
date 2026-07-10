#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/exits" "$tmp/wg" "$tmp/cache"

cat > "$tmp/exits/a.yaml" <<'YAML'
proxies:
  - name: a
    type: socks5
    server: 203.0.113.10
    port: 1080
YAML
printf 'a=a\n' > "$tmp/map"
printf 'DOMAIN-SUFFIX,example.com,a\nFINAL,direct\n' > "$tmp/rules"
EXITS_DIR="$tmp/exits" WG_DIR="$tmp/wg" PGW_RULESET_CACHE="$tmp/cache" PGW_POLICY_MAP="$tmp/map" \
  python3 "$root/mihomo-router-config.py" "$tmp/rules" > "$tmp/smart.yaml"
python3 - "$tmp/smart.yaml" <<'PY'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
assert cfg.get("sniffer", {}).get("enable") is True, "TLS/HTTP sniffer must be enabled for domain rules"
assert "TLS" in cfg["sniffer"].get("sniff", {}), "TLS sniffer missing"
PY

printf 'Missing=does-not-exist\n' > "$tmp/map"
printf 'DOMAIN,missing.example,Missing\nFINAL,direct\n' > "$tmp/rules"
if EXITS_DIR="$tmp/exits" WG_DIR="$tmp/wg" PGW_RULESET_CACHE="$tmp/cache" PGW_POLICY_MAP="$tmp/map" \
  python3 "$root/mihomo-router-config.py" "$tmp/rules" > /dev/null 2> "$tmp/err"; then
  echo "generator silently accepted missing exit" >&2
  exit 1
fi
grep -qi 'does-not-exist' "$tmp/err" || { echo "missing-exit error lacks target name" >&2; exit 1; }

printf 'RULE-SET,https://example.com/rules.srs,a\nFINAL,direct\n' > "$tmp/rules"
if EXITS_DIR="$tmp/exits" WG_DIR="$tmp/wg" PGW_RULESET_CACHE="$tmp/cache" PGW_POLICY_MAP="$tmp/map" \
  python3 "$root/mihomo-router-config.py" "$tmp/rules" >/dev/null 2>"$tmp/err"; then
  echo "generator accepted unsupported sing-box SRS" >&2; exit 1
fi
grep -qi 'srs' "$tmp/err" || { echo "SRS rejection lacks clear error" >&2; exit 1; }

printf 'RULE-SET,http://example.com/rules.yaml,a\nFINAL,direct\n' > "$tmp/rules"
if EXITS_DIR="$tmp/exits" WG_DIR="$tmp/wg" PGW_RULESET_CACHE="$tmp/cache" PGW_POLICY_MAP="$tmp/map" \
  python3 "$root/mihomo-router-config.py" "$tmp/rules" >/dev/null 2>"$tmp/err"; then
  echo "generator accepted an insecure rule-provider URL" >&2; exit 1
fi
grep -qi 'HTTPS' "$tmp/err" || { echo "HTTP rejection lacks clear error" >&2; exit 1; }

echo "mihomo smart routing safety OK"
