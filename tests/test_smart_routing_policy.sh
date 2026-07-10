#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="$root/install.sh"; gen="$root/mihomo-router-config.py"; body="$(cat "$install")"
fail() { echo "$1" >&2; exit 1; }
[[ -f "$gen" ]] || fail "mihomo-router-config.py missing"
python3 -m py_compile "$gen"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/exits" "$tmp/wg" "$tmp/rs"
cat > "$tmp/exits/us.yaml" <<'YAML'
proxies:
  - name: us
    type: socks5
    server: 1.1.1.1
    port: 1080
YAML
printf 'us=us\n' > "$tmp/policy"
printf 'a.com\n+.b.com\nDOMAIN-SUFFIX,c.com\n' > "$tmp/dev.list"
cat > "$tmp/rules.conf" <<EOF
DOMAIN-SUFFIX,google.com,us
DOMAIN-KEYWORD,netflix,direct
RULE-SET,$tmp/dev.list,us
GEOSITE,telegram,us
GEOIP,cn,direct
FINAL,block
EOF
EXITS_DIR="$tmp/exits" WG_DIR="$tmp/wg" PGW_RULESET_CACHE="$tmp/rs" PGW_POLICY_MAP="$tmp/policy" \
  python3 "$gen" "$tmp/rules.conf" > "$tmp/smart.yaml"
python3 - "$tmp/smart.yaml" <<'PY'
import sys,yaml
c=yaml.safe_load(open(sys.argv[1]))
assert c["tun"]["device"] == "pgw-smart"
assert c["sniffer"]["enable"] is True
assert c["proxies"][0]["name"] == "us"
assert c["rules"][0] == "DOMAIN-SUFFIX,google.com,us"
assert c["rules"][-1] == "MATCH,REJECT"
assert any(v["type"] == "file" for v in c.get("rule-providers", {}).values())
PY

for marker in 'set_rules()' '--set-rules)' 'mihomo-router-config.py' 'build_smart_candidate()' \
  'proxy-gateway-mihomo@smart.service' 'exit_reachable()' 'preflight_exit()'; do
  [[ "$body" == *"$marker"* ]] || fail "install.sh missing smart marker: $marker"
done

echo "smart routing policy OK"
