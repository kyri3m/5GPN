#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/exits" "$tmp/cache" "$tmp/wg"
cat >"$tmp/exits/HK.yaml" <<'YAML'
proxies:
- {name: HK, type: ss, server: 203.0.113.10, port: 443, cipher: aes-128-gcm, password: x}
YAML
printf 'router\n' >"$tmp/exits/HK.type"
printf 'FINAL,direct\n' >"$tmp/rules"
: >"$tmp/map"
# HTTPS private/loopback providers must be rejected before mihomo can fetch them.
printf 'RULE-SET,https://127.0.0.1:8443/x.yaml,HK\nFINAL,direct\n' >"$tmp/rules"
if EXITS_DIR="$tmp/exits" WG_DIR="$tmp/wg" PGW_RULESET_CACHE="$tmp/cache" PGW_POLICY_MAP="$tmp/map" python3 "$root/mihomo-router-config.py" "$tmp/rules" >/dev/null 2>"$tmp/err"; then exit 1; fi
grep -qiE 'private|non-global' "$tmp/err"
# Case-insensitive exit lookup must emit the canonical proxy name in rules.
printf 'DOMAIN-SUFFIX,example.com,hk\nFINAL,direct\n' >"$tmp/rules"
EXITS_DIR="$tmp/exits" WG_DIR="$tmp/wg" PGW_RULESET_CACHE="$tmp/cache" PGW_POLICY_MAP="$tmp/map" python3 "$root/mihomo-router-config.py" "$tmp/rules" >"$tmp/out"
python3 - "$tmp/out" <<'PY'
import sys,yaml
c=yaml.safe_load(open(sys.argv[1])); assert 'DOMAIN-SUFFIX,example.com,HK' in c['rules']
PY
# URL resolution must be single-shot so validated and connected addresses are identical.
python3 - "$root/rules-import.py" <<'PY'
import importlib.util, socket, sys
s=importlib.util.spec_from_file_location('ri',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
calls=[]
def fake(*a,**k):
 calls.append(1); return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('93.184.216.34',443))]
m.socket.getaddrinfo=fake
p,addrs=m.resolve_public_url('https://example.com/x')
assert addrs==['93.184.216.34'] and len(calls)==1
PY
# Callback payloads must remain <= Telegram's 64-byte limit.
python3 - "$root/tgbot.py" <<'PY'
import ast,sys
m=ast.parse(open(sys.argv[1]).read()); f=next(n for n in m.body if isinstance(n,ast.FunctionDef) and n.name=='rule_target_menu')
assert 'value' not in ast.unparse(f).split('callback_data')[1], 'rule value still embedded in callback_data'
PY
body=$(cat "$root/install.sh"); dns=$(cat "$root/update-rules.sh")
[[ "$body" == *'SMART_LOCK_FILE='* && "$body" == *'flock '* ]] || { echo no-smart-lock; exit 1; }
proxy_body="${body#*proxy_domain() \{}"; proxy_body="${proxy_body%%show_rules()*}"
[[ "$proxy_body" == *'acquire_smart_lock'* && "$proxy_body" == *'restore_smart_state'* && "$proxy_body" == *'update-dnsdist-rules.sh'* ]] || { echo proxy-domain-not-transactional; exit 1; }
[[ "$body" == *'MIHOMO_SHA256_'* && "$body" == *'sha256sum -c'* ]] || { echo no-mihomo-checksum; exit 1; }
[[ "$dns" == *'os.replace('* ]] || { echo dns-not-atomic; exit 1; }
for f in proxy-gateway-mihomo@.service proxy-gateway-tgbot.service quic-proxy.service china-dns-race-proxy.service; do
  grep -q '@BASE_DIR@' "$root/deploy/systemd/$f" || { echo "unrendered-template-missing:$f"; exit 1; }
done
rendered="$tmp/rendered"; bash "$root/deploy/systemd/install.sh" /opt/custom-5gpn "$rendered"
! grep -R -q '@BASE_DIR@' "$rendered"
grep -q '/opt/custom-5gpn/bin/mihomo' "$rendered/proxy-gateway-mihomo@.service"
echo followup-hardening-OK
