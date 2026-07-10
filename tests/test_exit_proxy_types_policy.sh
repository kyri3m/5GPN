#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="$root/install.sh"; gen="$root/mihomo-exit-config.py"
body="$(cat "$install")"
fail() { echo "$1" >&2; exit 1; }
[[ -f "$gen" ]] || fail "mihomo exit generator missing"
python3 -m py_compile "$gen"

assert_yaml() {
  local uri="$1" expr="$2"
  python3 "$gen" test "$uri" | python3 -c "import sys,yaml; c=yaml.safe_load(sys.stdin); p=c['proxies'][0]; assert $expr"
}

assert_yaml 'socks5://u:p@1.2.3.4:1080' "p['type']=='socks5' and p['username']=='u' and p['password']=='p'"
assert_yaml 'ss://YWVzLTI1Ni1nY206cHc=@5.6.7.8:8388' "p['type']=='ss' and p['cipher']=='aes-256-gcm'"
assert_yaml 'trojan://pw@example.com:443?sni=example.com' "p['type']=='trojan' and p['server']=='example.com'"
assert_yaml 'vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&sni=example.com' "p['type']=='vless'"
assert_yaml 'hysteria2://pw@example.com:443?sni=example.com' "p['type']=='hysteria2'"
assert_yaml 'tuic://00000000-0000-0000-0000-000000000000:pw@example.com:443?sni=example.com' "p['type']=='tuic'"
assert_yaml 'anytls://pw@example.com:443?sni=example.com' "p['type']=='anytls'"
assert_yaml 'http://u:p@example.com:8080' "p['type']=='http'"

out="$(PGW_USER='bob' PGW_PASS='p@ss:w/rd#1?' python3 "$gen" test 'socks5://1.2.3.4:1080')"
python3 - "$out" <<'PY'
import sys,yaml
p=yaml.safe_load(sys.argv[1])["proxies"][0]
assert p["username"] == "bob" and p["password"] == "p@ss:w/rd#1?"
PY

if python3 "$gen" test 'socks5://u:p@$(id):1080' >/dev/null 2>&1; then fail "malformed host accepted"; fi
if python3 "$gen" test 'ftp://x' >/dev/null 2>&1; then fail "unsupported scheme accepted"; fi

for marker in 'MIHOMO_VERSION_DEFAULT="1.19.4"' 'ensure_mihomo()' 'install_mihomo_unit()' \
  'systemctl start "proxy-gateway-mihomo@${name}.service"' 'mihomo-exit-config.py' \
  'ExecStartPost=-/usr/local/bin/proxy-gateway-apply-exit.sh' 'ip link show up "$iface"' \
  'ip route replace default dev'; do
  [[ "$body" == *"$marker"* ]] || fail "install.sh missing mihomo marker: $marker"
done
[[ "$body" != *'proxy-gateway-singbox@${name}.service'* ]] || fail "legacy sing-box service remains"

echo "exit proxy types policy OK"
