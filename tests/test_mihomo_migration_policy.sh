#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install="${root}/install.sh"
bot="${root}/tgbot.py"
body="$(cat "$install")"
bot_body="$(cat "$bot")"

fail() { echo "$1" >&2; exit 1; }

# The management path must be wired to mihomo end-to-end.
for marker in \
  'MIHOMO_BIN=' \
  'MIHOMO_CFG_GEN=' \
  'MIHOMO_ROUTER_GEN=' \
  'ensure_mihomo()' \
  'install_mihomo_unit()' \
  'proxy-gateway-mihomo@${name}.service' \
  'proxy-gateway-mihomo@smart.service' \
  '"${MIHOMO_BIN}" -t'; do
  [[ "$body" == *"$marker"* ]] || fail "missing mihomo management marker: $marker"
done

# New management operations must not create or restart sing-box services.
[[ "$body" != *'install_singbox_unit()'* ]] || fail "legacy sing-box unit installer still active"
[[ "$body" != *'proxy-gateway-singbox@${name}.service'* ]] || fail "exit switching still starts sing-box"
[[ "$body" != *'proxy-gateway-singbox@smart.service'* ]] || fail "smart regeneration still restarts sing-box"

# Rule updates must validate a candidate before replacing the live rule file.
[[ "$body" == *'candidate_rules'* ]] || fail "set_rules lacks a candidate rules file"
[[ "$body" == *'build_smart_candidate'* ]] || fail "set_rules lacks candidate config validation"
[[ "$body" == *'atomic_install "$candidate_rules" "${RULES_FILE}" 0644'* ]] || \
  fail "candidate rules are not atomically installed after validation"

# Bot async implementation and policy test must agree on the thread pool model.
[[ "$bot_body" == *'_POOL.submit(go)'* ]] || fail "bot callback work is not submitted to the pool"
[[ "$bot_body" != *'threading.Thread(target=go, daemon=True).start()'* ]] || \
  fail "bot still creates one thread per callback"

echo "mihomo migration policy OK"
