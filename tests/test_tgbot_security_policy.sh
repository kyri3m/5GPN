#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
body="$(cat "$root/tgbot.py")"
fail() { echo "$1" >&2; exit 1; }

[[ "$body" == *'def authorized(uid, chat):'* ]] || fail "authorization does not inspect chat context"
[[ "$body" == *'chat.get("type") != "private"'* ]] || fail "bot is not restricted to private chats"
[[ "$body" == *'RULE_TYPES = {'* ]] || fail "rule callback types lack an allowlist"
[[ "$body" == *'def valid_rule_target('* ]] || fail "rule/policy callback targets lack server-side validation"
[[ "$body" == *'if typ not in RULE_TYPES:'* ]] || fail "rt callback accepts arbitrary rule types"
[[ "$body" == *'state.get("action") != "rule_target"'* ]] || fail "rta callback is not bound to pending state"
[[ "$body" == *'if not valid_rule_target(target):'* ]] || fail "dangerous callback target is not validated"
[[ "$body" == *'name not in parse_exit_names()'* ]] || fail "exit callback accepts stale or invented exit names"
[[ "$body" == *'if not re.fullmatch(r"[0-9]{1,5}/(?:tcp|udp)", port_key):'* ]] || fail "firewall callback port is not validated"

echo "telegram authorization and callback validation OK"
