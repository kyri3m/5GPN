#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_body="$(cat "$root/install.sh")"
apply_body="$(cat "$root/bin/proxy-gateway-apply-exit.sh")"
fail() { echo "$1" >&2; exit 1; }

[[ "$install_body" == *'ensure_single_exit_rule()'* ]] || fail "install.sh lacks idempotent policy-rule helper"
[[ "$install_body" == *'ip -4 rule del priority'* ]] || fail "install.sh does not remove duplicate policy rules by priority"
[[ "$apply_body" == *'ip -4 rule del priority'* ]] || fail "apply helper does not remove duplicate policy rules"
[[ "$apply_body" == *'svc_state="$(systemctl is-active'* ]] || fail "apply helper does not inspect unit state before start"
[[ "$apply_body" == *'"inactive" || "${svc_state}" == "failed"'* ]] || fail "apply helper can recursively start an activating unit"
[[ "$apply_body" == *'ensure_single_exit_rule()'* ]] || fail "apply-exit lacks idempotent policy-rule helper"
[[ "$apply_body" != *'ip rule add fwmark "${MARK}" table "${TABLE}" 2>/dev/null || true'* ]] || \
  fail "apply-exit still blindly appends policy rules"
[[ "$install_body" == *'while ip -4 rule del fwmark "${EXIT_MARK}" table "${EXIT_TABLE}"'* ]] || \
  fail "uninstall does not remove every duplicate policy rule"

echo "exit policy rule idempotency OK"
