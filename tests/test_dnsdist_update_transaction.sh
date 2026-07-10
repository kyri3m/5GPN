#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
body="$(cat "$root/update-rules.sh")"
fail() { echo "$1" >&2; exit 1; }

[[ "$body" == *'flock -n 9'* ]] || fail "rule updater has no global lock"
[[ "$body" == *'DNSDIST_CANDIDATE='* ]] || fail "dnsdist config is still generated directly into the live file"
[[ "$body" == *'dnsdist --check-config -C "${DNSDIST_CANDIDATE}"'* ]] || fail "candidate dnsdist config is not validated"
[[ "$body" == *'rollback_transaction()'* ]] || fail "rule update lacks rollback transaction"
[[ "$body" == *'systemctl restart dnsdist'* ]] || fail "rule updater does not activate the validated config"
[[ "$body" == *'os.replace(src, dst)'* ]] || fail "validated candidate is not atomically committed"

echo "dnsdist update transaction policy OK"
