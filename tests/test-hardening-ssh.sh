#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
root="$work/root"
state="$work/state"
mkdir -p "$root/etc/ssh/sshd_config.d" "$state"
printf 'Include /etc/ssh/sshd_config.d/*.conf\n' >"$root/etc/ssh/sshd_config"
chmod +x "$project_dir/tests/fixtures/fake-sshd.sh" "$project_dir/tests/fixtures/fake-ssh-reload.sh"

export VPSGA_SYSTEM_ROOT="$root"
export VPSGA_HARDENING_STATE_ROOT="$state"
export VPSGA_TEST_SSHD_BIN="$project_dir/tests/fixtures/fake-sshd.sh"
export VPSGA_TEST_SSH_RELOAD_BIN="$project_dir/tests/fixtures/fake-ssh-reload.sh"

# shellcheck source=lib/hardening-transaction.sh
source "$project_dir/lib/hardening-transaction.sh"
# shellcheck source=lib/hardening-actions.sh
source "$project_dir/lib/hardening-actions.sh"

managed="$root/etc/ssh/sshd_config.d/90-vpsga-hardening.conf"

# 新文件语法验证失败时必须删除新建文件。
: >"$root/fail-next-sshd-test"
if execute_hardening_action HARD-1005 >/dev/null 2>&1; then
  echo '预期 HARD-1005 验证失败' >&2
  exit 1
fi
[[ ! -e "$managed" ]]
hardening_tx_close

execute_hardening_action HARD-1005 >/dev/null
tx_1005="$(find "$state" -mindepth 1 -maxdepth 1 -type d -name '*-HARD-1005-*' -printf '%f\n' | sort | tail -1)"
execute_hardening_action HARD-1006 >/dev/null
execute_hardening_action HARD-1007 >/dev/null
grep -qx 'PermitEmptyPasswords no' "$managed"
grep -qx 'MaxAuthTries 4' "$managed"
grep -qx 'X11Forwarding no' "$managed"
[[ "$(stat -c %a "$managed")" == 600 ]]

# 较早事务不能覆盖较新的同文件修改。
HARDENING_TX_DIR="$state/$tx_1005"
HARDENING_TX_ID="$tx_1005"
HARDENING_TX_ACTION="HARD-1005"
HARDENING_TX_MANIFEST="$HARDENING_TX_DIR/manifest.tsv"
HARDENING_TX_AFTER_MANIFEST="$HARDENING_TX_DIR/after.tsv"
if hardening_tx_rollback 'out-of-order test' >/dev/null 2>&1; then
  echo '较早 SSH 事务不应允许越序回滚' >&2
  exit 1
fi
hardening_tx_close

# reload 失败必须恢复修改前内容，并再次加载已恢复配置。
before="$(sha256sum "$managed" | awk '{print $1}')"
: >"$root/fail-next-reload"
if execute_hardening_action HARD-1006 >/dev/null 2>&1; then
  echo '预期 HARD-1006 reload 失败' >&2
  exit 1
fi
after="$(sha256sum "$managed" | awk '{print $1}')"
[[ "$before" == "$after" ]]

echo 'SSH hardening transaction tests passed.'
