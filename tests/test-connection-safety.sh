#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
root="$work/root"
state="$work/state"
guards="$work/guards"
timer_log="$work/timer.log"
mkdir -p "$root/etc" "$root/home/milo/.ssh" "$state"
cat >"$root/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
milo:x:1000:1000:Milo:/home/milo:/bin/bash
EOF
cat >"$root/etc/group" <<'EOF'
root:x:0:
sudo:x:27:milo
milo:x:1000:
EOF
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestOnlyKeyMaterial milo@test\n' \
  >"$root/home/milo/.ssh/authorized_keys"
chmod 0700 "$root/home/milo/.ssh"
chmod 0600 "$root/home/milo/.ssh/authorized_keys"
chmod +x "$project_dir/tests/fixtures/fake-timer.sh"

export VPSGA_SYSTEM_ROOT="$root"
export VPSGA_HARDENING_STATE_ROOT="$state"
export VPSGA_CONNECTION_GUARD_ROOT="$guards"
export VPSGA_TEST_TIMER_BIN="$project_dir/tests/fixtures/fake-timer.sh"
export VPSGA_TEST_TIMER_LOG="$timer_log"
export VPSGA_TEST_CONFIRMING_USER="milo"
export SSH_CONNECTION="198.51.100.20 50100 203.0.113.10 2222"

# shellcheck source=lib/hardening-transaction.sh
source "$project_dir/lib/hardening-transaction.sh"
# shellcheck source=lib/hardening-actions.sh
source "$project_dir/lib/hardening-actions.sh"
# shellcheck source=lib/connection-safety.sh
source "$project_dir/lib/connection-safety.sh"

connection_guard_admin_ready milo
if connection_guard_start milo WRONG >/dev/null 2>&1; then
  echo '未确认控制台时不应建立防失联会话' >&2
  exit 1
fi
token="$(connection_guard_start milo 'CONSOLE READY')"
[[ "$token" =~ ^[a-f0-9]{32}$ ]]

# 令牌必须先绑定到已经修改且已启动自动回滚的具体事务。
target="$root/etc/firewall-test.conf"
printf 'before\n' >"$target"
hardening_tx_begin HARD-2008
hardening_tx_capture "$target"
printf 'confirmed\n' >"$target"
hardening_tx_mark_pending_confirmation
tx_confirmed="$HARDENING_TX_ID"
connection_guard_arm_rollback "$tx_confirmed" 300
connection_guard_bind_transaction "$token" "$tx_confirmed"

if connection_guard_confirm "$token" >/dev/null 2>&1; then
  echo '原 SSH 会话不能冒充第二终端' >&2
  exit 1
fi
SSH_CONNECTION="198.51.100.20 50101 203.0.113.10 22"
if connection_guard_confirm "$token" >/dev/null 2>&1; then
  echo '不同服务器 SSH 端口不应通过确认' >&2
  exit 1
fi
SSH_CONNECTION="198.51.100.20 50101 203.0.113.10 2222"
VPSGA_TEST_CONFIRMING_USER="root"
if connection_guard_confirm "$token" >/dev/null 2>&1; then
  echo '错误管理员不应通过第二终端确认' >&2
  exit 1
fi
VPSGA_TEST_CONFIRMING_USER="milo"
connection_guard_confirm "$token"
connection_guard_assert_confirmed "$token"
connection_guard_finalize_transaction "$tx_confirmed" "$token"
grep -q '^status=committed$' "$state/$tx_confirmed/status"
grep -q $'^cancel\t' "$timer_log"
hardening_tx_close

# 未确认事务超时后应恢复到本次修改之前的状态。
hardening_tx_begin HARD-2008
hardening_tx_capture "$target"
printf 'timeout-change\n' >"$target"
hardening_tx_mark_pending_confirmation
tx_auto="$HARDENING_TX_ID"
connection_guard_arm_rollback "$tx_auto" 300
hardening_tx_assert_current_state
hardening_tx_close

VPSGA_SYSTEM_ROOT="$root" VPSGA_HARDENING_STATE_ROOT="$state" \
  VPSGA_CONNECTION_GUARD_ROOT="$guards" \
  bash "$project_dir/vpsga-manager.sh" rollback-auto "$tx_auto" >/dev/null
grep -qx confirmed "$target"
grep -q '^status=rolled_back$' "$state/$tx_auto/status"

# timer 不能覆盖事务完成后由管理员或其他工具写入的新配置。
hardening_tx_begin HARD-2008
hardening_tx_capture "$target"
printf 'pending\n' >"$target"
hardening_tx_mark_pending_confirmation
tx_changed="$HARDENING_TX_ID"
connection_guard_arm_rollback "$tx_changed" 300
hardening_tx_close
printf 'newer-external-change\n' >"$target"
if VPSGA_SYSTEM_ROOT="$root" VPSGA_HARDENING_STATE_ROOT="$state" \
  VPSGA_CONNECTION_GUARD_ROOT="$guards" \
  bash "$project_dir/vpsga-manager.sh" rollback-auto "$tx_changed" >/dev/null 2>&1; then
  echo '自动回滚不应覆盖事务后的外部变更' >&2
  exit 1
fi
grep -qx newer-external-change "$target"
grep -q '^status=pending_confirmation$' "$state/$tx_changed/status"

echo 'Connection safety tests passed.'
