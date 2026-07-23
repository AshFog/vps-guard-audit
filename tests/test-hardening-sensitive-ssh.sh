#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
root="$work/root"
state="$work/state"
guards="$work/guards"
timer_log="$work/timer.log"
mkdir -p "$root/etc/ssh/sshd_config.d" "$root/home/milo/.ssh" "$state"
printf 'Include /etc/ssh/sshd_config.d/*.conf\n' >"$root/etc/ssh/sshd_config"
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
chmod +x "$project_dir/tests/fixtures/fake-sshd.sh" \
  "$project_dir/tests/fixtures/fake-ssh-reload.sh" \
  "$project_dir/tests/fixtures/fake-timer.sh"

export VPSGA_SYSTEM_ROOT="$root"
export VPSGA_HARDENING_STATE_ROOT="$state"
export VPSGA_CONNECTION_GUARD_ROOT="$guards"
export VPSGA_TEST_SSHD_BIN="$project_dir/tests/fixtures/fake-sshd.sh"
export VPSGA_TEST_SSH_RELOAD_BIN="$project_dir/tests/fixtures/fake-ssh-reload.sh"
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

managed="$root/etc/ssh/sshd_config.d/90-vpsga-hardening.conf"

# The regular executor must never commit a sensitive action directly.
if execute_hardening_action HARD-2001 >/dev/null 2>&1; then
  echo '常规执行器不应接受连接敏感动作' >&2
  exit 1
fi
[[ ! -e "$managed" ]]

# HARD-2001 only commits after a distinct verified SSH session confirms it.
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2001 "$token" >/dev/null
tx_root="$HARDENING_TX_ID"
grep -qx 'PermitRootLogin no' "$managed"
grep -q '^status=pending_confirmation$' "$state/$tx_root/status"
SSH_CONNECTION="198.51.100.20 50101 203.0.113.10 2222"
connection_guard_confirm "$token"
connection_guard_finalize_transaction "$tx_root" "$token"
grep -q '^status=committed$' "$state/$tx_root/status"
hardening_tx_close

# HARD-2002 disables both password paths, then restores them on timeout.
SSH_CONNECTION="198.51.100.20 50102 203.0.113.10 2222"
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2002 "$token" >/dev/null
tx_password="$HARDENING_TX_ID"
grep -qx 'PasswordAuthentication no' "$managed"
grep -qx 'KbdInteractiveAuthentication no' "$managed"
hardening_tx_close
VPSGA_SYSTEM_ROOT="$root" VPSGA_HARDENING_STATE_ROOT="$state" \
  VPSGA_CONNECTION_GUARD_ROOT="$guards" \
  VPSGA_TEST_SSHD_BIN="$VPSGA_TEST_SSHD_BIN" \
  VPSGA_TEST_SSH_RELOAD_BIN="$VPSGA_TEST_SSH_RELOAD_BIN" \
  bash "$project_dir/vpsga-manager.sh" rollback-auto "$tx_password" >/dev/null
grep -qx 'PermitRootLogin no' "$managed"
! grep -q '^PasswordAuthentication ' "$managed"
! grep -q '^KbdInteractiveAuthentication ' "$managed"
grep -q '^status=rolled_back$' "$state/$tx_password/status"

# Reload failure restores the last committed SSH configuration immediately.
before="$(sha256sum "$managed" | awk '{print $1}')"
SSH_CONNECTION="198.51.100.20 50103 203.0.113.10 2222"
token="$(connection_guard_start milo 'CONSOLE READY')"
: >"$root/fail-next-reload"
if stage_sensitive_hardening_action HARD-2002 "$token" >/dev/null 2>&1; then
  echo 'reload 失败时敏感 SSH 动作不应成功' >&2
  exit 1
fi
after="$(sha256sum "$managed" | awk '{print $1}')"
[[ "$before" == "$after" ]]

echo 'Sensitive SSH hardening tests passed.'
