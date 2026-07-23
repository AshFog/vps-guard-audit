#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
root="$work/root"; state="$work/state"; guards="$work/guards"
mkdir -p "$root/etc/ufw" "$root/etc/default" "$root/lib/ufw" \
  "$root/etc/fail2ban" "$root/home/milo/.ssh" "$state"
cat >"$root/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
milo:x:1000:1000:Milo:/home/milo:/bin/bash
EOF
cat >"$root/etc/group" <<'EOF'
root:x:0:
sudo:x:27:milo
milo:x:1000:
EOF
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestOnlyKeyMaterial milo@test\n' >"$root/home/milo/.ssh/authorized_keys"
chmod 0700 "$root/home/milo/.ssh"; chmod 0600 "$root/home/milo/.ssh/authorized_keys"
: >"$root/etc/ufw/user.rules"; : >"$root/etc/ufw/user6.rules"
: >"$root/lib/ufw/user.rules"; : >"$root/lib/ufw/user6.rules"
printf 'inactive\n' >"$root/ufw-state"
printf 'enabled=0\nactive=0\n' >"$root/service-state"

chmod +x "$project_dir/tests/fixtures/fake-ufw.sh" "$project_dir/tests/fixtures/fake-systemctl.sh" \
  "$project_dir/tests/fixtures/fake-fail2ban.sh" "$project_dir/tests/fixtures/fake-timer.sh"
export VPSGA_SYSTEM_ROOT="$root" VPSGA_HARDENING_STATE_ROOT="$state" VPSGA_CONNECTION_GUARD_ROOT="$guards"
export VPSGA_TEST_UFW_BIN="$project_dir/tests/fixtures/fake-ufw.sh"
export VPSGA_TEST_SYSTEMCTL_BIN="$project_dir/tests/fixtures/fake-systemctl.sh"
export VPSGA_TEST_FAIL2BAN_BIN="$project_dir/tests/fixtures/fake-fail2ban.sh"
export VPSGA_TEST_SERVICE_STATE="$root/service-state"
export VPSGA_TEST_TIMER_BIN="$project_dir/tests/fixtures/fake-timer.sh" VPSGA_TEST_TIMER_LOG="$work/timer.log"
export VPSGA_TEST_CONFIRMING_USER=milo SSH_CONNECTION='198.51.100.20 50100 203.0.113.10 2222'

# shellcheck source=lib/hardening-transaction.sh
source "$project_dir/lib/hardening-transaction.sh"
# shellcheck source=lib/hardening-actions.sh
source "$project_dir/lib/hardening-actions.sh"
# shellcheck source=lib/connection-safety.sh
source "$project_dir/lib/connection-safety.sh"

# A newly installed Fail2ban service is stopped before the guarded transaction starts.
(
  unset VPSGA_TEST_FAIL2BAN_BIN
  PATH=/nonexistent
  hardening_install_official_package() { :; }
  hardening_systemctl_command() { printf '%s\n' "$*" >>"$work/preflight-service.log"; }
  hardening_sensitive_preflight HARD-2005
  [[ "$VPSGA_FAIL2BAN_PREINSTALL_STATE" == missing ]]
)
grep -qx 'stop fail2ban' "$work/preflight-service.log"
grep -qx 'disable fail2ban' "$work/preflight-service.log"

# SSH port omission is always rejected before UFW changes.
export VPSGA_UFW_ALLOW_SPECS='80/tcp 443/tcp'
token="$(connection_guard_start milo 'CONSOLE READY')"
if stage_sensitive_hardening_action HARD-2003 "$token" >/dev/null 2>&1; then
  echo '缺少 SSH 端口的 UFW 计划不应成功' >&2; exit 1
fi
[[ "$(cat "$root/ufw-state")" == inactive ]]

# An unknown initial UFW state is never guessed as inactive.
printf 'unknown\n' >"$root/ufw-state"
export VPSGA_UFW_ALLOW_SPECS='2222/tcp'
token="$(connection_guard_start milo 'CONSOLE READY')"
if stage_sensitive_hardening_action HARD-2003 "$token" >/dev/null 2>&1; then
  echo '无法识别 UFW 原状态时不应执行' >&2; exit 1
fi
printf 'inactive\n' >"$root/ufw-state"

# Explicit rules enable UFW and only commit after second-session confirmation.
export VPSGA_UFW_ALLOW_SPECS='2222/tcp 80/tcp 443/tcp'
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2003 "$token" >/dev/null
tx_ufw="$HARDENING_TX_ID"
[[ "$(cat "$root/ufw-state")" == active ]]
grep -Fqx '2222/tcp' "$root/etc/ufw/user.rules"
SSH_CONNECTION='198.51.100.20 50101 203.0.113.10 2222'
connection_guard_confirm "$token"; connection_guard_finalize_transaction "$tx_ufw" "$token"; hardening_tx_close

# Numbered deletion is restored exactly when second-session confirmation times out.
export VPSGA_UFW_DELETE_NUMBERS='2'
SSH_CONNECTION='198.51.100.20 50102 203.0.113.10 2222'
before="$(sha256sum "$root/etc/ufw/user.rules" | awk '{print $1}')"
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2004 "$token" >/dev/null
tx_cleanup="$HARDENING_TX_ID"; hardening_tx_close
! grep -Fqx '80/tcp' "$root/etc/ufw/user.rules"
VPSGA_SYSTEM_ROOT="$root" VPSGA_HARDENING_STATE_ROOT="$state" VPSGA_CONNECTION_GUARD_ROOT="$guards" \
  VPSGA_TEST_UFW_BIN="$VPSGA_TEST_UFW_BIN" VPSGA_TEST_TIMER_BIN="$VPSGA_TEST_TIMER_BIN" \
  VPSGA_TEST_TIMER_LOG="$VPSGA_TEST_TIMER_LOG" bash "$project_dir/vpsga-manager.sh" rollback-auto "$tx_cleanup" >/dev/null
[[ "$(sha256sum "$root/etc/ufw/user.rules" | awk '{print $1}')" == "$before" ]]

# Fail2ban uses the real SSH port and current client IP, then commits normally.
SSH_CONNECTION='198.51.100.20 50103 203.0.113.10 2222'
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2005 "$token" >/dev/null
tx_f2b="$HARDENING_TX_ID"
grep -Eq '^port = 2222$' "$root/etc/fail2ban/jail.d/vpsga-sshd.local"
grep -Eq '^ignoreip = .*198\.51\.100\.20$' "$root/etc/fail2ban/jail.d/vpsga-sshd.local"
SSH_CONNECTION='198.51.100.20 50104 203.0.113.10 2222'
connection_guard_confirm "$token"; connection_guard_finalize_transaction "$tx_f2b" "$token"; hardening_tx_close
grep -q '^active=1$' "$root/service-state"

# A service restart failure restores the prior jail and service state.
hardening_systemctl_command stop fail2ban; hardening_systemctl_command disable fail2ban
touch "$root/fail-service"
SSH_CONNECTION='198.51.100.20 50105 203.0.113.10 2222'
token="$(connection_guard_start milo 'CONSOLE READY')"
if stage_sensitive_hardening_action HARD-2005 "$token" >/dev/null 2>&1; then
  echo 'Fail2ban 启动失败时动作不应成功' >&2; exit 1
fi
rm -f "$root/fail-service"
grep -q '^active=0$' "$root/service-state"
grep -q '^enabled=0$' "$root/service-state"

echo 'Sensitive network hardening tests passed.'
