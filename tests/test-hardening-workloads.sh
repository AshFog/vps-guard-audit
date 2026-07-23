#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
root="$work/root"; state="$work/state"; guards="$work/guards"
mkdir -p "$root/etc/ssh/sshd_config.d" "$root/etc/sysctl.d" "$root/home/milo/.ssh" "$state"
cat >"$root/etc/ssh/sshd_config" <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf
EOF
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
chmod 0755 "$root/etc/ssh" "$root/etc/ssh/sshd_config.d" "$root/etc/sysctl.d"
chmod 0644 "$root/etc/ssh/sshd_config" "$root/etc/passwd" "$root/etc/group"
chmod 0700 "$root/home/milo/.ssh"; chmod 0600 "$root/home/milo/.ssh/authorized_keys"
cat >"$root/sysctl-runtime.tsv" <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.disable_ipv6=0
net.ipv6.conf.default.disable_ipv6=0
EOF
cat >"$root/service-units.tsv" <<'EOF'
cups.service	1	enabled	loaded
cups.socket	1	enabled	loaded
cups.path	0	disabled	loaded
cups-browsed.service	0	disabled	loaded
avahi-daemon.service	1	enabled	loaded
avahi-daemon.socket	0	disabled	loaded
EOF

export VPSGA_SYSTEM_ROOT="$root" VPSGA_HARDENING_STATE_ROOT="$state" VPSGA_CONNECTION_GUARD_ROOT="$guards"
export VPSGA_TEST_SSHD_BIN="$project_dir/tests/fixtures/fake-sshd.sh"
export VPSGA_TEST_SSH_RELOAD_BIN="$project_dir/tests/fixtures/fake-ssh-reload.sh"
export VPSGA_TEST_SYSCTL_BIN="$project_dir/tests/fixtures/fake-sysctl.sh"
export VPSGA_TEST_SYSTEMCTL_BIN="$project_dir/tests/fixtures/fake-service-systemctl.sh"
export VPSGA_TEST_SERVICE_UNITS_STATE="$root/service-units.tsv"
export VPSGA_TEST_TIMER_BIN="$project_dir/tests/fixtures/fake-timer.sh" VPSGA_TEST_TIMER_LOG="$work/timer.log"
export VPSGA_TEST_CONFIRMING_USER=milo SSH_CONNECTION='198.51.100.20 51000 203.0.113.10 2222'

# shellcheck source=lib/hardening-transaction.sh
source "$project_dir/lib/hardening-transaction.sh"
# shellcheck source=lib/hardening-actions.sh
source "$project_dir/lib/hardening-actions.sh"
# shellcheck source=lib/connection-safety.sh
source "$project_dir/lib/connection-safety.sh"

manager_auto_rollback() {
  bash "$project_dir/vpsga-manager.sh" rollback-auto "$1" >/dev/null
}

# HARD-2006 refuses a generic APPLY without the forwarding-specific acknowledgement.
token="$(connection_guard_start milo 'CONSOLE READY')"
if stage_sensitive_hardening_action HARD-2006 "$token" >/dev/null 2>&1; then
  echo '未确认 SSH 转发用途时不应执行' >&2; exit 1
fi
[[ ! -e "$root/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" ]]

# A staged SSH forwarding change is restored when the second connection is not confirmed.
export VPSGA_SSH_FORWARD_ACK='NO SSH FORWARDING'
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2006 "$token" >/dev/null
tx_forward="$HARDENING_TX_ID"; hardening_tx_close
grep -qx 'AllowTcpForwarding no' "$root/etc/ssh/sshd_config.d/90-vpsga-hardening.conf"
manager_auto_rollback "$tx_forward"
[[ ! -e "$root/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" ]]

# HARD-2007 restores a partially applied runtime value and its new policy file.
export VPSGA_NETWORK_POLICY=ipv4-forwarding-off VPSGA_NETWORK_USAGE_ACK='NO ROUTING REQUIRED'
touch "$root/fail-sysctl-apply"
SSH_CONNECTION='198.51.100.20 51001 203.0.113.10 2222'
token="$(connection_guard_start milo 'CONSOLE READY')"
if stage_sensitive_hardening_action HARD-2007 "$token" >/dev/null 2>&1; then
  echo 'sysctl 应用失败时不应进入确认阶段' >&2; exit 1
fi
[[ "$(bash "$VPSGA_TEST_SYSCTL_BIN" -n net.ipv4.ip_forward)" == 1 ]]
[[ ! -e "$root/etc/sysctl.d/91-vpsga-network-policy.conf" ]]

# Runtime changes made after staging prevent an automatic rollback from overwriting newer work.
SSH_CONNECTION='198.51.100.20 51002 203.0.113.10 2222'
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2007 "$token" >/dev/null
tx_network="$HARDENING_TX_ID"; hardening_tx_close
[[ "$(bash "$VPSGA_TEST_SYSCTL_BIN" -n net.ipv4.ip_forward)" == 0 ]]
bash "$VPSGA_TEST_SYSCTL_BIN" -w net.ipv4.ip_forward=1 >/dev/null
if manager_auto_rollback "$tx_network" >/dev/null 2>&1; then
  echo '自动回滚不应覆盖事务后的 sysctl 运行时变更' >&2; exit 1
fi
bash "$VPSGA_TEST_SYSCTL_BIN" -w net.ipv4.ip_forward=0 >/dev/null
manager_auto_rollback "$tx_network"
[[ "$(bash "$VPSGA_TEST_SYSCTL_BIN" -n net.ipv4.ip_forward)" == 1 ]]
[[ ! -e "$root/etc/sysctl.d/91-vpsga-network-policy.conf" ]]

# IPv6 cannot be disabled from a currently IPv6-based SSH session.
export VPSGA_NETWORK_POLICY=ipv6-off
SSH_CONNECTION='2001:db8::20 51003 2001:db8::10 2222'
token="$(connection_guard_start milo 'CONSOLE READY')"
if stage_sensitive_hardening_action HARD-2007 "$token" >/dev/null 2>&1; then
  echo 'IPv6 SSH 会话中不应允许关闭 IPv6' >&2; exit 1
fi

# HARD-2008 disables only the explicitly selected candidate group.
export VPSGA_SERVICE_GROUP=cups VPSGA_SERVICE_USAGE_ACK='SERVICE NOT NEEDED'
SSH_CONNECTION='198.51.100.20 51004 203.0.113.10 2222'
token="$(connection_guard_start milo 'CONSOLE READY')"
stage_sensitive_hardening_action HARD-2008 "$token" >/dev/null
tx_service="$HARDENING_TX_ID"; hardening_tx_close
awk -F '\t' '$1 ~ /^cups/ { if ($2 != 0 || $3 ~ /^enabled/) exit 1 }' "$root/service-units.tsv"
awk -F '\t' '$1 == "avahi-daemon.service" { exit !($2 == 1 && $3 == "enabled") }' "$root/service-units.tsv"

# A later manual service start blocks rollback until the administrator restores the staged state.
bash "$VPSGA_TEST_SYSTEMCTL_BIN" start cups.service
if manager_auto_rollback "$tx_service" >/dev/null 2>&1; then
  echo '自动回滚不应覆盖事务后的服务状态变化' >&2; exit 1
fi
bash "$VPSGA_TEST_SYSTEMCTL_BIN" stop cups.service
manager_auto_rollback "$tx_service"
awk -F '\t' '$1 == "cups.service" || $1 == "cups.socket" { if ($2 != 1 || $3 != "enabled") exit 1 }' "$root/service-units.tsv"

# A failure after some units were disabled restores every original unit state.
printf 'stop cups.socket\n' >"$root/fail-service-command"
SSH_CONNECTION='198.51.100.20 51005 203.0.113.10 2222'
token="$(connection_guard_start milo 'CONSOLE READY')"
if stage_sensitive_hardening_action HARD-2008 "$token" >/dev/null 2>&1; then
  echo '服务停止失败时不应进入确认阶段' >&2; exit 1
fi
rm -f "$root/fail-service-command"
awk -F '\t' '$1 == "cups.service" || $1 == "cups.socket" { if ($2 != 1 || $3 != "enabled") exit 1 }' "$root/service-units.tsv"

echo 'Workload-sensitive hardening tests passed.'
