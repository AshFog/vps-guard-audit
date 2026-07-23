#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
root="$work/root"
state="$work/state"
mkdir -p "$root/etc/apt/apt.conf.d" "$root/etc/sysctl.d" \
  "$root/etc/security/limits.d" "$root/etc/systemd" "$state"
chmod +x "$project_dir/tests/fixtures/fake-dpkg-query.sh" \
  "$project_dir/tests/fixtures/fake-apt-get.sh" "$project_dir/tests/fixtures/fake-sysctl.sh"

export VPSGA_SYSTEM_ROOT="$root"
export VPSGA_HARDENING_STATE_ROOT="$state"
export VPSGA_TEST_DPKG_QUERY_BIN="$project_dir/tests/fixtures/fake-dpkg-query.sh"
export VPSGA_TEST_APT_GET_BIN="$project_dir/tests/fixtures/fake-apt-get.sh"
export VPSGA_TEST_SYSCTL_BIN="$project_dir/tests/fixtures/fake-sysctl.sh"

# shellcheck source=lib/hardening-transaction.sh
source "$project_dir/lib/hardening-transaction.sh"
# shellcheck source=lib/hardening-actions.sh
source "$project_dir/lib/hardening-actions.sh"

hardening_sysctl_pairs | awk -F= '{print $1 "=9"}' >"$root/sysctl-runtime.tsv"
sysctl_before="$(sha256sum "$root/sysctl-runtime.tsv" | awk '{print $1}')"

execute_hardening_action HARD-1008 >/dev/null
[[ -f "$root/unattended-upgrades.installed" ]]
grep -q 'Unattended-Upgrade "1"' "$root/etc/apt/apt.conf.d/52-vpsga-auto-upgrades"

# 安装新包后的事务回滚恢复配置，但保留软件包，避免自动卸载影响依赖。
tx_1008="$(find "$state" -mindepth 1 -maxdepth 1 -type d -name '*-HARD-1008-*' -print | sort | tail -1)"
HARDENING_TX_DIR="$tx_1008"; HARDENING_TX_ID="${tx_1008##*/}"; HARDENING_TX_ACTION=HARD-1008
HARDENING_TX_MANIFEST="$tx_1008/manifest.tsv"; HARDENING_TX_AFTER_MANIFEST="$tx_1008/after.tsv"
hardening_tx_rollback test >/dev/null
[[ ! -e "$root/etc/apt/apt.conf.d/52-vpsga-auto-upgrades" ]]
[[ -f "$root/unattended-upgrades.installed" ]]
hardening_tx_close

# sysctl 部分应用失败时，文件和全部运行时值都必须恢复。
: >"$root/fail-sysctl-apply"
if execute_hardening_action HARD-1009 >/dev/null 2>&1; then
  echo '预期 HARD-1009 应用失败' >&2
  exit 1
fi
[[ ! -e "$root/etc/sysctl.d/90-vpsga-hardening.conf" ]]
[[ "$(sha256sum "$root/sysctl-runtime.tsv" | awk '{print $1}')" == "$sysctl_before" ]]
hardening_tx_close

# 当前内核不存在的可选参数应跳过，不阻断其余基线。
sed -i '/^net\.ipv6\./d' "$root/sysctl-runtime.tsv"
execute_hardening_action HARD-1009 >/dev/null
hardening_validate_1009
! grep -q '^net\.ipv6\.' "$root/etc/sysctl.d/90-vpsga-hardening.conf"

# 第二个 Core Dump 文件冲突时，第一个新文件也必须被事务删除。
mkdir -p "$root/etc/systemd/coredump.conf.d"
echo 'local config' >"$root/etc/systemd/coredump.conf.d/90-vpsga.conf"
if execute_hardening_action HARD-1010 >/dev/null 2>&1; then
  echo '预期 HARD-1010 拒绝覆盖非受管文件' >&2
  exit 1
fi
[[ ! -e "$root/etc/security/limits.d/90-vpsga-hardening.conf" ]]
grep -qx 'local config' "$root/etc/systemd/coredump.conf.d/90-vpsga.conf"
hardening_tx_close

rm -f "$root/etc/systemd/coredump.conf.d/90-vpsga.conf"
rmdir "$root/etc/systemd/coredump.conf.d"
execute_hardening_action HARD-1010 >/dev/null
hardening_validate_1010

tx_1010="$(find "$state" -mindepth 2 -maxdepth 2 -type f -path '*-HARD-1010-*/status' -exec grep -l '^status=committed$' {} + | head -n1)"
HARDENING_TX_DIR="${tx_1010%/status}"; HARDENING_TX_ID="${HARDENING_TX_DIR##*/}"; HARDENING_TX_ACTION=HARD-1010
HARDENING_TX_MANIFEST="$HARDENING_TX_DIR/manifest.tsv"; HARDENING_TX_AFTER_MANIFEST="$HARDENING_TX_DIR/after.tsv"
hardening_tx_rollback test >/dev/null
[[ ! -e "$root/etc/security/limits.d/90-vpsga-hardening.conf" ]]
[[ ! -e "$root/etc/systemd/coredump.conf.d" ]]

echo 'System hardening transaction tests passed.'
