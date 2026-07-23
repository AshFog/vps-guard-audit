#!/usr/bin/env bash
# shellcheck shell=bash
# 第一批低风险动作。所有动作必须由事务包装器调用。

hardening_system_path() {
  local path="$1" root="${VPSGA_SYSTEM_ROOT:-}"
  [[ "$path" == /* ]] || return 64
  printf '%s%s' "${root%/}" "$path"
}

hardening_capture_and_mode() {
  local path="$1" owner="$2" mode="$3"
  [[ -e "$path" && ! -L "$path" ]] || return 0
  hardening_tx_capture "$path" || return
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown "$owner" -- "$path" || return
  fi
  chmod "$mode" -- "$path"
}

hardening_action_1001() {
  local shadow_group="root" path
  getent group shadow >/dev/null 2>&1 && shadow_group="shadow"
  path="$(hardening_system_path /etc/passwd)";  hardening_capture_and_mode "$path" root:root 0644 || return
  path="$(hardening_system_path /etc/group)";   hardening_capture_and_mode "$path" root:root 0644 || return
  path="$(hardening_system_path /etc/shadow)";  hardening_capture_and_mode "$path" "root:$shadow_group" 0640 || return
  path="$(hardening_system_path /etc/gshadow)"; hardening_capture_and_mode "$path" "root:$shadow_group" 0640 || return
}

hardening_validate_1001() {
  local path expected
  for expected in '/etc/passwd:644' '/etc/group:644' '/etc/shadow:640' '/etc/gshadow:640'; do
    path="$(hardening_system_path "${expected%:*}")"
    [[ ! -e "$path" || "$(stat -c %a "$path")" == "${expected##*:}" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || ! -e "$path" || "$(stat -c %u "$path")" == 0 ]] || return 1
  done
}

hardening_action_1002() {
  local passwd_file path home shell uid gid user key ssh_dir
  passwd_file="$(hardening_system_path /etc/passwd)"
  while IFS=: read -r user _ uid gid _ home shell; do
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    ssh_dir="$(hardening_system_path "$home/.ssh")"
    key="$ssh_dir/authorized_keys"
    [[ -f "$key" && ! -L "$key" ]] || continue
    hardening_capture_and_mode "$ssh_dir" "$uid:$gid" 0700 || return
    hardening_capture_and_mode "$key" "$uid:$gid" 0600 || return
  done <"$passwd_file"
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    hardening_capture_and_mode "$path" root:root 0600 || return
  done < <(find "$(hardening_system_path /etc/ssh)" -maxdepth 1 -type f -name 'ssh_host_*_key' -print 2>/dev/null)
}

hardening_validate_1002() {
  local passwd_file path home shell uid gid user key ssh_dir
  passwd_file="$(hardening_system_path /etc/passwd)"
  while IFS=: read -r user _ uid gid _ home shell; do
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    ssh_dir="$(hardening_system_path "$home/.ssh")"; key="$ssh_dir/authorized_keys"
    [[ ! -f "$key" ]] && continue
    [[ "$(stat -c %a "$ssh_dir")" == 700 ]] || return 1
    [[ "$(stat -c %a "$key")" == 600 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$ssh_dir")" == "$uid" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$key")" == "$uid" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %g "$ssh_dir")" == "$gid" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %g "$key")" == "$gid" ]] || return 1
  done <"$passwd_file"
  while IFS= read -r path; do
    [[ "$(stat -c %a "$path")" == 600 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  done < <(find "$(hardening_system_path /etc/ssh)" -maxdepth 1 -type f -name 'ssh_host_*_key' -print 2>/dev/null)
}

hardening_action_1003() {
  local root path
  root="$(hardening_system_path /etc)"
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]] && command -v visudo >/dev/null 2>&1; then
    visudo -c >/dev/null 2>&1 || return 1
  fi
  path="$root/sudoers"; hardening_capture_and_mode "$path" root:root 0440 || return
  while IFS= read -r path; do
    hardening_capture_and_mode "$path" root:root 0440 || return
  done < <(find "$root/sudoers.d" -xdev -type f -print 2>/dev/null)
}

hardening_validate_1003() {
  local root path
  root="$(hardening_system_path /etc)"
  for path in "$root/sudoers" "$root"/sudoers.d/*; do
    [[ -f "$path" ]] || continue
    [[ "$(stat -c %a "$path")" == 440 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  done
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]] || ! command -v visudo >/dev/null 2>&1 || visudo -c >/dev/null 2>&1
}

hardening_action_1004() {
  local root path mode
  root="$(hardening_system_path /etc)"
  for path in "$root/crontab" "$root"/cron.d/* "$root"/cron.daily/* "$root"/cron.hourly/* "$root"/cron.weekly/* "$root"/cron.monthly/*; do
    [[ -f "$path" ]] || continue
    mode="$(stat -c %a "$path")"
    # 仅移除组用户和其他用户的写权限，保留发行版原有的读取/执行语义。
    if (( (8#$mode & 8#022) != 0 )); then
      hardening_tx_capture "$path" || return
      chmod go-w -- "$path" || return
    fi
  done
}

hardening_validate_1004() {
  local root path
  root="$(hardening_system_path /etc)"
  path="$root/crontab"
  if [[ -f "$path" ]]; then
    (( (8#$(stat -c %a "$path") & 8#022) == 0 )) || return 1
  fi
  ! find "$root/cron.d" "$root/cron.daily" "$root/cron.hourly" "$root/cron.weekly" "$root/cron.monthly" \
    -xdev -type f -perm /022 -print -quit 2>/dev/null | grep -q .
}

hardening_ssh_managed_path() {
  hardening_system_path /etc/ssh/sshd_config.d/90-vpsga-hardening.conf
}

hardening_ssh_main_config() {
  hardening_system_path /etc/ssh/sshd_config
}

hardening_ssh_preflight() {
  local main include_dir managed mode path
  main="$(hardening_ssh_main_config)"
  include_dir="$(hardening_system_path /etc/ssh/sshd_config.d)"
  managed="$(hardening_ssh_managed_path)"
  [[ -f "$main" && ! -L "$main" ]] || {
    echo "未找到安全可用的 SSH 主配置：$main" >&2
    return 69
  }
  [[ -d "$include_dir" && ! -L "$include_dir" ]] || {
    echo "SSH drop-in 目录不存在或不安全：$include_dir" >&2
    return 69
  }
  for path in "$main" "$include_dir"; do
    mode="$(stat -c %a "$path")" || return 74
    (( (8#$mode & 8#022) == 0 )) || {
      echo "SSH 配置路径可被非 root 用户写入，拒绝修改：$path" >&2
      return 76
    }
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$path")" == 0 ]] || {
      echo "SSH 配置路径不属于 root，拒绝修改：$path" >&2
      return 76
    }
  done
  if [[ -e "$managed" || -L "$managed" ]]; then
    [[ -f "$managed" && ! -L "$managed" ]] || {
      echo "拒绝覆盖非普通文件或符号链接：$managed" >&2
      return 76
    }
    grep -qx '# Managed by VPS Guard Audit. Local edits may be replaced.' "$managed" || {
      echo "目标文件并非由 VPS Guard Audit 管理，拒绝覆盖：$managed" >&2
      return 76
    }
  fi
  # Debian/Ubuntu 的 drop-in 必须由主配置显式 Include。忽略注释和大小写。
  awk '
    /^[[:space:]]*#/ { next }
    tolower($1) == "include" {
      for (i = 2; i <= NF; i++)
        if ($i == "/etc/ssh/sshd_config.d/*.conf") found = 1
    }
    END { exit(found ? 0 : 1) }
  ' "$main" || {
    echo "SSH 主配置没有启用 /etc/ssh/sshd_config.d/*.conf，无法安全使用 drop-in。" >&2
    return 78
  }
}

hardening_sshd_test() {
  local main
  main="$(hardening_ssh_main_config)"
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_SSHD_BIN:-}" ]] || {
      echo "隔离根目录测试必须设置 VPSGA_TEST_SSHD_BIN。" >&2
      return 69
    }
    "$VPSGA_TEST_SSHD_BIN" -t -f "$main"
  else
    command -v sshd >/dev/null 2>&1 || {
      echo "找不到 sshd，无法验证 SSH 配置。" >&2
      return 69
    }
    sshd -t -f "$main"
  fi
}

hardening_sshd_effective_value() {
  local key="$1" main output
  main="$(hardening_ssh_main_config)"
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_SSHD_BIN:-}" ]] || return 69
    output="$("$VPSGA_TEST_SSHD_BIN" -T -f "$main")" || return
  else
    command -v sshd >/dev/null 2>&1 || return 69
    output="$(sshd -T -f "$main")" || return
  fi
  awk -v key="${key,,}" '$1 == key { print $2; found=1; exit } END { if (!found) exit 1 }' <<<"$output"
}

hardening_ssh_reload() {
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    if [[ -n "${VPSGA_TEST_SSH_RELOAD_BIN:-}" ]]; then
      "$VPSGA_TEST_SSH_RELOAD_BIN" "$(hardening_ssh_main_config)"
      return
    fi
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
  elif command -v service >/dev/null 2>&1; then
    service ssh reload 2>/dev/null || service sshd reload
  else
    echo "找不到可用的 SSH 服务重载方式。" >&2
    return 69
  fi
}

hardening_ssh_write_setting() {
  local managed tmp dir line key value
  local first="" second="" third="" fourth="" fifth="" sixth=""
  (($# >= 2 && $# % 2 == 0)) || return 64
  managed="$(hardening_ssh_managed_path)"
  dir="${managed%/*}"
  hardening_ssh_preflight || return
  hardening_tx_capture "$managed" || return

  if [[ -f "$managed" ]]; then
    while IFS= read -r line; do
      case "${line%%[[:space:]]*}" in
        PermitEmptyPasswords) first="$line" ;;
        MaxAuthTries) second="$line" ;;
        X11Forwarding) third="$line" ;;
        PermitRootLogin) fourth="$line" ;;
        PasswordAuthentication) fifth="$line" ;;
        KbdInteractiveAuthentication) sixth="$line" ;;
      esac
    done <"$managed"
  fi
  while (($#)); do
    key="$1"; value="$2"; shift 2
    case "$key" in
      PermitEmptyPasswords) first="$key $value" ;;
      MaxAuthTries) second="$key $value" ;;
      X11Forwarding) third="$key $value" ;;
      PermitRootLogin) fourth="$key $value" ;;
      PasswordAuthentication) fifth="$key $value" ;;
      KbdInteractiveAuthentication) sixth="$key $value" ;;
      *) return 64 ;;
    esac
  done

  tmp="$(mktemp "$dir/.90-vpsga-hardening.conf.XXXXXX")" || return 73
  {
    echo '# Managed by VPS Guard Audit. Local edits may be replaced.'
    echo '# Changes are backed up under /var/lib/vps-guard-audit/hardening.'
    [[ -z "$first" ]] || echo "$first"
    [[ -z "$second" ]] || echo "$second"
    [[ -z "$third" ]] || echo "$third"
    [[ -z "$fourth" ]] || echo "$fourth"
    [[ -z "$fifth" ]] || echo "$fifth"
    [[ -z "$sixth" ]] || echo "$sixth"
  } >"$tmp" || { rm -f -- "$tmp"; return 73; }
  chmod 0600 -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown root:root -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  fi
  mv -f -- "$tmp" "$managed" || { rm -f -- "$tmp"; return 73; }
  hardening_sshd_test || return
  hardening_ssh_reload
}

hardening_action_1005() { hardening_ssh_write_setting PermitEmptyPasswords no; }
hardening_action_1006() { hardening_ssh_write_setting MaxAuthTries 4; }
hardening_action_1007() { hardening_ssh_write_setting X11Forwarding no; }
hardening_action_2001() { hardening_ssh_write_setting PermitRootLogin no; }
hardening_action_2002() {
  hardening_ssh_write_setting PasswordAuthentication no KbdInteractiveAuthentication no
}

hardening_ssh_validate_setting() {
  local key="$1" value="$2" managed
  managed="$(hardening_ssh_managed_path)"
  [[ -f "$managed" && ! -L "$managed" ]] || return 1
  [[ "$(stat -c %a "$managed")" == 600 ]] || return 1
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$managed")" == '0:0' ]] || return 1
  [[ "$(awk -v key="$key" '
    $1 == key { count++; result=$2 }
    END { if (count == 1) print result; else exit 1 }
  ' "$managed")" == "$value" ]] || return 1
  hardening_sshd_test || return
  [[ "$(hardening_sshd_effective_value "$key")" == "${value,,}" ]]
}

hardening_validate_1005() { hardening_ssh_validate_setting PermitEmptyPasswords no; }
hardening_validate_1006() { hardening_ssh_validate_setting MaxAuthTries 4; }
hardening_validate_1007() { hardening_ssh_validate_setting X11Forwarding no; }
hardening_validate_2001() { hardening_ssh_validate_setting PermitRootLogin no; }
hardening_validate_2002() {
  hardening_ssh_validate_setting PasswordAuthentication no &&
    hardening_ssh_validate_setting KbdInteractiveAuthentication no
}

hardening_require_safe_directory() {
  local path="$1" mode
  [[ -d "$path" && ! -L "$path" ]] || {
    echo "目标目录不存在或不安全：$path" >&2
    return 69
  }
  mode="$(stat -c %a "$path")" || return 74
  (( (8#$mode & 8#022) == 0 )) || {
    echo "目标目录可被非 root 用户写入，拒绝修改：$path" >&2
    return 76
  }
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$path")" == 0 ]] || {
    echo "目标目录不属于 root，拒绝修改：$path" >&2
    return 76
  }
}

hardening_write_managed_file() {
  local path="$1" content="$2" marker="$3" dir tmp
  dir="${path%/*}"
  hardening_require_safe_directory "$dir" || return
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -f "$path" && ! -L "$path" ]] || {
      echo "拒绝覆盖非普通文件或符号链接：$path" >&2
      return 76
    }
    grep -Fqx "$marker" "$path" || {
      echo "目标文件并非由 VPS Guard Audit 管理，拒绝覆盖：$path" >&2
      return 76
    }
  fi
  hardening_tx_capture "$path" || return
  tmp="$(mktemp "$dir/.vpsga-managed.XXXXXX")" || return 73
  printf '%s' "$content" >"$tmp" || { rm -f -- "$tmp"; return 73; }
  chmod 0600 -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown root:root -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  fi
  mv -f -- "$tmp" "$path" || { rm -f -- "$tmp"; return 73; }
}

hardening_ensure_managed_directory() {
  local path="$1" parent
  if [[ -e "$path" || -L "$path" ]]; then
    hardening_require_safe_directory "$path"
    return
  fi
  parent="${path%/*}"
  hardening_require_safe_directory "$parent" || return
  hardening_tx_capture "$path" || return
  mkdir -- "$path" || return 73
  chmod 0755 -- "$path" || return 73
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown root:root -- "$path" || return 73
  fi
}

hardening_apt_config_path() {
  hardening_system_path /etc/apt/apt.conf.d/52-vpsga-auto-upgrades
}

hardening_apt_package_installed() {
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_DPKG_QUERY_BIN:-}" ]] || return 69
    "$VPSGA_TEST_DPKG_QUERY_BIN" unattended-upgrades
  else
    dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'ok installed'
  fi
}

hardening_apt_install_unattended() {
  hardening_apt_package_installed && return 0
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_APT_GET_BIN:-}" ]] || return 69
    "$VPSGA_TEST_APT_GET_BIN" install -y unattended-upgrades
  else
    command -v apt-get >/dev/null 2>&1 || return 69
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
  fi
  hardening_apt_package_installed
}

hardening_action_1008() {
  local path content marker='# Managed by VPS Guard Audit. Local edits may be replaced.'
  path="$(hardening_apt_config_path)"
  hardening_require_safe_directory "$(hardening_system_path /etc/apt/apt.conf.d)" || return
  hardening_apt_install_unattended || return
  content="$marker
// The distribution package keeps the allowed security origins in 50unattended-upgrades.
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
"
  hardening_write_managed_file "$path" "$content" "$marker"
}

hardening_validate_1008() {
  local path
  path="$(hardening_apt_config_path)"
  hardening_apt_package_installed || return
  [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  [[ "$(grep -Ec '^[[:space:]]*APT::Periodic::Update-Package-Lists[[:space:]]+\"1\";' "$path")" == 1 ]] || return 1
  [[ "$(grep -Ec '^[[:space:]]*APT::Periodic::Unattended-Upgrade[[:space:]]+\"1\";' "$path")" == 1 ]]
}

hardening_sysctl_path() {
  hardening_system_path /etc/sysctl.d/90-vpsga-hardening.conf
}

hardening_sysctl_command() {
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_SYSCTL_BIN:-}" ]] || return 69
    "$VPSGA_TEST_SYSCTL_BIN" "$@"
  else
    command sysctl "$@"
  fi
}

hardening_sysctl_pairs() {
  cat <<'EOF'
kernel.randomize_va_space=2
kernel.kptr_restrict=1
kernel.yama.ptrace_scope=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF
}

hardening_sysctl_capture_runtime() {
  local key value snapshot="$HARDENING_TX_DIR/sysctl-before.tsv"
  : >"$snapshot" || return 73
  while IFS='=' read -r key _; do
    if ! value="$(hardening_sysctl_command -n "$key" 2>/dev/null)"; then
      echo "跳过当前内核不存在的参数：$key" >&2
      continue
    fi
    [[ "$value" =~ ^-?[0-9]+$ ]] || {
      echo "内核参数返回了无法安全保存的值，拒绝修改：$key" >&2
      return 76
    }
    printf '%s\t%s\n' "$key" "$value" >>"$snapshot"
  done < <(hardening_sysctl_pairs)
  chmod 0600 -- "$snapshot"
}

hardening_sysctl_apply_file() {
  hardening_sysctl_command -p "$(hardening_sysctl_path)" >/dev/null
}

hardening_sysctl_restore_runtime() {
  local key value snapshot="$HARDENING_TX_DIR/sysctl-before.tsv" failed=0
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 74
  while IFS=$'\t' read -r key value; do
    [[ "$key" =~ ^[a-z0-9_.]+$ && "$value" =~ ^-?[0-9]+$ ]] || return 76
    hardening_sysctl_command -w "$key=$value" >/dev/null || failed=1
  done <"$snapshot"
  [[ "$failed" -eq 0 ]]
}

hardening_action_1009() {
  local path content marker='# Managed by VPS Guard Audit. Local edits may be replaced.' key expected
  path="$(hardening_sysctl_path)"
  hardening_sysctl_capture_runtime || return
  content="$marker
# Does not change IP forwarding or disable IPv6.
"
  while IFS='=' read -r key expected; do
    hardening_sysctl_command -n "$key" >/dev/null 2>&1 || continue
    content+="$key = $expected"$'\n'
  done < <(hardening_sysctl_pairs)
  hardening_write_managed_file "$path" "$content" "$marker" || return
  hardening_sysctl_apply_file
}

hardening_validate_1009() {
  local path key expected actual
  path="$(hardening_sysctl_path)"
  [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  while IFS='=' read -r key expected; do
    actual="$(hardening_sysctl_command -n "$key" 2>/dev/null)" || continue
    [[ "$(grep -Ec "^[[:space:]]*${key//./\\.}[[:space:]]*=[[:space:]]*$expected[[:space:]]*$" "$path")" == 1 ]] || return 1
    [[ "$actual" == "$expected" ]] || return 1
  done < <(hardening_sysctl_pairs)
}

hardening_core_limits_path() {
  hardening_system_path /etc/security/limits.d/90-vpsga-hardening.conf
}

hardening_coredump_path() {
  hardening_system_path /etc/systemd/coredump.conf.d/90-vpsga.conf
}

hardening_action_1010() {
  local marker='# Managed by VPS Guard Audit. Local edits may be replaced.' limits coredump
  limits="$marker
* hard core 0
"
  coredump="$marker
[Coredump]
Storage=none
ProcessSizeMax=0
"
  hardening_ensure_managed_directory "$(hardening_system_path /etc/systemd/coredump.conf.d)" || return
  hardening_write_managed_file "$(hardening_core_limits_path)" "$limits" "$marker" || return
  hardening_write_managed_file "$(hardening_coredump_path)" "$coredump" "$marker"
}

hardening_validate_1010() {
  local limits coredump path
  limits="$(hardening_core_limits_path)"; coredump="$(hardening_coredump_path)"
  for path in "$limits" "$coredump"; do
    [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  done
  [[ "$(grep -Ec '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0([[:space:]]|$)' "$limits")" == 1 ]] || return 1
  [[ "$(grep -Eic '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none[[:space:]]*$' "$coredump")" == 1 ]] || return 1
  [[ "$(grep -Eic '^[[:space:]]*ProcessSizeMax[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$coredump")" == 1 ]]
}

hardening_after_rollback() {
  case "$1" in
    HARD-1005|HARD-1006|HARD-1007|HARD-2001|HARD-2002)
      hardening_sshd_test && hardening_ssh_reload
      ;;
    HARD-1009)
      hardening_sysctl_restore_runtime
      ;;
    *) return 0 ;;
  esac
}

run_hardening_action_body() {
  case "$1" in
    HARD-1001) hardening_action_1001 ;;
    HARD-1002) hardening_action_1002 ;;
    HARD-1003) hardening_action_1003 ;;
    HARD-1004) hardening_action_1004 ;;
    HARD-1005) hardening_action_1005 ;;
    HARD-1006) hardening_action_1006 ;;
    HARD-1007) hardening_action_1007 ;;
    HARD-1008) hardening_action_1008 ;;
    HARD-1009) hardening_action_1009 ;;
    HARD-1010) hardening_action_1010 ;;
    HARD-2001) hardening_action_2001 ;;
    HARD-2002) hardening_action_2002 ;;
    *) echo "该项目尚未开放自动执行：$1" >&2; return 78 ;;
  esac
}

validate_hardening_action() {
  case "$1" in
    HARD-1001) hardening_validate_1001 ;;
    HARD-1002) hardening_validate_1002 ;;
    HARD-1003) hardening_validate_1003 ;;
    HARD-1004) hardening_validate_1004 ;;
    HARD-1005) hardening_validate_1005 ;;
    HARD-1006) hardening_validate_1006 ;;
    HARD-1007) hardening_validate_1007 ;;
    HARD-1008) hardening_validate_1008 ;;
    HARD-1009) hardening_validate_1009 ;;
    HARD-1010) hardening_validate_1010 ;;
    HARD-2001) hardening_validate_2001 ;;
    HARD-2002) hardening_validate_2002 ;;
    *) return 78 ;;
  esac
}

execute_hardening_action() {
  local action="$1" rc=0 tx_id
  [[ "$action" =~ ^HARD-1[0-9]{3}$ ]] || {
    echo "连接敏感动作必须使用防失联执行流程：$action" >&2
    return 78
  }
  hardening_tx_begin "$action" || return
  tx_id="$HARDENING_TX_ID"
  if run_hardening_action_body "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "动作执行失败" || rc=74
    [[ ! -s "$HARDENING_TX_MANIFEST" ]] || hardening_after_rollback "$action" || rc=74
    echo "[$action] 执行失败，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if validate_hardening_action "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "修改后验证失败" || rc=74
    [[ ! -s "$HARDENING_TX_MANIFEST" ]] || hardening_after_rollback "$action" || rc=74
    echo "[$action] 验证失败，已自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if hardening_tx_commit; then
    :
  else
    rc=$?
    hardening_tx_rollback "事务提交失败" || rc=74
    [[ ! -s "$HARDENING_TX_MANIFEST" ]] || hardening_after_rollback "$action" || rc=74
    echo "[$action] 无法提交事务，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  echo "[$action] 已完成并通过验证。事务：$tx_id"
  hardening_tx_close
}

stage_sensitive_hardening_action() {
  local action="$1" token="$2" rc=0 tx_id
  [[ "$action" == HARD-2001 || "$action" == HARD-2002 ]] || return 78
  hardening_tx_begin "$action" || return
  tx_id="$HARDENING_TX_ID"

  # Timer is armed before SSH is changed. It only becomes eligible to restore
  # after the transaction reaches pending_confirmation.
  if connection_guard_arm_rollback "$tx_id" 300; then
    :
  else
    rc=$?
    hardening_tx_rollback "无法建立延时自动回滚" >/dev/null 2>&1 || true
    hardening_tx_close
    return "$rc"
  fi
  if run_hardening_action_body "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "连接敏感动作执行失败" || rc=74
    [[ ! -s "$HARDENING_TX_MANIFEST" ]] || hardening_after_rollback "$action" || rc=74
    connection_guard_cancel_rollback "$tx_id" >/dev/null 2>&1 || true
    echo "[$action] 执行失败，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if validate_hardening_action "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "连接敏感修改验证失败" || rc=74
    [[ ! -s "$HARDENING_TX_MANIFEST" ]] || hardening_after_rollback "$action" || rc=74
    connection_guard_cancel_rollback "$tx_id" >/dev/null 2>&1 || true
    echo "[$action] 验证失败，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if hardening_tx_mark_pending_confirmation && connection_guard_bind_transaction "$token" "$tx_id"; then
    :
  else
    rc=$?
    hardening_tx_rollback "无法绑定第二终端确认" || rc=74
    hardening_after_rollback "$action" || rc=74
    connection_guard_cancel_rollback "$tx_id" >/dev/null 2>&1 || true
    echo "[$action] 无法进入第二终端确认，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
}
