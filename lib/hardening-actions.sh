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
  local key="$1" value="$2" managed tmp dir line first="" second="" third=""
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
      esac
    done <"$managed"
  fi
  case "$key" in
    PermitEmptyPasswords) first="$key $value" ;;
    MaxAuthTries) second="$key $value" ;;
    X11Forwarding) third="$key $value" ;;
    *) return 64 ;;
  esac

  tmp="$(mktemp "$dir/.90-vpsga-hardening.conf.XXXXXX")" || return 73
  {
    echo '# Managed by VPS Guard Audit. Local edits may be replaced.'
    echo '# Changes are backed up under /var/lib/vps-guard-audit/hardening.'
    [[ -z "$first" ]] || echo "$first"
    [[ -z "$second" ]] || echo "$second"
    [[ -z "$third" ]] || echo "$third"
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

hardening_after_rollback() {
  case "$1" in
    HARD-1005|HARD-1006|HARD-1007)
      hardening_sshd_test && hardening_ssh_reload
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
    *) return 78 ;;
  esac
}

execute_hardening_action() {
  local action="$1" rc=0 tx_id
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
