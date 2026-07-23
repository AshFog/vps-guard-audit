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

run_hardening_action_body() {
  case "$1" in
    HARD-1001) hardening_action_1001 ;;
    HARD-1002) hardening_action_1002 ;;
    HARD-1003) hardening_action_1003 ;;
    HARD-1004) hardening_action_1004 ;;
    *) echo "该项目尚未开放自动执行：$1" >&2; return 78 ;;
  esac
}

validate_hardening_action() {
  case "$1" in
    HARD-1001) hardening_validate_1001 ;;
    HARD-1002) hardening_validate_1002 ;;
    HARD-1003) hardening_validate_1003 ;;
    HARD-1004) hardening_validate_1004 ;;
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
    echo "[$action] 执行失败，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if validate_hardening_action "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "修改后验证失败" || rc=74
    echo "[$action] 验证失败，已自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  hardening_tx_commit || return
  echo "[$action] 已完成并通过验证。事务：$tx_id"
  hardening_tx_close
}
