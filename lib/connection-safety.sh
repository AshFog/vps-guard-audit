#!/usr/bin/env bash
# shellcheck shell=bash
# 连接敏感加固的防失联门槛：SSH 会话、备用管理员、第二终端与延时回滚。

CONNECTION_GUARD_ROOT="${VPSGA_CONNECTION_GUARD_ROOT:-/run/vps-guard-audit/connection-guards}"
CONNECTION_GUARD_TOKEN=""

connection_guard_safe_token() {
  [[ "$1" =~ ^[a-f0-9]{32}$ ]]
}

connection_guard_parse_context() {
  local value="$1" remote_ip remote_port local_ip local_port extra
  IFS=' ' read -r remote_ip remote_port local_ip local_port extra <<<"$value"
  [[ -n "$remote_ip" && -n "$local_ip" && -z "${extra:-}" ]] || return 65
  [[ "$remote_ip" != *[[:space:]]* && "$local_ip" != *[[:space:]]* ]] || return 65
  [[ "$remote_port" =~ ^[0-9]+$ && "$local_port" =~ ^[0-9]+$ ]] || return 65
  ((remote_port >= 1 && remote_port <= 65535 && local_port >= 1 && local_port <= 65535)) || return 65
  printf '%s\t%s\t%s\t%s\n' "$remote_ip" "$remote_port" "$local_ip" "$local_port"
}

connection_guard_current_context() {
  [[ -n "${SSH_CONNECTION:-}" ]] || {
    echo "当前不是可验证的 SSH 会话，拒绝执行连接敏感加固。" >&2
    return 65
  }
  connection_guard_parse_context "$SSH_CONNECTION"
}

connection_guard_system_path() {
  local path="$1" root="${VPSGA_SYSTEM_ROOT:-}"
  [[ "$path" == /* ]] || return 64
  printf '%s%s' "${root%/}" "$path"
}

connection_guard_user_record() {
  local wanted="$1" passwd
  [[ "$wanted" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || return 65
  passwd="$(connection_guard_system_path /etc/passwd)"
  [[ -f "$passwd" && ! -L "$passwd" ]] || return 66
  awk -F: -v user="$wanted" '$1 == user { print; found=1; exit } END { if (!found) exit 1 }' "$passwd"
}

connection_guard_user_in_admin_group() {
  local user="$1" groups record primary_gid
  groups="$(connection_guard_system_path /etc/group)"
  [[ -f "$groups" && ! -L "$groups" ]] || return 66
  record="$(connection_guard_user_record "$user")" || return
  primary_gid="$(cut -d: -f4 <<<"$record")"
  awk -F: -v user="$user" -v primary_gid="$primary_gid" '
    $1 == "sudo" || $1 == "admin" {
      if ($3 == primary_gid) found=1
      n=split($4, members, ",")
      for (i=1; i<=n; i++) if (members[i] == user) found=1
    }
    END { exit(found ? 0 : 1) }
  ' "$groups"
}

connection_guard_key_is_safe() {
  local user="$1" record uid gid home shell ssh_dir key mode
  record="$(connection_guard_user_record "$user")" || return
  IFS=: read -r _ _ uid gid _ home shell <<<"$record"
  [[ "$uid" =~ ^[0-9]+$ && "$uid" -ne 0 && ! "$shell" =~ (nologin|false)$ ]] || return 1
  ssh_dir="$(connection_guard_system_path "$home/.ssh")"
  key="$ssh_dir/authorized_keys"
  [[ -d "$ssh_dir" && ! -L "$ssh_dir" && -f "$key" && ! -L "$key" ]] || return 1
  mode="$(stat -c %a "$ssh_dir")" || return 1
  (( (8#$mode & 8#022) == 0 )) || return 1
  mode="$(stat -c %a "$key")" || return 1
  (( (8#$mode & 8#022) == 0 )) || return 1
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ "$(stat -c %u "$ssh_dir")" == "$uid" && "$(stat -c %u "$key")" == "$uid" ]] || return 1
  fi
  grep -Eq '^[[:space:]]*(ssh-(rsa|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+' "$key"
}

connection_guard_admin_ready() {
  local user="$1"
  connection_guard_user_in_admin_group "$user" || {
    echo "用户 $user 不属于 sudo/admin 管理组。" >&2
    return 1
  }
  connection_guard_key_is_safe "$user" || {
    echo "用户 $user 没有权限安全且非空的 authorized_keys。" >&2
    return 1
  }
}

connection_guard_list_admins() {
  local passwd user _ uid _gid _ home shell
  passwd="$(connection_guard_system_path /etc/passwd)"
  [[ -f "$passwd" && ! -L "$passwd" ]] || return 66
  while IFS=: read -r user _ uid _gid _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ && "$uid" -ne 0 && ! "$shell" =~ (nologin|false)$ ]] || continue
    if connection_guard_admin_ready "$user" >/dev/null 2>&1; then
      printf '%s\n' "$user"
    fi
  done <"$passwd"
}

connection_guard_prepare_root() {
  local parent mode
  parent="${CONNECTION_GUARD_ROOT%/*}"
  [[ ! -L "$parent" && ! -L "$CONNECTION_GUARD_ROOT" ]] || return 76
  (umask 077; mkdir -p -- "$parent" "$CONNECTION_GUARD_ROOT") || return 73
  [[ "$(stat -c %u "$parent")" == "${EUID:-$(id -u)}" ]] || return 76
  mode="$(stat -c %a "$parent")" || return 74
  (( (8#$mode & 8#022) == 0 )) || return 76
  [[ "$(stat -c %u "$CONNECTION_GUARD_ROOT")" == "${EUID:-$(id -u)}" ]] || return 76
  chmod 0700 -- "$CONNECTION_GUARD_ROOT"
}

connection_guard_start() {
  local admin_user="$1" console_ack="$2" context token dir
  [[ "$console_ack" == "CONSOLE READY" ]] || {
    echo "尚未确认 VPS 网页控制台、VNC 或救援模式可用。" >&2
    return 65
  }
  context="$(connection_guard_current_context)" || return
  connection_guard_admin_ready "$admin_user" || return
  connection_guard_prepare_root || return
  token="$(printf '%s:%s:%s:%s' "$context" "$admin_user" "$$" "${RANDOM:-0}" | sha256sum | cut -c1-32)"
  connection_guard_safe_token "$token" || return 74
  dir="$CONNECTION_GUARD_ROOT/$token"
  (umask 077; mkdir -- "$dir") || return 73
  printf '%s\n' "$context" >"$dir/initial-context.tsv"
  printf 'admin=%s\ncreated_at=%s\ncreated_epoch=%s\nstatus=waiting\n' \
    "$admin_user" "$(date -Is)" "$(date +%s)" >"$dir/status"
  chmod 0600 -- "$dir/initial-context.tsv" "$dir/status"
  CONNECTION_GUARD_TOKEN="$token"
  printf '%s\n' "$token"
}

connection_guard_load_safe_dir() {
  local token="$1" dir path
  connection_guard_safe_token "$token" || return 64
  dir="$CONNECTION_GUARD_ROOT/$token"
  [[ -d "$dir" && ! -L "$dir" ]] || return 66
  [[ "$(stat -c %u "$dir")" == "${EUID:-$(id -u)}" ]] || return 76
  if find "$dir" -xdev -type f -perm /077 -print -quit 2>/dev/null | grep -q .; then return 76; fi
  for path in "$dir/status" "$dir/initial-context.tsv"; do
    [[ -f "$path" && ! -L "$path" && "$(stat -c %u "$path")" == "${EUID:-$(id -u)}" ]] || return 76
  done
  printf '%s\n' "$dir"
}

connection_guard_confirm() {
  local token="$1" dir initial current admin confirming_user created_epoch now tx_id tx_status
  dir="$(connection_guard_load_safe_dir "$token")" || return
  [[ "$(sed -n 's/^status=//p' "$dir/status")" == awaiting_second_connection ]] || return 65
  created_epoch="$(sed -n 's/^created_epoch=//p' "$dir/status")"
  now="$(date +%s)"
  [[ "$created_epoch" =~ ^[0-9]+$ ]] && ((now >= created_epoch && now - created_epoch <= 600)) || {
    echo "第二终端确认令牌已过期，请从原终端重新开始。" >&2
    return 65
  }
  tx_id="$(sed -n 's/^transaction=//p' "$dir/status")"
  connection_guard_unit_name "$tx_id" >/dev/null || return 76
  tx_status="$HARDENING_STATE_ROOT/$tx_id/status"
  [[ -f "$tx_status" && ! -L "$tx_status" && "$(sed -n 's/^status=//p' "$tx_status")" == pending_confirmation ]] || return 65
  initial="$(cat "$dir/initial-context.tsv")" || return 74
  current="$(connection_guard_current_context)" || return
  [[ "$current" != "$initial" ]] || {
    echo "必须从第二个独立 SSH 连接确认，当前仍是原会话。" >&2
    return 65
  }
  # 两条连接必须到达同一服务器地址和 SSH 端口。
  [[ "$(cut -f3,4 <<<"$current")" == "$(cut -f3,4 <<<"$initial")" ]] || {
    echo "第二条连接的服务器地址或 SSH 端口与原会话不一致。" >&2
    return 65
  }
  admin="$(sed -n 's/^admin=//p' "$dir/status")"
  confirming_user="${VPSGA_TEST_CONFIRMING_USER:-${SUDO_USER:-${USER:-}}}"
  [[ "$confirming_user" == "$admin" ]] || {
    echo "必须由已验证的备用管理员 $admin 从第二终端确认。" >&2
    return 65
  }
  printf '%s\n' "$current" >"$dir/confirmed-context.tsv"
  printf 'admin=%s\ncreated_at=%s\ncreated_epoch=%s\ntransaction=%s\nconfirmed_at=%s\nstatus=confirmed\n' \
    "$admin" "$(sed -n 's/^created_at=//p' "$dir/status")" "$created_epoch" "$tx_id" "$(date -Is)" >"$dir/status"
  chmod 0600 -- "$dir/confirmed-context.tsv" "$dir/status"
}

connection_guard_assert_confirmed() {
  local token="$1" dir created_epoch now
  dir="$(connection_guard_load_safe_dir "$token")" || return
  [[ "$(sed -n 's/^status=//p' "$dir/status")" == confirmed ]] || return 65
  created_epoch="$(sed -n 's/^created_epoch=//p' "$dir/status")"
  now="$(date +%s)"
  [[ "$created_epoch" =~ ^[0-9]+$ ]] && ((now >= created_epoch && now - created_epoch <= 600)) || return 65
  [[ -s "$dir/confirmed-context.tsv" && ! -L "$dir/confirmed-context.tsv" ]]
}

connection_guard_bind_transaction() {
  local token="$1" tx_id="$2" dir created_at created_epoch tx_status
  dir="$(connection_guard_load_safe_dir "$token")" || return
  [[ "$(sed -n 's/^status=//p' "$dir/status")" == waiting ]] || return 65
  connection_guard_unit_name "$tx_id" >/dev/null || return
  tx_status="$HARDENING_STATE_ROOT/$tx_id/status"
  [[ -f "$tx_status" && ! -L "$tx_status" && "$(sed -n 's/^status=//p' "$tx_status")" == pending_confirmation ]] || return 65
  [[ -f "$HARDENING_STATE_ROOT/$tx_id/rollback-unit" ]] || return 65
  created_at="$(sed -n 's/^created_at=//p' "$dir/status")"
  created_epoch="$(sed -n 's/^created_epoch=//p' "$dir/status")"
  printf 'admin=%s\ncreated_at=%s\ncreated_epoch=%s\ntransaction=%s\nstatus=awaiting_second_connection\n' \
    "$(sed -n 's/^admin=//p' "$dir/status")" "$created_at" "$created_epoch" "$tx_id" >"$dir/status"
  chmod 0600 -- "$dir/status"
}

connection_guard_unit_name() {
  local tx_id="$1"
  [[ "$tx_id" =~ ^[0-9]{8}T[0-9]{6}Z-HARD-2[0-9]{3}-[0-9]+-[0-9]+$ ]] || return 64
  printf 'vpsga-rollback-%s' "${tx_id,,}"
}

connection_guard_arm_rollback() {
  local tx_id="$1" delay="${2:-300}" tx_dir unit
  [[ "$delay" =~ ^[0-9]+$ ]] && ((delay >= 60 && delay <= 1800)) || return 64
  unit="$(connection_guard_unit_name "$tx_id")" || return
  tx_dir="$HARDENING_STATE_ROOT/$tx_id"
  [[ -d "$tx_dir" && ! -L "$tx_dir" ]] || return 66
  if [[ -n "${VPSGA_TEST_TIMER_BIN:-}" ]]; then
    "$VPSGA_TEST_TIMER_BIN" arm "$unit" "$delay" "$tx_id" || return
  else
    command -v systemd-run >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1 || {
      echo "系统不支持可靠的临时 systemd timer，拒绝执行连接敏感加固。" >&2
      return 69
    }
    systemd-run --quiet --unit "$unit" --on-active="${delay}s" --property=Type=oneshot \
      -- /usr/local/bin/vpsga rollback-auto "$tx_id" || return
  fi
  printf '%s\n' "$unit" >"$tx_dir/rollback-unit"
  chmod 0600 -- "$tx_dir/rollback-unit"
}

connection_guard_cancel_rollback() {
  local tx_id="$1" tx_dir unit
  tx_dir="$HARDENING_STATE_ROOT/$tx_id"
  [[ -f "$tx_dir/rollback-unit" && ! -L "$tx_dir/rollback-unit" ]] || return 66
  unit="$(cat "$tx_dir/rollback-unit")"
  [[ "$unit" == "$(connection_guard_unit_name "$tx_id")" ]] || return 76
  if [[ -n "${VPSGA_TEST_TIMER_BIN:-}" ]]; then
    "$VPSGA_TEST_TIMER_BIN" cancel "$unit" "$tx_id"
  else
    systemctl stop "$unit.timer" "$unit.service" 2>/dev/null || true
    systemctl reset-failed "$unit.service" 2>/dev/null || true
  fi
}

connection_guard_finalize_transaction() {
  local tx_id="$1" token="$2" status guard_dir
  [[ "$HARDENING_TX_ID" == "$tx_id" && -n "$HARDENING_TX_DIR" ]] || return 75
  status="$(sed -n 's/^status=//p' "$HARDENING_TX_DIR/status")"
  [[ "$status" == pending_confirmation ]] || return 65
  connection_guard_assert_confirmed "$token" || {
    echo "第二 SSH 连接尚未验证，不能提交连接敏感变更。" >&2
    return 65
  }
  guard_dir="$(connection_guard_load_safe_dir "$token")" || return
  [[ "$(sed -n 's/^transaction=//p' "$guard_dir/status")" == "$tx_id" ]] || return 76
  hardening_tx_assert_current_state || {
    echo "等待确认期间目标配置已发生变化，不能提交事务。" >&2
    return 75
  }
  # 先提交状态，再取消 timer。即使 timer 同时触发，也只允许恢复 pending_confirmation。
  hardening_tx_commit || return
  connection_guard_cancel_rollback "$tx_id" || {
    echo "事务已确认，但清理延时 timer 失败；迟到的 timer 会因 committed 状态安全退出。" >&2
    return 0
  }
}
