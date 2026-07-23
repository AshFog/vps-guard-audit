#!/usr/bin/env bash
# shellcheck shell=bash
# 加固事务：为每次动作保存受保护的备份、元数据和结果，并支持自动回滚。

HARDENING_STATE_ROOT="${VPSGA_HARDENING_STATE_ROOT:-/var/lib/vps-guard-audit/hardening}"
HARDENING_TX_DIR=""
HARDENING_TX_ID=""
HARDENING_TX_ACTION=""
HARDENING_TX_MANIFEST=""
HARDENING_TX_CAPTURE_COUNT=0

hardening_tx_safe_path() {
  local path="$1"
  [[ "$path" == /* && "$path" != *$'\n'* && "$path" != *$'\t'* ]]
}

hardening_tx_prepare_root() {
  if [[ -L "$HARDENING_STATE_ROOT" ]]; then
    echo "拒绝使用符号链接加固记录目录：$HARDENING_STATE_ROOT" >&2
    return 76
  fi
  mkdir -p -- "$HARDENING_STATE_ROOT" || return 73
  if [[ "$(stat -c %u "$HARDENING_STATE_ROOT" 2>/dev/null || true)" != "${EUID:-$(id -u)}" ]]; then
    echo "加固记录目录所有者不正确：$HARDENING_STATE_ROOT" >&2
    return 76
  fi
  chmod 0700 -- "$HARDENING_STATE_ROOT" || return 73
}

hardening_tx_begin() {
  local action="$1" stamp random
  [[ "$action" =~ ^HARD-[0-9]{4}$ ]] || return 64
  [[ -z "$HARDENING_TX_DIR" ]] || {
    echo "已有未结束的加固事务：$HARDENING_TX_ID" >&2
    return 75
  }
  hardening_tx_prepare_root || return
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  random="${RANDOM:-0}"
  HARDENING_TX_ID="${stamp}-${action}-$$-${random}"
  HARDENING_TX_DIR="$HARDENING_STATE_ROOT/$HARDENING_TX_ID"
  (umask 077; mkdir -- "$HARDENING_TX_DIR" && mkdir -- "$HARDENING_TX_DIR/files") || return 73
  HARDENING_TX_ACTION="$action"
  HARDENING_TX_MANIFEST="$HARDENING_TX_DIR/manifest.tsv"
  HARDENING_TX_CAPTURE_COUNT=0
  : >"$HARDENING_TX_MANIFEST"
  printf 'action=%s\nstarted_at=%s\nstatus=running\n' \
    "$action" "$(date -Is)" >"$HARDENING_TX_DIR/status"
  chmod 0600 -- "$HARDENING_TX_MANIFEST" "$HARDENING_TX_DIR/status" || return 73
}

hardening_tx_capture() {
  local path="$1" type mode uid gid checksum="-" backup="-"
  [[ -n "$HARDENING_TX_DIR" ]] || return 75
  hardening_tx_safe_path "$path" || {
    echo "拒绝备份不安全路径：$path" >&2
    return 76
  }
  [[ ! -L "$path" ]] || {
    echo "拒绝修改符号链接目标：$path" >&2
    return 76
  }
  if [[ ! -e "$path" ]]; then
    printf 'missing\t-\t-\t-\t-\t-\t%s\n' "$path" >>"$HARDENING_TX_MANIFEST"
    return 0
  fi
  mode="$(stat -c %a "$path")" || return 74
  uid="$(stat -c %u "$path")" || return 74
  gid="$(stat -c %g "$path")" || return 74
  if [[ -f "$path" ]]; then
    type="file"
    HARDENING_TX_CAPTURE_COUNT=$((HARDENING_TX_CAPTURE_COUNT + 1))
    backup="files/$HARDENING_TX_CAPTURE_COUNT"
    cp --preserve=all -- "$path" "$HARDENING_TX_DIR/$backup" || return 74
    # 备份可能来自错误地设为全局可读/写的敏感文件；事务副本必须始终私有。
    chown "${EUID:-$(id -u)}:$(id -g)" -- "$HARDENING_TX_DIR/$backup" || return 74
    chmod 0600 -- "$HARDENING_TX_DIR/$backup" || return 74
    checksum="$(sha256sum "$path" | awk '{print $1}')" || return 74
  elif [[ -d "$path" ]]; then
    type="directory"
  else
    echo "不支持备份此文件类型：$path" >&2
    return 76
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$type" "$mode" "$uid" "$gid" "$checksum" "$backup" "$path" >>"$HARDENING_TX_MANIFEST"
}

hardening_tx_restore_entry() {
  local type="$1" mode="$2" uid="$3" gid="$4" _checksum="$5" backup="$6" path="$7"
  hardening_tx_safe_path "$path" || return 76
  case "$type" in
    file)
      [[ -f "$HARDENING_TX_DIR/$backup" && ! -L "$HARDENING_TX_DIR/$backup" ]] || return 74
      [[ ! -L "$path" ]] || return 76
      [[ "$(sha256sum "$HARDENING_TX_DIR/$backup" | awk '{print $1}')" == "$_checksum" ]] || return 74
      cp --preserve=all -- "$HARDENING_TX_DIR/$backup" "$path" || return 74
      chown "$uid:$gid" -- "$path" && chmod "$mode" -- "$path"
      ;;
    directory)
      [[ -d "$path" && ! -L "$path" ]] || return 74
      chown "$uid:$gid" -- "$path" && chmod "$mode" -- "$path"
      ;;
    missing)
      # 当前阶段不会创建新文件；保留该记录供后续配置型动作使用。
      [[ ! -e "$path" ]] || return 74
      ;;
    *) return 76 ;;
  esac
}

hardening_tx_rollback() {
  local reason="${1:-验证失败}" line failed=0
  local -a entries=()
  [[ -n "$HARDENING_TX_DIR" && -f "$HARDENING_TX_MANIFEST" ]] || return 75
  mapfile -t entries <"$HARDENING_TX_MANIFEST"
  for ((line=${#entries[@]}-1; line>=0; line--)); do
    IFS=$'\t' read -r type mode uid gid checksum backup path <<<"${entries[$line]}"
    hardening_tx_restore_entry "$type" "$mode" "$uid" "$gid" "$checksum" "$backup" "$path" || failed=1
  done
  printf 'action=%s\nstarted_at=%s\nstatus=%s\nfinished_at=%s\nreason=%s\n' \
    "$HARDENING_TX_ACTION" "$(sed -n 's/^started_at=//p' "$HARDENING_TX_DIR/status")" \
    "$([[ "$failed" -eq 0 ]] && echo rolled_back || echo rollback_failed)" "$(date -Is)" "$reason" \
    >"$HARDENING_TX_DIR/status"
  chmod 0600 -- "$HARDENING_TX_DIR/status" || failed=1
  [[ "$failed" -eq 0 ]]
}

hardening_tx_commit() {
  local started
  [[ -n "$HARDENING_TX_DIR" ]] || return 75
  started="$(sed -n 's/^started_at=//p' "$HARDENING_TX_DIR/status")"
  printf 'action=%s\nstarted_at=%s\nstatus=committed\nfinished_at=%s\n' \
    "$HARDENING_TX_ACTION" "$started" "$(date -Is)" >"$HARDENING_TX_DIR/status"
  chmod 0600 -- "$HARDENING_TX_DIR/status"
}

hardening_tx_close() {
  HARDENING_TX_DIR=""
  HARDENING_TX_ID=""
  HARDENING_TX_ACTION=""
  HARDENING_TX_MANIFEST=""
  HARDENING_TX_CAPTURE_COUNT=0
}
