#!/usr/bin/env bash
# shellcheck shell=bash

HISTORY_DIR="${VPSGA_HISTORY_DIR:-/var/lib/vps-guard-audit/history}"
declare -a HISTORY_ADDED=()
declare -a HISTORY_RESOLVED=()
declare -a HISTORY_CHANGED=()
HISTORY_PREVIOUS=""
HISTORY_FIRST_RUN=0
HISTORY_NOTICE=""

add_redaction_pair() {
  local replacement="$1" original="$2"
  [[ -n "$original" ]] || return 0
  original="${original//$'\t'/ }"
  original="${original//$'\n'/ }"
  printf '%s\t%s\n' "$replacement" "$original" >>"$REDACTION_MAP"
}

build_redaction_map() {
  local fqdn user container domain index=0
  REDACTION_MAP="$TMP_DIR/redaction-map.tsv"
  : >"$REDACTION_MAP"

  fqdn="$(hostname -f 2>/dev/null || true)"
  [[ -n "$fqdn" && "$fqdn" != localhost ]] && add_redaction_pair HOST-FQDN "$fqdn"
  add_redaction_pair HOST-1 "$HOST"

  while IFS= read -r user; do
    [[ -n "$user" && "$user" != root && "$user" != nobody ]] || continue
    index=$((index+1))
    add_redaction_pair "USER-$index" "$user"
  done < <(awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null | sort -u)

  index=0
  if have docker; then
    while IFS= read -r container; do
      [[ -n "$container" ]] || continue
      index=$((index+1))
      add_redaction_pair "CONTAINER-$index" "$container"
    done < <(docker ps -a --format '{{.Names}}' 2>/dev/null | sort -u)
  fi

  index=0
  while IFS= read -r domain; do
    [[ "$domain" == *.* ]] || continue
    case "$domain" in localhost|localhost.localdomain|example.com) continue ;; esac
    index=$((index+1))
    add_redaction_pair "DOMAIN-$index" "$domain"
  done < <({
    [[ "$fqdn" == *.* ]] && printf '%s\n' "$fqdn"
    grep -RhsE '^[[:space:]]*server_name[[:space:]]+' /etc/nginx 2>/dev/null \
      | sed -E 's/^[[:space:]]*server_name[[:space:]]+//; s/[;[:space:]]+/\n/g' \
      | sed '/^$/d; /^_/d; /^\*/d'
    grep -RhsE '^[[:space:]]*ServerName[[:space:]]+' /etc/apache2 2>/dev/null \
      | awk '{print $2}'
  } | sort -u)
}

generate_ai_report() {
  build_redaction_map
  cat <<'EOF_AI_HEADER_ZH' >"$AI_REPORT"
VPS Guard Audit — AI 脱敏报告

这份文件由完整报告自动生成，适合提交给可信的 AI 助手继续分析。
自动脱敏无法保证覆盖所有自定义名称和凭据，分享前仍需亲自检查。
------------------------------------------------------------------------------
EOF_AI_HEADER_ZH

  awk -F '\t' '
    function replace_literal(text, old, new, p) {
      if (old == "") return text
      while ((p = index(text, old)) > 0) {
        text = substr(text, 1, p - 1) new substr(text, p + length(old))
      }
      return text
    }
    function redact_ipv4(text, ip) {
      while (match(text, /[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?/)) {
        ip = substr(text, RSTART, RLENGTH)
        if (!(ip in ip_map)) ip_map[ip] = "IP-" ++ip_count
        text = substr(text, 1, RSTART - 1) ip_map[ip] substr(text, RSTART + RLENGTH)
      }
      return text
    }
    NR == FNR { replacement[++pair_count] = $1; original[pair_count] = $2; next }
    {
      line = $0
      for (i = 1; i <= pair_count; i++) line = replace_literal(line, original[i], replacement[i])
      line = redact_ipv4(line)
      gsub(/[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]][[:alpha:]]+/, "EMAIL-REDACTED", line)
      gsub(/([[:xdigit:]][[:xdigit:]]:){5}[[:xdigit:]][[:xdigit:]]/, "MAC-REDACTED", line)
      gsub(/SHA256:[[:alnum:]+\/=]+/, "SHA256:REDACTED", line)
      print line
    }
  ' "$REDACTION_MAP" "$FULL_REPORT" >>"$AI_REPORT"
  chmod 0600 "$AI_REPORT" 2>/dev/null || true
}

prepare_history_comparison() {
  local previous id level title idx current_level
  declare -A prev_level=() prev_title=() cur_level=() cur_title=()

  HISTORY_ADDED=()
  HISTORY_RESOLVED=()
  HISTORY_CHANGED=()
  HISTORY_PREVIOUS=""
  HISTORY_FIRST_RUN=0
  HISTORY_NOTICE=""

  [[ "$HISTORY_ENABLED" -eq 1 ]] || return 0
  if [[ -L "$HISTORY_DIR" ]]; then
    HISTORY_ENABLED=0
    HISTORY_NOTICE="历史目录是符号链接，为避免写入到意外位置，本次已关闭历史比较：$HISTORY_DIR"
    return 0
  fi
  install -d -m 0700 "$HISTORY_DIR" 2>/dev/null || {
    HISTORY_ENABLED=0
    HISTORY_NOTICE="无法创建历史目录，本次未保存历史比较：$HISTORY_DIR"
    return 0
  }

  previous="$(find "$HISTORY_DIR" -maxdepth 1 -type f -name 'vpsga-*.state' -printf '%f\n' 2>/dev/null | sort | tail -n1)"
  if [[ -z "$previous" ]]; then
    HISTORY_FIRST_RUN=1
    return 0
  fi
  HISTORY_PREVIOUS="$HISTORY_DIR/$previous"
  [[ -L "$HISTORY_PREVIOUS" ]] && {
    HISTORY_ENABLED=0
    HISTORY_NOTICE="上一份历史状态是符号链接，本次已关闭历史比较。"
    return 0
  }

  while IFS=$'\t' read -r id level title; do
    [[ -n "$id" ]] || continue
    prev_level["$id"]="$level"
    prev_title["$id"]="$title"
  done <"$HISTORY_PREVIOUS"

  for idx in "${!FINDING_IDS[@]}"; do
    id="${FINDING_IDS[$idx]}"
    level="${FINDING_LEVELS[$idx]}"
    title="${FINDING_TITLES[$idx]}"
    cur_level["$id"]="$level"
    cur_title["$id"]="$title"
  done

  for id in "${!cur_level[@]}"; do
    current_level="${cur_level[$id]}"
    [[ "$current_level" == WARN || "$current_level" == FAIL ]] || continue
    if [[ -z "${prev_level[$id]+x}" || ( "${prev_level[$id]}" != WARN && "${prev_level[$id]}" != FAIL ) ]]; then
      HISTORY_ADDED+=("${cur_title[$id]}")
    elif [[ "${prev_level[$id]}" != "$current_level" ]]; then
      HISTORY_CHANGED+=("${cur_title[$id]} (${prev_level[$id]} -> $current_level)")
    fi
  done

  for id in "${!prev_level[@]}"; do
    [[ "${prev_level[$id]}" == WARN || "${prev_level[$id]}" == FAIL ]] || continue
    if [[ -z "${cur_level[$id]+x}" || ( "${cur_level[$id]}" != WARN && "${cur_level[$id]}" != FAIL ) ]]; then
      HISTORY_RESOLVED+=("${prev_title[$id]}")
    fi
  done
}

print_history_comparison() {
  [[ -n "$HISTORY_NOTICE" ]] && { echo; echo "$HISTORY_NOTICE"; return 0; }
  [[ "$HISTORY_ENABLED" -eq 1 ]] || return 0
  echo
  echo "与上一次检测相比"
  echo "------------------------------------------------------------------------------"
  if ((HISTORY_FIRST_RUN)); then
    echo "这是第一次保存历史结果。下一次运行时会显示新增问题和已经解决的问题。"
    return 0
  fi
  echo "  新增问题：${#HISTORY_ADDED[@]}"
  echo "  已经解决：${#HISTORY_RESOLVED[@]}"
  echo "  严重程度变化：${#HISTORY_CHANGED[@]}"
  ((${#HISTORY_ADDED[@]})) && { echo "  新增："; printf '    - %s\n' "${HISTORY_ADDED[@]}"; }
  ((${#HISTORY_RESOLVED[@]})) && { echo "  已解决："; printf '    - %s\n' "${HISTORY_RESOLVED[@]}"; }
  ((${#HISTORY_CHANGED[@]})) && { echo "  变化："; printf '    - %s\n' "${HISTORY_CHANGED[@]}"; }
}

finalize_report_ownership() {
  local report output_owner
  for report in "$FULL_REPORT" "$AI_REPORT" "$JSON_REPORT"; do
    [[ -f "$report" ]] && chmod 0600 "$report" 2>/dev/null || true
  done

  [[ "${SUDO_UID:-}" =~ ^[0-9]+$ && "${SUDO_GID:-}" =~ ^[0-9]+$ ]] || return 0
  [[ "$SUDO_UID" -ne 0 ]] || return 0
  output_owner="$(stat -c %u "$OUTPUT_DIR" 2>/dev/null || true)"
  [[ "$output_owner" == "$SUDO_UID" ]] || return 0

  for report in "$FULL_REPORT" "$AI_REPORT" "$JSON_REPORT"; do
    [[ -f "$report" ]] && chown "$SUDO_UID:$SUDO_GID" "$report" 2>/dev/null || true
  done
}

save_history_state() {
  local idx title state_tmp state_file
  if [[ "$HISTORY_ENABLED" -eq 1 ]]; then
    if [[ ! -L "$HISTORY_DIR" ]] && install -d -m 0700 "$HISTORY_DIR" 2>/dev/null; then
      state_tmp="$TMP_DIR/current.state"
      : >"$state_tmp"
      for idx in "${!FINDING_IDS[@]}"; do
        title="${FINDING_TITLES[$idx]//$'\t'/ }"
        title="${title//$'\n'/ }"
        printf '%s\t%s\t%s\n' "${FINDING_IDS[$idx]}" "${FINDING_LEVELS[$idx]}" "$title" >>"$state_tmp"
      done
      state_file="$HISTORY_DIR/vpsga-${STAMP}.state"
      if [[ ! -e "$state_file" && ! -L "$state_file" ]]; then
        install -m 0600 "$state_tmp" "$state_file" 2>/dev/null || true
      fi
      find "$HISTORY_DIR" -maxdepth 1 -type f -name 'vpsga-*.state' -printf '%f\n' 2>/dev/null \
        | sort -r | tail -n +31 \
        | while IFS= read -r old; do rm -f -- "$HISTORY_DIR/$old"; done
    fi
  fi
  finalize_report_ownership
}
