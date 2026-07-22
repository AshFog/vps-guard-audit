#!/usr/bin/env bash
# shellcheck shell=bash

HISTORY_DIR="${VPSGA_HISTORY_DIR:-/var/lib/vps-guard-audit/history}"
declare -a HISTORY_ADDED=()
declare -a HISTORY_RESOLVED=()
declare -a HISTORY_CHANGED=()
HISTORY_PREVIOUS=""
HISTORY_FIRST_RUN=0

html_escape_stream() {
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"
}

html_escape_text() {
  printf '%s' "${1-}" | html_escape_stream
}

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
  {
    if [[ "$LANGUAGE" == zh ]]; then
      cat <<'EOF_AI_HEADER_ZH'
VPS Guard Audit — AI 脱敏报告

这份文件由完整报告自动生成，适合提交给可信的 AI 助手继续分析。
自动脱敏无法保证覆盖所有自定义名称和凭据，分享前仍需亲自检查。
------------------------------------------------------------------------------
EOF_AI_HEADER_ZH
    else
      cat <<'EOF_AI_HEADER_EN'
VPS Guard Audit — AI-Safe Report

This file was generated from the full report for submission to a trusted AI assistant.
Automatic redaction cannot guarantee removal of every custom identifier or credential.
Review the file yourself before sharing it.
------------------------------------------------------------------------------
EOF_AI_HEADER_EN
    fi

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
    ' "$REDACTION_MAP" "$FULL_REPORT"
  } >"$AI_REPORT"
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

  [[ "$HISTORY_ENABLED" -eq 1 ]] || return 0
  install -d -m 0700 "$HISTORY_DIR" 2>/dev/null || return 0
  previous="$(find "$HISTORY_DIR" -maxdepth 1 -type f -name 'vpsga-*.state' -printf '%f\n' 2>/dev/null | sort | tail -n1)"
  if [[ -z "$previous" ]]; then
    HISTORY_FIRST_RUN=1
    return 0
  fi
  HISTORY_PREVIOUS="$HISTORY_DIR/$previous"

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
  [[ "$HISTORY_ENABLED" -eq 1 ]] || return 0
  echo
  if [[ "$LANGUAGE" == zh ]]; then
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
  else
    echo "Compared with the previous audit"
    echo "------------------------------------------------------------------------------"
    if ((HISTORY_FIRST_RUN)); then
      echo "This is the first saved baseline. The next run will show new and resolved findings."
      return 0
    fi
    echo "  New findings: ${#HISTORY_ADDED[@]}"
    echo "  Resolved findings: ${#HISTORY_RESOLVED[@]}"
    echo "  Severity changes: ${#HISTORY_CHANGED[@]}"
    ((${#HISTORY_ADDED[@]})) && { echo "  New:"; printf '    - %s\n' "${HISTORY_ADDED[@]}"; }
    ((${#HISTORY_RESOLVED[@]})) && { echo "  Resolved:"; printf '    - %s\n' "${HISTORY_RESOLVED[@]}"; }
    ((${#HISTORY_CHANGED[@]})) && { echo "  Changed:"; printf '    - %s\n' "${HISTORY_CHANGED[@]}"; }
  fi
}

save_history_state() {
  local idx title state_tmp state_file
  [[ "$HISTORY_ENABLED" -eq 1 ]] || return 0
  install -d -m 0700 "$HISTORY_DIR" 2>/dev/null || return 0
  state_tmp="$TMP_DIR/current.state"
  : >"$state_tmp"
  for idx in "${!FINDING_IDS[@]}"; do
    title="${FINDING_TITLES[$idx]//$'\t'/ }"
    title="${title//$'\n'/ }"
    printf '%s\t%s\t%s\n' "${FINDING_IDS[$idx]}" "${FINDING_LEVELS[$idx]}" "$title" >>"$state_tmp"
  done
  state_file="$HISTORY_DIR/vpsga-${STAMP}.state"
  install -m 0600 "$state_tmp" "$state_file" 2>/dev/null || true
  find "$HISTORY_DIR" -maxdepth 1 -type f -name 'vpsga-*.state' -printf '%f\n' 2>/dev/null \
    | sort -r | tail -n +31 \
    | while IFS= read -r old; do rm -f "$HISTORY_DIR/$old"; done
}

write_html_findings() {
  local wanted="$1" idx id title detail rec css label
  for idx in "${!FINDING_IDS[@]}"; do
    [[ "${FINDING_LEVELS[$idx]}" == "$wanted" ]] || continue
    id="${FINDING_IDS[$idx]}"
    title="${FINDING_TITLES[$idx]}"
    detail="${FINDING_DETAILS[$idx]}"
    rec="${FINDING_RECOMMENDATIONS[$idx]}"
    finding_plain_text "$id" "$rec"
    case "$wanted" in FAIL) css="danger" ;; WARN) css="warning" ;; *) css="normal" ;; esac
    label="$wanted"
    printf '<article class="finding %s"><div class="badge">%s</div><h3>%s</h3>' "$css" "$label" "$(html_escape_text "$title")"
    [[ -n "$detail" ]] && printf '<p><strong>%s</strong> %s</p>' "$([[ "$LANGUAGE" == zh ]] && echo '检测信息：' || echo 'Detected:')" "$(html_escape_text "$detail")"
    printf '<p><strong>%s</strong> %s</p>' "$([[ "$LANGUAGE" == zh ]] && echo '这表示：' || echo 'What it means:')" "$(html_escape_text "$PLAIN_MEANING")"
    [[ -n "$PLAIN_ACTION" ]] && printf '<p><strong>%s</strong> %s</p>' "$([[ "$LANGUAGE" == zh ]] && echo '建议：' || echo 'Suggested next step:')" "$(html_escape_text "$PLAIN_ACTION")"
    [[ -n "$PLAIN_CAUTION" ]] && printf '<p class="caution"><strong>%s</strong> %s</p>' "$([[ "$LANGUAGE" == zh ]] && echo '操作提醒：' || echo 'Caution:')" "$(html_escape_text "$PLAIN_CAUTION")"
    printf '</article>\n'
  done
}

generate_html_report() {
  local full_name ai_name json_name conclusion item
  full_name="$(basename "$FULL_REPORT")"
  ai_name="$(basename "$AI_REPORT")"
  json_name="$(basename "$JSON_REPORT")"
  if [[ "$LANGUAGE" == zh ]]; then
    if ((FAIL > 0)); then conclusion="发现需要尽快处理的问题"; elif ((WARN > 0)); then conclusion="没有发现明确的高危问题，但有项目需要确认或改进"; else conclusion="没有发现明确的高危问题"; fi
  else
    if ((FAIL > 0)); then conclusion="Issues requiring prompt attention were found"; elif ((WARN > 0)); then conclusion="No clear high-risk issue was found, but some items need review"; else conclusion="No clear high-risk issue was found"; fi
  fi

  {
    cat <<'EOF_HTML_HEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPS Guard Audit</title>
<style>
:root{color-scheme:light dark;--bg:#f5f7fa;--card:#fff;--text:#18212f;--muted:#627083;--line:#dfe5ec;--ok:#147d4f;--warn:#9a6500;--bad:#b42318}@media(prefers-color-scheme:dark){:root{--bg:#101418;--card:#171d23;--text:#edf2f7;--muted:#a7b2c0;--line:#303943;--ok:#6dd6a4;--warn:#f5c451;--bad:#ff8a80}}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 64px}header,.panel,.finding{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;margin-bottom:16px}h1{margin:0 0 6px;font-size:30px}h2{margin:0 0 14px}h3{margin:8px 0}.muted{color:var(--muted)}.summary{display:grid;grid-template-columns:repeat(5,minmax(110px,1fr));gap:10px;margin-top:18px}.metric{border:1px solid var(--line);border-radius:12px;padding:12px}.metric b{display:block;font-size:24px}.links{display:flex;flex-wrap:wrap;gap:10px}.links a{color:inherit;border:1px solid var(--line);border-radius:10px;padding:7px 11px;text-decoration:none}.badge{display:inline-block;font-size:12px;font-weight:700;border-radius:999px;padding:3px 9px;background:var(--line)}.finding.warning{border-left:5px solid var(--warn)}.finding.danger{border-left:5px solid var(--bad)}.caution{color:var(--warn)}details{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px}summary{cursor:pointer;font-weight:700}pre{white-space:pre-wrap;word-break:break-word;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace}.history li{margin:4px 0}@media(max-width:720px){.summary{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body><main class="wrap">
EOF_HTML_HEAD
    printf '<header><h1>VPS Guard Audit</h1><p class="muted">%s · %s · %s</p><p>%s</p>' "$(html_escape_text "$STAMP")" "$(html_escape_text "$HOST_PROFILE")" "$(html_escape_text "$OS_ID $OS_VERSION")" "$(html_escape_text "$conclusion")"
    printf '<div class="summary"><div class="metric"><b>%s</b>PASS</div><div class="metric"><b>%s</b>WARN</div><div class="metric"><b>%s</b>FAIL</div><div class="metric"><b>%s</b>INFO</div><div class="metric"><b>%s</b>SKIP</div></div></header>' "$PASS" "$WARN" "$FAIL" "$INFO" "$SKIP"
    printf '<section class="panel"><h2>%s</h2><div class="links">' "$([[ "$LANGUAGE" == zh ]] && echo '报告文件' || echo 'Report files')"
    printf '<a href="%s">Full TXT</a><a href="%s">AI TXT</a>' "$(html_escape_text "$full_name")" "$(html_escape_text "$ai_name")"
    [[ -f "$JSON_REPORT" ]] && printf '<a href="%s">JSON</a>' "$(html_escape_text "$json_name")"
    printf '</div></section>'

    if [[ "$HISTORY_ENABLED" -eq 1 ]]; then
      printf '<section class="panel history"><h2>%s</h2>' "$([[ "$LANGUAGE" == zh ]] && echo '与上次相比' || echo 'Compared with previous audit')"
      if ((HISTORY_FIRST_RUN)); then
        printf '<p>%s</p>' "$([[ "$LANGUAGE" == zh ]] && echo '这是第一次保存历史结果。' || echo 'This is the first saved baseline.')"
      else
        printf '<p>%s: %s · %s: %s · %s: %s</p>' \
          "$([[ "$LANGUAGE" == zh ]] && echo '新增' || echo 'New')" "${#HISTORY_ADDED[@]}" \
          "$([[ "$LANGUAGE" == zh ]] && echo '已解决' || echo 'Resolved')" "${#HISTORY_RESOLVED[@]}" \
          "$([[ "$LANGUAGE" == zh ]] && echo '变化' || echo 'Changed')" "${#HISTORY_CHANGED[@]}"
        ((${#HISTORY_ADDED[@]})) && { printf '<h3>%s</h3><ul>' "$([[ "$LANGUAGE" == zh ]] && echo '新增' || echo 'New')"; for item in "${HISTORY_ADDED[@]}"; do printf '<li>%s</li>' "$(html_escape_text "$item")"; done; printf '</ul>'; }
        ((${#HISTORY_RESOLVED[@]})) && { printf '<h3>%s</h3><ul>' "$([[ "$LANGUAGE" == zh ]] && echo '已解决' || echo 'Resolved')"; for item in "${HISTORY_RESOLVED[@]}"; do printf '<li>%s</li>' "$(html_escape_text "$item")"; done; printf '</ul>'; }
      fi
      printf '</section>'
    fi

    if ((FAIL > 0)); then
      printf '<section><h2>%s</h2>' "$([[ "$LANGUAGE" == zh ]] && echo '需要尽快处理' || echo 'Needs prompt attention')"
      write_html_findings FAIL
      printf '</section>'
    fi
    if ((WARN > 0)); then
      printf '<section><h2>%s</h2>' "$([[ "$LANGUAGE" == zh ]] && echo '需要确认或改进' || echo 'Review or improvement')"
      write_html_findings WARN
      printf '</section>'
    fi

    printf '<details><summary>%s</summary><pre>' "$([[ "$LANGUAGE" == zh ]] && echo '查看完整技术报告' || echo 'View full technical report')"
    html_escape_stream <"$FULL_REPORT"
    printf '</pre></details></main></body></html>\n'
  } >"$HTML_REPORT"
  chmod 0600 "$HTML_REPORT" 2>/dev/null || true
}

file_url() {
  local absolute
  absolute="$(readlink -f "$1" 2>/dev/null || printf '%s' "$1")"
  printf 'file://%s' "${absolute// /%20}"
}
