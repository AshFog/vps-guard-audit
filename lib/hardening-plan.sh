#!/usr/bin/env bash
# shellcheck shell=bash
# 根据本次审计结果生成中文加固计划。本模块只读，不执行系统修改。

declare -ga HARDENING_IDS=()
declare -ga HARDENING_GROUPS=()
declare -ga HARDENING_TITLES=()
declare -ga HARDENING_SUMMARIES=()
declare -ga HARDENING_RISKS=()
declare -ga HARDENING_MATCHERS=()
declare -ga HARDENING_TARGETS=()
declare -ga HARDENING_AUTOMATION=()
declare -ga HARDENING_DOCS=()
declare -ga HARDENING_MATCHED_FINDINGS=()
declare -ga APPLICABLE_REGULAR=()
declare -ga APPLICABLE_SENSITIVE=()

register_hardening_action() {
  HARDENING_IDS+=("$1")
  HARDENING_GROUPS+=("$2")
  HARDENING_TITLES+=("$3")
  HARDENING_SUMMARIES+=("$4")
  HARDENING_RISKS+=("$5")
  HARDENING_MATCHERS+=("$6")
  HARDENING_TARGETS+=("$7")
  HARDENING_AUTOMATION+=("$8")
  HARDENING_DOCS+=("$9")
  HARDENING_MATCHED_FINDINGS+=("")
}

load_hardening_registry() {
  ((${#HARDENING_IDS[@]} == 0)) || return 0
  hardening_registry_visit
  validate_hardening_registry
}

validate_hardening_registry() {
  local i id group automation
  local -A seen=()
  [[ "${#HARDENING_IDS[@]}" -eq 18 ]] || {
    echo "加固注册表必须恰好包含 18 项。" >&2
    return 76
  }
  for i in "${!HARDENING_IDS[@]}"; do
    id="${HARDENING_IDS[$i]}"
    group="${HARDENING_GROUPS[$i]}"
    automation="${HARDENING_AUTOMATION[$i]}"
    [[ "$id" =~ ^HARD-[12][0-9]{3}$ && -z "${seen[$id]+x}" ]] || {
      echo "加固注册表包含无效或重复编号：$id" >&2
      return 76
    }
    [[ "$group" == regular || "$group" == sensitive ]] || {
      echo "加固项目 $id 的风险分组无效。" >&2
      return 76
    }
    [[ "$automation" == yes || "$automation" == planned || "$automation" == no ]] || {
      echo "加固项目 $id 的自动化状态无效。" >&2
      return 76
    }
    seen[$id]=1
  done
}

hardening_pattern_matches() {
  local value="$1" pattern="$2"
  # Patterns come only from the root-owned built-in registry.
  # shellcheck disable=SC2053
  [[ "$value" == $pattern ]]
}

hardening_action_matches_findings() {
  local action_index="$1" finding_index pattern level matched=""
  local -a action_matchers=()
  IFS=',' read -r -a action_matchers <<<"${HARDENING_MATCHERS[$action_index]}"
  for finding_index in "${!FINDING_LEGACY_IDS[@]}"; do
    level="${FINDING_LEVELS[$finding_index]}"
    [[ "$level" == WARN || "$level" == FAIL ]] || continue
    for pattern in "${action_matchers[@]}"; do
      if hardening_pattern_matches "${FINDING_LEGACY_IDS[$finding_index]}" "$pattern"; then
        if [[ ",$matched," != *",${FINDING_IDS[$finding_index]},"* ]]; then
          if [[ -n "$matched" ]]; then matched+=","; fi
          matched+="${FINDING_IDS[$finding_index]}"
        fi
        break
      fi
    done
  done
  HARDENING_MATCHED_FINDINGS[$action_index]="$matched"
  [[ -n "$matched" ]]
}

collect_applicable_hardening() {
  local i
  load_hardening_registry
  APPLICABLE_REGULAR=()
  APPLICABLE_SENSITIVE=()
  for i in "${!HARDENING_IDS[@]}"; do
    if hardening_action_matches_findings "$i"; then
      if [[ "${HARDENING_GROUPS[$i]}" == regular ]]; then
        APPLICABLE_REGULAR+=("$i")
      else
        APPLICABLE_SENSITIVE+=("$i")
      fi
    fi
  done
}

hardening_docs_url() {
  printf '%s/hardening/%s/' \
    "${VPSGA_DOCS_BASE_URL:-https://ashfog.github.io/vps-guard-audit}" "$1"
}

print_hardening_action() {
  local i="$1" number="$2" automation_label
  case "${HARDENING_AUTOMATION[$i]}" in
    yes) automation_label="可在确认后自动处理" ;;
    planned) automation_label="暂只提供人工方案" ;;
    *) automation_label="不支持自动处理" ;;
  esac
  printf '  [%s] %s  %s\n' "$number" "${HARDENING_IDS[$i]}" "${HARDENING_TITLES[$i]}"
  printf '      %s\n' "${HARDENING_SUMMARIES[$i]}"
  printf '      涉及：%s｜%s｜发现：%s\n' \
    "${HARDENING_TARGETS[$i]}" "$automation_label" "${HARDENING_MATCHED_FINDINGS[$i]}"
  if [[ "${HARDENING_GROUPS[$i]}" == sensitive ]]; then
    printf '      详细说明：%s\n' "$(hardening_docs_url "${HARDENING_DOCS[$i]}")"
  fi
}

print_hardening_plan() {
  local i n=1
  collect_applicable_hardening
  echo
  echo "=============================================================================="
  echo "中文加固计划（只读预览）"
  echo "=============================================================================="
  printf '本次发现 %d 项常规加固、%d 项连接敏感加固可供处理。\n' \
    "${#APPLICABLE_REGULAR[@]}" "${#APPLICABLE_SENSITIVE[@]}"
  echo
  echo "常规安全加固（通常不影响当前 SSH 连接）"
  if ((${#APPLICABLE_REGULAR[@]} == 0)); then
    echo "  暂无与本次检测结果匹配的项目。"
  else
    for i in "${APPLICABLE_REGULAR[@]}"; do print_hardening_action "$i" "$n"; n=$((n+1)); done
  fi
  echo
  echo "连接敏感加固（可能影响登录、网络或现有服务）"
  echo "  执行前必须准备 VPS 网页控制台、VNC 或救援模式，且需逐项确认。"
  if ((${#APPLICABLE_SENSITIVE[@]} == 0)); then
    echo "  暂无与本次检测结果匹配的项目。"
  else
    n=1
    for i in "${APPLICABLE_SENSITIVE[@]}"; do print_hardening_action "$i" "$n"; n=$((n+1)); done
  fi
  echo
  echo "当前仅 HARD-1001 至 HARD-1007 开放确认后执行；其余项目仍只提供计划。"
}

show_regular_hardening_menu() {
  local answer i n
  while true; do
    echo
    echo "常规安全加固"
    n=1
    if ((${#APPLICABLE_REGULAR[@]} == 0)); then
      echo "  暂无匹配项目。"
      return 0
    fi
    for i in "${APPLICABLE_REGULAR[@]}"; do
      print_hardening_action "$i" "$n"
      n=$((n+1))
    done
    echo
    echo "输入编号可处理单项；尚未开放的项目只会显示说明。"
    echo "  0. 返回"
    printf '请选择：'
    IFS= read -r answer || return 0
    [[ "$answer" == 0 ]] && return 0
    if [[ ! "$answer" =~ ^[0-9]+$ ]] || ((answer < 1 || answer > ${#APPLICABLE_REGULAR[@]})); then
      echo "无效选项，请重新输入。"
      continue
    fi
    i="${APPLICABLE_REGULAR[$((answer-1))]}"
    if [[ "${HARDENING_AUTOMATION[$i]}" != yes ]]; then
      echo "${HARDENING_IDS[$i]} 暂未开放自动执行。"
      continue
    fi
    echo
    echo "即将执行：${HARDENING_IDS[$i]} ${HARDENING_TITLES[$i]}"
    echo "工具会先备份目标，修改后验证；验证失败将自动回滚。"
    printf '输入 APPLY 确认执行：'
    IFS= read -r answer || return 0
    if [[ "$answer" == APPLY ]]; then
      execute_hardening_action "${HARDENING_IDS[$i]}" || true
      echo "请重新运行 vpsga，确认该检查项已经解决且没有新增问题。"
      collect_applicable_hardening
    else
      echo "已取消。"
    fi
  done
}

show_post_audit_menu() {
  local answer
  collect_applicable_hardening
  while true; do
    echo
    echo "────────────────────────────────────────"
    echo "VPS Guard Audit：检测完成"
    echo "────────────────────────────────────────"
    printf '发现 %d 项常规加固、%d 项连接敏感加固。\n' \
      "${#APPLICABLE_REGULAR[@]}" "${#APPLICABLE_SENSITIVE[@]}"
    echo
    echo "  1. 查看常规安全加固（通常不影响连接）"
    echo "  2. 查看连接敏感加固（可能导致失联）"
    echo "  3. 查看完整中文加固计划"
    echo "  4. 仅保留报告，不进行修改"
    echo "  0. 退出"
    printf '请输入选项：'
    IFS= read -r answer || return 0
    case "$answer" in
      1)
        show_regular_hardening_menu
        ;;
      2)
        echo
        echo "⚠ 连接敏感加固"
        echo "以下设置可能导致 SSH 无法重新连接，请先准备 VPS 控制台或救援模式。"
        if ((${#APPLICABLE_SENSITIVE[@]} == 0)); then echo "  暂无匹配项目。"; fi
        local i n=1
        for i in "${APPLICABLE_SENSITIVE[@]}"; do print_hardening_action "$i" "$n"; n=$((n+1)); done
        ;;
      3) print_hardening_plan ;;
      4|0) return 0 ;;
      *) echo "无效选项，请重新输入。" ;;
    esac
  done
}
