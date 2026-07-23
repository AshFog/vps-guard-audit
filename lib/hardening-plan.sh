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
  echo "HARD-1001 至 HARD-1010 可在确认后执行；HARD-2001 至 HARD-2008 还必须通过用途确认、防失联和第二终端验证。"
}

show_sensitive_hardening_menu() {
  local answer i n admin console_ack token tx_id admins action specs group policy
  while true; do
    echo
    echo "⚠ 连接敏感加固"
    echo "以下设置可能导致 SSH 无法重新连接。请保留当前窗口，并先打开 VPS 控制台。"
    n=1
    if ((${#APPLICABLE_SENSITIVE[@]} == 0)); then
      echo "  暂无匹配项目。"
      return 0
    fi
    for i in "${APPLICABLE_SENSITIVE[@]}"; do
      print_hardening_action "$i" "$n"
      n=$((n+1))
    done
    echo
    echo "输入编号可处理已开放项目；每次只能执行一项。"
    echo "  0. 返回"
    printf '请选择：'
    IFS= read -r answer || return 0
    [[ "$answer" == 0 ]] && return 0
    if [[ ! "$answer" =~ ^[0-9]+$ ]] || ((answer < 1 || answer > ${#APPLICABLE_SENSITIVE[@]})); then
      echo "无效选项，请重新输入。"
      continue
    fi
    i="${APPLICABLE_SENSITIVE[$((answer-1))]}"
    action="${HARDENING_IDS[$i]}"
    if [[ "${HARDENING_AUTOMATION[$i]}" != yes ]]; then
      echo "${HARDENING_IDS[$i]} 暂未开放自动执行，请查看详细说明。"
      continue
    fi

    unset VPSGA_UFW_ALLOW_SPECS VPSGA_UFW_DELETE_NUMBERS VPSGA_SSH_FORWARD_ACK \
      VPSGA_NETWORK_POLICY VPSGA_NETWORK_USAGE_ACK VPSGA_SERVICE_GROUP VPSGA_SERVICE_USAGE_ACK

    case "$action" in
      HARD-2003)
        hardening_firewall_plan || { echo "无法生成端口计划。" >&2; continue; }
        echo "请输入确认需要公网放行的清单，例如：22/tcp 80/tcp 443/tcp"
        printf '端口清单：'
        IFS= read -r specs || return 0
        if ! hardening_parse_ufw_specs "$specs" "$(connection_guard_current_context | cut -f4)" >/dev/null; then
          echo "端口清单无效，已取消。" >&2
          continue
        fi
        export VPSGA_UFW_ALLOW_SPECS="$specs"
        ;;
      HARD-2004)
        echo "当前 UFW 编号规则："
        hardening_ufw_command status numbered || { echo "无法读取 UFW 规则。" >&2; continue; }
        echo "只输入已经逐条确认可删除的编号，例如：7 4 2"
        printf '删除编号：'
        IFS= read -r specs || return 0
        if ! hardening_parse_ufw_delete_numbers "$specs" >/dev/null; then
          echo "规则编号无效，已取消。" >&2
          continue
        fi
        export VPSGA_UFW_DELETE_NUMBERS="$specs"
        ;;
      HARD-2006)
        hardening_workload_plan || { echo "无法生成业务用途检查。" >&2; continue; }
        echo "此设置会影响 ssh -L/-R/-D、VS Code Remote、数据库隧道和跳板机。"
        printf '确认这些功能均不需要，请输入 NO SSH FORWARDING：'
        IFS= read -r specs || return 0
        [[ "$specs" == 'NO SSH FORWARDING' ]] || { echo "未确认 SSH 转发用途，已取消。"; continue; }
        export VPSGA_SSH_FORWARD_ACK="$specs"
        ;;
      HARD-2007)
        hardening_workload_plan || { echo "无法生成业务用途检查。" >&2; continue; }
        echo "每次只能选择一个变化："
        echo "  1. 关闭 IPv4 转发（net.ipv4.ip_forward=0）"
        echo "  2. 关闭 IPv6 转发（net.ipv6.conf.all.forwarding=0）"
        echo "  3. 关闭 IPv6（仅适合明确不使用双栈的主机）"
        printf '请选择：'
        IFS= read -r specs || return 0
        case "$specs" in
          1) policy=ipv4-forwarding-off ;;
          2) policy=ipv6-forwarding-off ;;
          3) policy=ipv6-off ;;
          *) echo "网络策略选项无效，已取消。"; continue ;;
        esac
        printf '确认 Docker、VPN、代理、软路由均不依赖所选能力，请输入 NO ROUTING REQUIRED：'
        IFS= read -r specs || return 0
        [[ "$specs" == 'NO ROUTING REQUIRED' ]] || { echo "未确认网络用途，已取消。"; continue; }
        export VPSGA_NETWORK_POLICY="$policy" VPSGA_NETWORK_USAGE_ACK="$specs"
        ;;
      HARD-2008)
        hardening_workload_plan || { echo "无法生成业务用途检查。" >&2; continue; }
        echo "仅支持经过审计的候选组：cups 或 avahi；不会卸载软件包。"
        printf '请输入要停用的服务组：'
        IFS= read -r group || return 0
        if ! hardening_service_group_valid "$group" || ! hardening_service_group_available "$group"; then
          echo "服务组无效或没有找到对应 systemd 单元，已取消。" >&2
          continue
        fi
        printf '确认该服务没有打印或局域网发现用途，请输入 SERVICE NOT NEEDED：'
        IFS= read -r specs || return 0
        [[ "$specs" == 'SERVICE NOT NEEDED' ]] || { echo "未确认服务用途，已取消。"; continue; }
        export VPSGA_SERVICE_GROUP="$group" VPSGA_SERVICE_USAGE_ACK="$specs"
        ;;
    esac

    admins="$(connection_guard_list_admins || true)"
    if [[ -z "$admins" ]]; then
      echo "没有找到具备安全公钥的非 root sudo/admin 备用管理员，拒绝执行。" >&2
      continue
    fi
    echo "可用于第二终端验证的备用管理员："
    sed 's/^/  - /' <<<"$admins"
    printf '请输入要用于第二终端的管理员用户名：'
    IFS= read -r admin || return 0
    if ! grep -Fqx -- "$admin" <<<"$admins"; then
      echo "该用户未通过备用管理员检查。" >&2
      continue
    fi
    printf '确认 VPS 网页控制台、VNC 或救援模式可用，请输入 CONSOLE READY：'
    IFS= read -r console_ack || return 0
    if [[ "$console_ack" != "CONSOLE READY" ]]; then
      echo "未确认控制台，已取消。"
      continue
    fi
    echo "即将执行：${HARDENING_IDS[$i]} ${HARDENING_TITLES[$i]}"
    echo "修改后若5分钟内未由第二 SSH 终端确认，工具将自动回滚。"
    printf '输入 APPLY 确认执行：'
    IFS= read -r answer || return 0
    [[ "$answer" == APPLY ]] || { echo "已取消。"; continue; }

    # 安装官方依赖可能耗时；先在用户确认后完成，再创建10分钟令牌和5分钟回滚 timer。
    if ! hardening_sensitive_preflight "$action"; then
      echo "连接敏感加固的依赖或冲突检查失败，尚未修改连接策略。" >&2
      continue
    fi
    token="$(connection_guard_start "$admin" "$console_ack")" || {
      echo "防失联前置检查失败，未修改 SSH。" >&2
      continue
    }
    if ! stage_sensitive_hardening_action "$action" "$token"; then
      echo "连接敏感加固未能进入确认阶段。" >&2
      continue
    fi
    tx_id="$HARDENING_TX_ID"
    echo
    echo "配置已临时应用，当前窗口不要关闭。"
    echo "请以 $admin 打开第二个 SSH 连接，并运行："
    echo "  sudo vpsga connection-confirm $token"
    echo "第二终端显示验证成功后，回到这里输入 CONFIRM。"
    printf '输入 CONFIRM 提交，其他输入将保留自动回滚：'
    IFS= read -r answer || answer=""
    if [[ "$answer" == CONFIRM ]] && connection_guard_finalize_transaction "$tx_id" "$token"; then
      echo "[${HARDENING_IDS[$i]}] 第二终端验证成功，事务已提交：$tx_id"
    else
      echo "尚未完成第二终端验证。请保持当前 SSH 连接；延时任务会恢复配置。" >&2
    fi
    hardening_tx_close
    collect_applicable_hardening
  done
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
        show_sensitive_hardening_menu
        ;;
      3) print_hardening_plan ;;
      4|0) return 0 ;;
      *) echo "无效选项，请重新输入。" ;;
    esac
  done
}
