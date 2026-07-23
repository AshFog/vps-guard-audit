#!/usr/bin/env bash
# shellcheck shell=bash

print_finding_item() {
  local idx="$1" number="$2"
  local id="${FINDING_LEGACY_IDS[$idx]}" stable_id="${FINDING_IDS[$idx]}" title="${FINDING_TITLES[$idx]}" detail="${FINDING_DETAILS[$idx]}" rec="${FINDING_RECOMMENDATIONS[$idx]}"

  finding_plain_text "$id" "$rec"

  printf '%s) %s %s\n' "$number" "$stable_id" "$title"
  if [[ -n "$detail" ]]; then
    printf '   检测信息：%s\n' "$detail"
  fi
  printf '   这表示：%s\n' "$PLAIN_MEANING"
  [[ -n "$PLAIN_ACTION" ]] && printf '   建议：%s\n' "$PLAIN_ACTION"
  [[ -n "$PLAIN_CAUTION" ]] && printf '   操作提醒：%s\n' "$PLAIN_CAUTION"
  echo
}

print_sysctl_group() {
  local number="$1" idx count=0 details=""
  for idx in "${!FINDING_IDS[@]}"; do
    if [[ "${FINDING_LEVELS[$idx]}" == WARN && "${FINDING_LEGACY_IDS[$idx]}" == sysctl.* ]]; then
      count=$((count+1))
      details+="${FINDING_TITLES[$idx]}${FINDING_DETAILS[$idx]:+ — ${FINDING_DETAILS[$idx]}}"$'\n'
    fi
  done
  ((count > 0)) || return 1

  printf '%s) 有 %s 项内核或网络安全设置比建议基线更宽松\n' "$number" "$count"
  echo "   这表示：这些值与脚本采用的通用安全基线不同，但不代表服务器已经被入侵。路由、网络共享、容器、调试或桌面功能可能需要不同设置。"
  echo "   建议：不要直接复制一整套 sysctl 配置。把完整 TXT 报告、服务器用途和正在运行的服务交给可信的 AI 助手，让它只调整确实适用的项目，并给出备份、验证和回滚方法。"
  echo "   本次涉及："
  printf '%s' "$details" | sed 's/^/     - /'
  echo
  return 0
}

print_bucket_findings() {
  local bucket="$1" number=1 idx current
  local printed=0
  for idx in "${!FINDING_IDS[@]}"; do
    [[ "${FINDING_LEVELS[$idx]}" == WARN ]] || continue
    [[ "${FINDING_LEGACY_IDS[$idx]}" == sysctl.* ]] && continue
    current="$(finding_bucket "${FINDING_LEGACY_IDS[$idx]}")"
    [[ "$current" == "$bucket" ]] || continue
    print_finding_item "$idx" "$number"
    number=$((number+1))
    printed=1
  done
  if [[ "$bucket" == improve ]]; then
    if print_sysctl_group "$number"; then
      printed=1
    fi
  fi
  return $((printed == 0))
}

print_ai_handoff() {
  echo
  echo "------------------------------------------------------------------------------"
  cat <<'EOF_AI_ZH'
使用 AI 获取更详细的修复方案

请优先提交本次生成的 *-ai.txt 脱敏报告，而不是完整报告。
AI 脱敏报告会替换部分主机名、用户名、容器名称、域名、IP、邮箱、MAC 地址和密钥指纹，
但自动脱敏无法保证覆盖所有自定义信息，提交前仍需亲自检查。

建议同时告诉 AI：
  - 服务器主要运行什么服务；
  - 当前使用哪个 SSH 端口登录；
  - 哪些端口、容器、代理或网站是你主动部署的；
  - 是否拥有云平台控制台、VNC、串口控制台或救援模式；
  - 修改是否可以安排维护窗口。

可以直接使用下面的提问方式：

请分析这份 VPS Guard Audit 报告。
1. 先用简单语言总结目前的安全状况。
2. 区分需要尽快处理、建议改进、需要本人确认和可选加固。
3. 不要把所有监听端口都当成恶意服务。
4. 每个问题说明原因、实际风险和可能影响的现有服务。
5. 提供适用于报告中系统版本的修复步骤。
6. 涉及 SSH、防火墙、Docker、网络或重启时，先说明断连和停机风险。
7. 修改前提供备份或快照建议，修改后提供验证和回滚方法。
8. 不要建议清空 iptables/nftables、重置 UFW，或直接关闭当前 SSH 端口。
9. 一次只处理一个可能导致断连的项目。

不要提交密码、SSH 私钥、API Key、访问令牌、Cookie 或其他凭据。
EOF_AI_ZH
}

audit_summary() {
  local idx number
  prepare_history_comparison
  section "$(t summary)"
  TOTAL=$((PASS+WARN+FAIL+INFO+SKIP))

  echo "本次检查结论"
    if ((FAIL > 0)); then
      echo "发现了需要尽快处理的问题。先不要批量修改配置，应逐项确认，并优先处理账户、SSH、防火墙或恶意进程相关问题。"
    elif ((WARN > 0)); then
      echo "没有发现明确的高危问题，但有一些项目建议确认或改进。警告不等于服务器已经被入侵。"
    else
      echo "没有发现明确的高危问题，当前基础配置总体正常。"
    fi
    echo
    echo "检查结果概览："
    echo "  检查正常：$PASS"
    echo "  建议确认或改进：$WARN"
    echo "  需要尽快处理：$FAIL"
    echo "  补充信息：$INFO"
    echo "  本次未检查：$SKIP"
    echo "  总检查项：$TOTAL"

  print_history_comparison

  if ((FAIL > 0)); then
    echo
    echo "需要尽快处理"
    echo "------------------------------------------------------------------------------"
    number=1
    for idx in "${!FINDING_IDS[@]}"; do
      [[ "${FINDING_LEVELS[$idx]}" == FAIL ]] || continue
      print_finding_item "$idx" "$number"
      number=$((number+1))
    done
  fi

  if ((WARN > 0)); then
    echo
    echo "需要本人确认"
    echo "------------------------------------------------------------------------------"
    if ! print_bucket_findings confirm; then
      echo "  本次没有需要本人确认的项目。"
    fi

    echo
    echo "建议改进"
    echo "------------------------------------------------------------------------------"
    if ! print_bucket_findings improve; then
      echo "  本次没有其他建议改进项目。"
    fi
  fi

  echo
  echo "说明：检测阶段保持只读；只有在菜单中明确输入 APPLY，才会执行已开放的加固动作。"
  echo "任何检测结果都无法绝对证明系统未被入侵。"
  echo "发现陌生成功登录、异常 UID 0 账户或明确恶意进程时，应立即限制外部访问、保存证据并轮换凭据。"

  print_ai_handoff
}
