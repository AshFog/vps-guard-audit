#!/usr/bin/env bash
# shellcheck shell=bash

print_finding_item() {
  local idx="$1" number="$2"
  local id="${FINDING_IDS[$idx]}" title="${FINDING_TITLES[$idx]}" detail="${FINDING_DETAILS[$idx]}" rec="${FINDING_RECOMMENDATIONS[$idx]}"

  finding_plain_text "$id" "$rec"

  printf '%s) %s\n' "$number" "$title"
  if [[ -n "$detail" ]]; then
    [[ "$LANGUAGE" == zh ]] && printf '   检测信息：%s\n' "$detail" || printf '   Detected: %s\n' "$detail"
  fi
  [[ "$LANGUAGE" == zh ]] && printf '   这表示：%s\n' "$PLAIN_MEANING" || printf '   What it means: %s\n' "$PLAIN_MEANING"
  [[ -n "$PLAIN_ACTION" ]] && { [[ "$LANGUAGE" == zh ]] && printf '   建议：%s\n' "$PLAIN_ACTION" || printf '   Suggested next step: %s\n' "$PLAIN_ACTION"; }
  [[ -n "$PLAIN_CAUTION" ]] && { [[ "$LANGUAGE" == zh ]] && printf '   操作提醒：%s\n' "$PLAIN_CAUTION" || printf '   Caution: %s\n' "$PLAIN_CAUTION"; }
  echo
}

print_sysctl_group() {
  local number="$1" idx count=0 details=""
  for idx in "${!FINDING_IDS[@]}"; do
    if [[ "${FINDING_LEVELS[$idx]}" == WARN && "${FINDING_IDS[$idx]}" == sysctl.* ]]; then
      count=$((count+1))
      details+="${FINDING_TITLES[$idx]}${FINDING_DETAILS[$idx]:+ — ${FINDING_DETAILS[$idx]}}"$'\n'
    fi
  done
  ((count > 0)) || return 1

  if [[ "$LANGUAGE" == zh ]]; then
    printf '%s) 有 %s 项内核或网络安全设置比建议基线更宽松\n' "$number" "$count"
    echo "   这表示：这些值与脚本采用的通用安全基线不同，但不代表服务器已经被入侵。路由、网络共享、容器、调试或桌面功能可能需要不同设置。"
    echo "   建议：不要直接复制一整套 sysctl 配置。把完整 TXT 报告、服务器用途和正在运行的服务交给可信的 AI 助手，让它只调整确实适用的项目，并给出备份、验证和回滚方法。"
    echo "   本次涉及："
  else
    printf '%s) %s kernel or network settings are looser than the audit baseline\n' "$number" "$count"
    echo "   What it means: These values differ from a general security baseline, but they do not show that the host is compromised. Routing, network sharing, containers, debugging, or desktop features may require different settings."
    echo "   Suggested next step: Do not paste a complete generic sysctl template. Give the full TXT report, host role, and running services to a trusted AI assistant and ask for only applicable changes with backup, verification, and rollback steps."
    echo "   Included settings:"
  fi
  printf '%s' "$details" | sed 's/^/     - /'
  echo
  return 0
}

print_bucket_findings() {
  local bucket="$1" number=1 idx current
  local printed=0
  for idx in "${!FINDING_IDS[@]}"; do
    [[ "${FINDING_LEVELS[$idx]}" == WARN ]] || continue
    [[ "${FINDING_IDS[$idx]}" == sysctl.* ]] && continue
    current="$(finding_bucket "${FINDING_IDS[$idx]}")"
    [[ "$current" == "$bucket" ]] || continue
    print_finding_item "$idx" "$number"
    number=$((number+1))
    printed=1
  done
  if [[ "$bucket" == improve ]]; then
    if print_sysctl_group "$number"; then
      number=$((number+1))
      printed=1
    fi
  fi
  return $((printed == 0))
}

print_ai_handoff() {
  echo
  echo "------------------------------------------------------------------------------"
  if [[ "$LANGUAGE" == zh ]]; then
    cat <<'EOF_AI_ZH'
使用 AI 获取更详细的修复方案

这份 TXT 文件是本次检查的完整报告。你可以把它提交给可信的 AI 助手，
让 AI 结合系统版本、服务器用途和检测结果，逐项解释问题并制定修复计划。

建议同时告诉 AI：
  - 服务器主要运行什么服务；
  - 当前使用哪个 SSH 端口登录；
  - 哪些端口、容器、代理或网站是你主动部署的；
  - 是否拥有云平台控制台、VNC、串口控制台或救援模式；
  - 修改是否可以安排维护窗口。

可以直接使用下面的提问方式：

请分析这份 VPS Guard Audit 完整报告。
1. 先用简单语言总结目前的安全状况。
2. 区分需要尽快处理、建议改进、需要本人确认和可选加固。
3. 不要把所有监听端口都当成恶意服务。
4. 每个问题说明原因、实际风险和可能影响的现有服务。
5. 提供适用于报告中系统版本的修复步骤。
6. 涉及 SSH、防火墙、Docker、网络或重启时，先说明断连和停机风险。
7. 修改前提供备份或快照建议，修改后提供验证和回滚方法。
8. 不要建议清空 iptables/nftables、重置 UFW，或直接关闭当前 SSH 端口。
9. 一次只处理一个可能导致断连的项目。

隐私提醒：
报告默认会隐藏部分标识信息，但提交前仍应亲自检查。
可以删除不希望公开的公网 IP、域名、用户名、容器名称、主机名和密钥指纹。
不要提交密码、SSH 私钥、API Key、访问令牌、Cookie 或其他凭据。
EOF_AI_ZH
  else
    cat <<'EOF_AI_EN'
Using AI for a more detailed remediation plan

This TXT file is the complete report from the audit. You can submit it to a trusted AI
assistant and ask it to explain each finding and prepare a remediation plan based on the
operating-system release, intended host role, and detected services.

Also tell the AI:
  - what the server is intended to run;
  - which SSH port you currently use;
  - which ports, containers, proxies, or websites you intentionally deployed;
  - whether provider console, VNC, serial console, or rescue access is available;
  - whether changes can be scheduled in a maintenance window.

Suggested prompt:

Please analyze this complete VPS Guard Audit report.
1. Begin with a plain-language summary of the current security posture.
2. Separate prompt attention, suggested improvements, owner confirmation, and optional hardening.
3. Do not assume that every listening port is malicious.
4. For each issue, explain the cause, realistic risk, and possible impact on existing services.
5. Provide steps appropriate for the operating-system release shown in the report.
6. Explain disconnect or downtime risk before SSH, firewall, Docker, networking, or reboot changes.
7. Provide backup or snapshot guidance before changes, plus verification and rollback steps afterward.
8. Do not recommend flushing iptables/nftables, resetting UFW, or directly closing the active SSH port.
9. Handle only one potentially disconnecting change at a time.

Privacy reminder:
The report redacts some identifiers by default, but review it before sharing.
Remove public IP addresses, domains, usernames, container names, hostnames, or fingerprints you do not
want to disclose. Never share passwords, SSH private keys, API keys, access tokens, cookies, or credentials.
EOF_AI_EN
  fi
}

audit_summary() {
  local idx number
  section "$(t summary)"
  TOTAL=$((PASS+WARN+FAIL+INFO+SKIP))

  if [[ "$LANGUAGE" == zh ]]; then
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
  else
    echo "Audit conclusion"
    if ((FAIL > 0)); then
      echo "Issues requiring prompt attention were found. Do not make broad configuration changes; verify each item and prioritize account, SSH, firewall, or malware findings."
    elif ((WARN > 0)); then
      echo "No clear high-risk issue was found, but some items should be reviewed or improved. A warning does not mean that the host is compromised."
    else
      echo "No clear high-risk issue was found and the baseline configuration looks generally healthy."
    fi
    echo
    echo "Result overview:"
    echo "  Checks passed: $PASS"
    echo "  Review or improvement: $WARN"
    echo "  Prompt attention: $FAIL"
    echo "  Additional information: $INFO"
    echo "  Not checked this time: $SKIP"
    echo "  Total checks: $TOTAL"
  fi

  if ((FAIL > 0)); then
    echo
    [[ "$LANGUAGE" == zh ]] && echo "需要尽快处理" || echo "Needs prompt attention"
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
    [[ "$LANGUAGE" == zh ]] && echo "需要本人确认" || echo "Requires owner confirmation"
    echo "------------------------------------------------------------------------------"
    if ! print_bucket_findings confirm; then
      [[ "$LANGUAGE" == zh ]] && echo "  本次没有需要本人确认的项目。" || echo "  No owner-confirmation items were found."
    fi

    echo
    [[ "$LANGUAGE" == zh ]] && echo "建议改进" || echo "Suggested improvements"
    echo "------------------------------------------------------------------------------"
    if ! print_bucket_findings improve; then
      [[ "$LANGUAGE" == zh ]] && echo "  本次没有其他建议改进项目。" || echo "  No additional improvements were found."
    fi
  fi

  echo
  if [[ "$LANGUAGE" == zh ]]; then
    echo "说明：本脚本只做检查，不会自动修复，也无法绝对证明系统未被入侵。"
    echo "发现陌生成功登录、异常 UID 0 账户或明确恶意进程时，应立即限制外部访问、保存证据并轮换凭据。"
  else
    echo "Note: this script performs checks only. It does not automatically repair the host and cannot prove that the system is uncompromised."
    echo "Unknown successful logins, unexpected UID 0 accounts, or confirmed malicious processes require immediate access restriction, evidence preservation, and credential rotation."
  fi

  print_ai_handoff
}
