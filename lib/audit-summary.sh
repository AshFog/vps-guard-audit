#!/usr/bin/env bash
# shellcheck shell=bash

audit_summary() {
    section "$(t summary)"
    TOTAL=$((PASS+WARN+FAIL+INFO+SKIP))
    echo "PASS: $PASS"
    echo "WARN: $WARN"
    echo "FAIL: $FAIL"
    echo "INFO: $INFO"
    echo "SKIP: $SKIP"
    echo "TOTAL: $TOTAL"
    echo

    if ((FAIL > 0)); then
      echo "$(t high)"
      [[ "$LANGUAGE" == zh ]] && echo "需要尽快处理：" || echo "Failures requiring remediation:"
      printf '  - %s\n' "${FAILURES[@]}"
    elif ((WARN > 0)); then
      echo "$(t medium)"
    else
      echo "$(t low)"
    fi

    if ((${#WARNINGS[@]})); then
      echo
      [[ "$LANGUAGE" == zh ]] && echo "需要人工确认：" || echo "Warnings requiring review:"
      printf '  - %s\n' "${WARNINGS[@]}"
    fi

    if ((${#RECOMMENDATIONS[@]})); then
      echo
      [[ "$LANGUAGE" == zh ]] && echo "建议操作：" || echo "Recommended actions:"
      printf '%s\n' "${RECOMMENDATIONS[@]}" | awk '!seen[$0]++' | sed 's/^/  - /'
    fi

    echo
    [[ "$LANGUAGE" == zh ]] \
      && echo "重要说明：本脚本只做检查，无法绝对证明系统未被入侵。发现陌生登录、异常 UID 0 账户或恶意进程时，应立即隔离服务器并轮换密钥。" \
      || echo "Important: this audit cannot prove the host is uncompromised. Unknown logins, unexpected UID 0 accounts or malicious processes require immediate isolation and key rotation."
}
