#!/usr/bin/env bash
# shellcheck shell=bash

audit_deep() {
  section "17. 深度检查"

  if systemctl list-unit-files auditd.service >/dev/null 2>&1 || have auditctl; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
      record PASS deep.auditd "auditd 审计服务正在运行" "" "系统能够记录较完整的安全审计事件"
      have auditctl && auditctl -s 2>/dev/null | trim_lines 20 || true
    else
      record WARN deep.auditd "已安装 auditd，但服务没有运行" "" "深度检查建议确认 auditd 状态" \
        "运行 systemctl status auditd --no-pager 和 journalctl -u auditd -n 80 --no-pager，确认失败原因后再决定是否启用。"
    fi
  else
    record WARN deep.auditd "未检测到 auditd 审计服务" "" "系统缺少常用的安全事件审计组件" \
      "公网服务器可考虑安装并启用 auditd；启用前先确认磁盘空间、日志轮转和性能影响。"
  fi

  if have systemd-analyze && [[ "$(cat /proc/1/comm 2>/dev/null || true)" == systemd ]]; then
    security_output="$(systemd-analyze security --no-pager --no-legend 2>/dev/null || true)"
    if [[ -n "$security_output" ]]; then
      unsafe_count="$(grep -Ec 'UNSAFE|DANGEROUS' <<<"$security_output" || true)"
      echo "--- systemd-analyze security（最多 20 行）---"
      printf '%s\n' "$security_output" | sort -k3,3nr | trim_lines 20
      if ((unsafe_count > 0)); then
        record WARN deep.systemd_security "部分 systemd 服务隔离评分较弱" "" "$unsafe_count 个服务被 systemd 标记为 UNSAFE 或 DANGEROUS" \
          "先确认服务用途，再通过 systemctl edit 服务名逐项增加适用的隔离设置；不要批量套用模板。"
      else
        record INFO deep.systemd_security "已完成 systemd 服务隔离检查" "" "未读取到 UNSAFE 或 DANGEROUS 标记"
      fi
    else
      record SKIP deep.systemd_security "systemd-analyze 没有返回服务隔离结果" ""
    fi
  else
    record SKIP deep.systemd_security "当前环境无法运行 systemd 服务隔离检查" ""
  fi

  cert_count=0
  cert_warn=0
  cert_fail=0
  if have openssl && [[ -d /etc/letsencrypt/live ]]; then
    while IFS= read -r cert; do
      [[ -r "$cert" ]] || continue
      cert_count=$((cert_count+1))
      end_raw="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2- || true)"
      [[ -n "$end_raw" ]] || continue
      end_epoch="$(date -d "$end_raw" +%s 2>/dev/null || true)"
      [[ "$end_epoch" =~ ^[0-9]+$ ]] || continue
      days=$(( (end_epoch - $(date +%s)) / 86400 ))
      echo "证书：$cert；剩余天数：$days"
      if ((days < 0)); then
        cert_fail=$((cert_fail+1))
      elif ((days <= 30)); then
        cert_warn=$((cert_warn+1))
      fi
    done < <(find /etc/letsencrypt/live -maxdepth 2 -type l -name fullchain.pem -print 2>/dev/null | sort | head -n 50)

    if ((cert_fail > 0)); then
      record FAIL deep.cert_expiry "检测到已过期的 Let's Encrypt 证书" "" "$cert_fail 个证书已过期" \
        "检查 certbot timer、续期日志、域名解析和 80/443 访问条件，修复后重新验证证书。"
    elif ((cert_warn > 0)); then
      record WARN deep.cert_expiry "部分 Let's Encrypt 证书将在 30 天内到期" "" "$cert_warn 个证书需要确认自动续期" \
        "运行 certbot renew --dry-run，并检查 systemctl status certbot.timer --no-pager。"
    elif ((cert_count > 0)); then
      record PASS deep.cert_expiry "Let's Encrypt 证书有效期暂时正常" "" "$cert_count 个证书"
    else
      record SKIP deep.cert_expiry "没有找到可读取的 Let's Encrypt 证书" ""
    fi
  else
    record SKIP deep.cert_expiry "未检测到 openssl 或 Let's Encrypt 证书目录" ""
  fi

  for mountpoint in /tmp /var/tmp; do
    if have findmnt; then
      mount_opts="$(findmnt -n -o OPTIONS --target "$mountpoint" 2>/dev/null || true)"
      if [[ -z "$mount_opts" ]]; then
        record SKIP "deep.tmp_mount.$mountpoint" "无法读取 $mountpoint 的挂载参数" ""
        continue
      fi
      missing=""
      [[ ",$mount_opts," == *,nodev,* ]] || missing+=" nodev"
      [[ ",$mount_opts," == *,nosuid,* ]] || missing+=" nosuid"
      if [[ -n "$missing" ]]; then
        record WARN "deep.tmp_mount.$mountpoint" "$mountpoint 缺少部分可选安全挂载参数" "" "当前参数：$mount_opts；缺少：${missing# }" \
          "先确认应用是否需要设备文件或 SUID 行为，再评估 nodev/nosuid；不要直接添加 noexec，以免影响安装器和业务程序。"
      else
        record PASS "deep.tmp_mount.$mountpoint" "$mountpoint 已启用 nodev 和 nosuid" "" "$mount_opts"
      fi
    else
      record SKIP "deep.tmp_mount.$mountpoint" "缺少 findmnt，无法检查 $mountpoint 挂载参数" ""
    fi
  done

  integrity_tools=""
  for tool in aide tripwire afick osqueryi wazuh-agent; do
    have "$tool" && integrity_tools+=" $tool"
  done
  if [[ -n "$integrity_tools" ]]; then
    record INFO deep.integrity "检测到文件完整性或主机监控工具" "" "${integrity_tools# }"
  else
    record WARN deep.integrity "未检测到常见文件完整性监控工具" "" "这不是入侵证据，但系统缺少独立的文件变化基线" \
      "长期运行的重要服务器可评估 AIDE、Wazuh 或其他完整性监控方案，并把数据库和告警发送到服务器之外。"
  fi

  compilers=""
  for compiler in gcc g++ clang make; do
    have "$compiler" && compilers+=" $compiler"
  done
  if [[ -n "$compilers" ]]; then
    record INFO deep.compiler "系统中存在编译工具" "" "${compilers# }；开发或构建服务器可能属于正常情况"
  else
    record PASS deep.compiler "未检测到常见编译工具" ""
  fi

  entropy="$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || true)"
  if [[ "$entropy" =~ ^[0-9]+$ ]]; then
    if ((entropy < 128)); then
      record WARN deep.entropy "当前可用随机熵偏低" "" "$entropy" \
        "稍后复查，并确认虚拟化平台、随机数设备和高并发密钥操作是否正常。"
    else
      record PASS deep.entropy "当前随机熵可用量正常" "" "$entropy"
    fi
  else
    record SKIP deep.entropy "无法读取当前随机熵" ""
  fi
}
