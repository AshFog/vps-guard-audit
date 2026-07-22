#!/usr/bin/env bash
# shellcheck shell=bash

audit_system() {
    section "$(t persistence)"
    FAILED_UNITS="$(systemctl --failed --no-legend 2>/dev/null || true)"
    if [[ "$F2B_FAILURE_RECORDED" -eq 1 ]]; then
      FAILED_UNITS="$(grep -v 'fail2ban.service' <<<"$FAILED_UNITS" || true)"
    fi
    if [[ -z "$FAILED_UNITS" ]]; then
      record PASS systemd.failed "没有未单独报告的失败 systemd 单元" "No additional failed systemd units"
    else
      failed_count="$(wc -l <<<"$FAILED_UNITS" | tr -d ' ')"
      record WARN systemd.failed "发现失败的 systemd 单元" "Failed systemd units detected" "$failed_count"
      printf '%s\n' "$FAILED_UNITS" | trim_lines
    fi
    echo "--- 已启用服务（前 $MAX_LIST_ITEMS 项）---"
    systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | trim_lines || true
    echo "--- root 的 crontab ---"; crontab -l 2>/dev/null | trim_lines || echo "无"
    echo "--- 系统 Cron（前 $MAX_LIST_ITEMS 项）---"; grep -RHsEv '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d 2>/dev/null | trim_lines || true
    echo "--- systemd 定时器（前 $MAX_LIST_ITEMS 项）---"; systemctl list-timers --all --no-pager --no-legend 2>/dev/null | trim_lines || true
    BAD_CRON="$(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -xdev -type f -perm -0002 -print 2>/dev/null || true)"
    [[ -z "$BAD_CRON" ]] \
      && record PASS cron.mode "未发现全局可写的 Cron 文件" "No world-writable cron files" \
      || record FAIL cron.mode "发现全局可写的 Cron 文件" "World-writable cron files detected" "$BAD_CRON"

    section "$(t packages)"
    if have dpkg; then
      AUDIT="$(dpkg --audit 2>/dev/null || true)"
      [[ -z "$AUDIT" ]] \
        && record PASS pkg.dpkg "dpkg 状态正常" "dpkg state is clean" \
        || { record WARN pkg.dpkg "dpkg 存在未完成状态" "dpkg reports incomplete package state"; echo "$AUDIT"; }
    fi
    if [[ "$CHECK_UPDATES" -eq 1 ]] && have apt; then
      if [[ "$REFRESH_PACKAGE_INDEX" -eq 1 ]]; then
        apt-get -qq update >/dev/null 2>&1 \
          && record INFO pkg.index.refresh "已按用户要求刷新 APT 软件包索引" "APT package indexes were refreshed as requested" \
          || record WARN pkg.index "软件源索引刷新失败" "Package index refresh failed"
      else
        newest_index="$(find /var/lib/apt/lists -maxdepth 1 -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -n1 | cut -d. -f1)"
        if [[ "$newest_index" =~ ^[0-9]+$ ]]; then
          age_days=$(( ($(date +%s) - newest_index) / 86400 ))
          ((age_days <= 7)) \
            && record PASS pkg.index.age "APT 软件包索引较新" "APT package indexes are recent" "$age_days 天" \
            || record WARN pkg.index.age "APT 软件包索引可能过旧" "APT package indexes may be stale" "$age_days 天" \
              "需要最新结果时，使用 --refresh-package-index。" "Use --refresh-package-index when fresh results are required."
        else
          record SKIP pkg.index.age "无法确定 APT 索引更新时间" "Unable to determine APT index age"
        fi
      fi
      UPDATES="$(apt list --upgradable 2>/dev/null | sed '1d' || true)"
      update_count="$(sed '/^$/d' <<<"$UPDATES" | wc -l | tr -d ' ')"
      security_count="$(grep -Eic 'security|updates-security' <<<"$UPDATES" || true)"
      kernel_count="$(grep -Eic '(^|/)(linux-image|linux-headers|linux-base)' <<<"$UPDATES" || true)"
      if [[ "$update_count" -eq 0 ]]; then
        record PASS pkg.updates "没有待更新的软件包" "No package updates are pending"
      else
        record WARN pkg.updates "存在待更新的软件包" "Package updates are pending" "共 $update_count 个；安全更新 $security_count 个；内核相关 $kernel_count 个"
        printf '%s\n' "$UPDATES" | trim_lines
        ((update_count > MAX_LIST_ITEMS)) && echo "……另有 $((update_count-MAX_LIST_ITEMS)) 项未显示"
      fi
      HELD="$(apt-mark showhold 2>/dev/null || true)"
      [[ -z "$HELD" ]] \
        && record PASS pkg.held "没有被 hold 的软件包" "No packages are held" \
        || { record WARN pkg.held "存在被 hold 的软件包" "Held packages detected" "$(wc -l <<<"$HELD" | tr -d ' ')"; printf '%s\n' "$HELD" | trim_lines; }
      if grep -RqsE 'security\.debian\.org|-[Ss]ecurity|security\.ubuntu\.com' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
        record PASS pkg.security_source "检测到发行版安全更新源" "Distribution security update source detected"
      else
        record WARN pkg.security_source "未确认发行版安全更新源" "Distribution security update source was not confirmed"
      fi
      if [[ -e /var/run/reboot-required ]]; then
        record WARN pkg.reboot "系统标记为需要重启" "System reports that a reboot is required"
      fi
      running_kernel="$(uname -r)"
      latest_kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null | sed 's/^vmlinuz-//' | sort -V | tail -n1)"
      if [[ -n "$latest_kernel" && "$latest_kernel" != "$running_kernel" ]]; then
        record WARN pkg.kernel_running "当前运行内核不是 /boot 中最新安装版本" "Running kernel is not the newest installed under /boot" "$running_kernel -> $latest_kernel"
      else
        record PASS pkg.kernel_running "当前运行内核与最新安装版本一致" "Running kernel matches the newest installed version" "$running_kernel"
      fi
      dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'ok installed' \
        && record PASS pkg.unattended "已安装 unattended-upgrades" "unattended-upgrades is installed" \
        || record WARN pkg.unattended "未安装 unattended-upgrades" "unattended-upgrades is not installed" "" \
          "建议安装并启用 unattended-upgrades 自动安装安全更新。" "Install and enable unattended-upgrades for automatic security fixes."
    elif [[ "$CHECK_UPDATES" -eq 0 ]]; then
      record SKIP pkg.updates "已跳过软件更新检查" "Package update check skipped"
    else
      record SKIP pkg.updates "系统没有可用的 apt 命令" "apt is unavailable; package update check skipped"
    fi

    if [[ "$DEPTH" != quick ]]; then
    section "$(t sysctl)"
    check_sysctl() {
      local key="$1" expected="$2" val
      val="$(sysctl -n "$key" 2>/dev/null || true)"
      if [[ -z "$val" ]]; then
        echo "$key = unavailable"
        record SKIP "sysctl.$key" "$key 在当前系统中不可读取" "$key is unavailable on this system"
        return
      fi
      echo "$key = $val"
      [[ "$val" == "$expected" ]] \
        && record PASS "sysctl.$key" "$key 符合建议值" "$key matches recommended value" "$expected" \
        || record WARN "sysctl.$key" "$key 与建议值不一致" "$key differs from recommended value" "$val; expected $expected"
    }
    check_sysctl kernel.randomize_va_space 2
    check_sysctl kernel.kptr_restrict 1
    check_sysctl kernel.yama.ptrace_scope 1
    check_sysctl fs.protected_hardlinks 1
    check_sysctl fs.protected_symlinks 1
    check_sysctl net.ipv4.tcp_syncookies 1
    check_sysctl net.ipv4.conf.all.accept_redirects 0
    check_sysctl net.ipv4.conf.default.accept_redirects 0
    check_sysctl net.ipv4.conf.all.send_redirects 0
    check_sysctl net.ipv4.conf.default.send_redirects 0
    check_sysctl net.ipv4.conf.all.accept_source_route 0
    check_sysctl net.ipv4.conf.default.accept_source_route 0
    check_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
    check_sysctl net.ipv4.conf.all.log_martians 1
    check_sysctl net.ipv6.conf.all.accept_redirects 0
    check_sysctl net.ipv6.conf.default.accept_redirects 0
    else
      section "$(t sysctl)"
      record SKIP sysctl.depth "快速检查跳过内核参数基线" "Kernel baseline skipped in quick mode"
    fi

    if [[ "$DEPTH" == deep ]]; then
    section "$(t files)"
    for item in "/etc/passwd:644" "/etc/group:644" "/etc/shadow:600,640" "/etc/gshadow:600,640" "/etc/ssh/sshd_config:600,644"; do
      path="${item%%:*}"; expected="${item#*:}"
      [[ -e "$path" ]] || { record WARN "perm.$path" "$path 不存在" "$path is missing"; continue; }
      mode="$(stat -c %a "$path" 2>/dev/null || true)"
      [[ ",$expected," == *",$mode,"* ]] \
        && record PASS "perm.$path" "$path 权限合理" "$path permissions are acceptable" "$mode" \
        || record WARN "perm.$path" "$path 权限需要确认" "$path permissions require review" "$mode; expected $expected"
    done
    for d in /etc/systemd/system /usr/local/bin /usr/local/sbin /etc/ssh /etc/cron.d; do
      [[ -d "$d" ]] || continue
      bad="$(find "$d" -xdev -type f -perm -0002 -print 2>/dev/null || true)"
      [[ -z "$bad" ]] \
        && record PASS "world.$d" "$d 中没有全局可写文件" "No world-writable files in $d" \
        || record FAIL "world.$d" "$d 中存在全局可写文件" "World-writable files in $d" "$bad"
    done
    echo "--- 主机 SUID/SGID 清单 ---"
    SUID_LIST="$(find / -xdev \
      \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/snapd \) -prune -o \
      -type f -perm /111 \( -perm -4000 -o \( -perm -2000 -user root \) \) -printf '%m %u:%g %p\n' 2>/dev/null | sort || true)"
    suid_count="$(sed '/^$/d' <<<"$SUID_LIST" | wc -l | tr -d ' ')"
    echo "主机 SUID/SGID 数量：$suid_count"
    printf '%s\n' "$SUID_LIST" | trim_lines
    SUID_UNUSUAL="$(awk '$2 ~ /^root:/ && $3 ~ /^\/(tmp|var\/tmp|dev\/shm|home|opt|usr\/local)\// {print}' <<<"$SUID_LIST" || true)"
    [[ -z "$SUID_UNUSUAL" ]] \
      && record PASS suid.unusual "未发现位于高风险路径的 SUID/SGID 文件" "No SUID/SGID files found in high-risk paths" \
      || { record WARN suid.unusual "高风险路径中存在 SUID/SGID 文件" "SUID/SGID files detected in high-risk paths" "$(wc -l <<<"$SUID_UNUSUAL" | tr -d ' ')"; echo "$SUID_UNUSUAL"; }
    else
      section "$(t files)"
      record SKIP perm.depth "仅深度检查扫描敏感文件权限和 SUID/SGID" "Sensitive permissions and SUID/SGID inventory require deep mode"
    fi
}
