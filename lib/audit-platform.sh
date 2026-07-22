#!/usr/bin/env bash
# shellcheck shell=bash

audit_platform() {
    section "$(t system)"
    echo "配置档案：$HOST_PROFILE"
    echo "安全策略：$POLICY"
    echo "主机名：$HOST"
    echo "内核：$(uname -srmo 2>/dev/null || true)"
    echo "虚拟化：$(systemd-detect-virt 2>/dev/null || echo 未知)"
    echo "设备类型：$(hostnamectl chassis 2>/dev/null || echo 未知)"
    safe uptime
    [[ -r /etc/os-release ]] && grep -E '^(PRETTY_NAME|VERSION_ID|VERSION_CODENAME|ID)=' /etc/os-release
    if [[ "$FULL_IDENTIFIERS" -eq 1 ]]; then safe hostnamectl; fi
    supported_os_check

    if [[ "$(cat /proc/1/comm 2>/dev/null || true)" == systemd ]]; then
      record PASS platform.systemd "systemd 正常作为 PID 1 运行" "systemd is running as PID 1"
    elif [[ "$IS_CONTAINER" -eq 1 ]]; then
      record INFO platform.systemd "容器中 systemd 不是 PID 1，部分宿主机检查不可见" "systemd is not PID 1 in this container; some host checks are unavailable"
    else
      record WARN platform.systemd "systemd 不是 PID 1，部分检查可能不完整" "systemd is not PID 1; some checks may be incomplete"
    fi

    if [[ -d /sys/module/apparmor ]]; then
      [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true)" == Y ]] \
        && record PASS kernel.apparmor "AppArmor 已启用" "AppArmor is enabled" \
        || record WARN kernel.apparmor "AppArmor 模块存在但未启用" "AppArmor module exists but is not enabled" "" \
          "启用 AppArmor 并确认关键配置文件处于 enforce 模式。" "Enable AppArmor and enforce profiles for important services."
    elif [[ "$IS_CONTAINER" -eq 1 ]]; then
      record INFO kernel.apparmor "容器中无法确认宿主机 AppArmor 状态" "Host AppArmor state is not visible from this container"
    else
      record WARN kernel.apparmor "未检测到 AppArmor" "AppArmor is unavailable"
    fi
    if have aa-status; then
      AA_SUMMARY="$(aa-status 2>/dev/null | grep -E 'profiles are loaded|profiles are in enforce|profiles are in complain|processes have profiles defined|processes are in enforce' | head -n 10 || true)"
      [[ -n "$AA_SUMMARY" ]] && echo "$AA_SUMMARY"
    else
      record SKIP apparmor.tool "未安装 aa-status，无法输出 AppArmor 统计" "aa-status is unavailable; AppArmor statistics skipped"
    fi

    section "$(t ports)"
    declare -A PUBLIC_LISTENERS=() LISTENER_PROCESSES=() LISTENER_FAMILIES=()
    avahi_ports=()
    listener_keys=()
    PORT_SCAN_AVAILABLE=0

    if have ss; then
      PORT_SCAN_AVAILABLE=1
      SOCKETS="$(ss -H -lntup 2>/dev/null || true)"
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        proto="$(awk '{print $1}' <<<"$line")"
        local_ep="$(awk '{print $5}' <<<"$line")"
        process="$(sed -n 's/.*users:/users:/p' <<<"$line")"
        [[ -n "$process" ]] || process="进程信息不可用"
        addr=""; port=""
        if [[ "$local_ep" =~ ^\[(.*)\]:([0-9]+)$ ]]; then
          addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
        elif [[ "$local_ep" =~ ^(.+):([0-9]+)$ ]]; then
          addr="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
        fi
        [[ -z "$port" ]] && continue
        if [[ "$addr" == "0.0.0.0" || "$addr" == "*" || "$addr" == "::" ]]; then
          base_proto="${proto%%[0-9]*}"
          key="${base_proto}/${port}"
          PUBLIC_LISTENERS["$key"]=1
          [[ -z "${LISTENER_PROCESSES[$key]-}" ]] && LISTENER_PROCESSES["$key"]="$process"
          family="IPv4"; [[ "$addr" == "::" ]] && family="IPv6"
          [[ " ${LISTENER_FAMILIES[$key]-} " == *" $family "* ]] || LISTENER_FAMILIES["$key"]="${LISTENER_FAMILIES[$key]-} ${family}"
          [[ "$process" == *avahi-daemon* ]] && avahi_ports+=("$key")
        fi
      done <<<"$SOCKETS"
      mapfile -t listener_keys < <(printf '%s\n' "${!PUBLIC_LISTENERS[@]}" | sed '/^$/d' | sort -t/ -k1,1 -k2,2n)
    else
      record SKIP ports.tool "未安装 ss，无法检查监听端口" "ss is unavailable; listening-port checks were skipped"
    fi

    if [[ "$PORT_SCAN_AVAILABLE" -eq 1 ]]; then
      avahi_seen=0
      for key in "${listener_keys[@]}"; do
        proto="${key%/*}"; port="${key#*/}"; process="${LISTENER_PROCESSES[$key]}"; families="$(xargs <<<"${LISTENER_FAMILIES[$key]}")"
        if [[ "$process" == *avahi-daemon* ]]; then avahi_seen=1; continue; fi
        known=""
        case "$key" in tcp/22|tcp/80|tcp/443|udp/443) known=1 ;; esac
        [[ "$proto" == tcp ]] && contains_word "$CUSTOM_ALLOWED_TCP_PORTS" "$port" && known=1
        [[ "$proto" == udp ]] && contains_word "$CUSTOM_ALLOWED_UDP_PORTS" "$port" && known=1
        detail="$families; $process"
        case "$key" in
          tcp/631)
            if [[ "$HOST_PROFILE" == desktop ]]; then
              record WARN "port.cups.$port" "CUPS 正在全部接口监听 tcp/$port" "CUPS is listening on all interfaces at tcp/$port" "$detail"
            else
              record FAIL "port.cups.$port" "CUPS 打印服务正在全部接口监听 tcp/$port" "CUPS is listening on all interfaces at tcp/$port" "$detail" \
                "服务器通常不需要 CUPS；确认无打印需求后停止并卸载对应 apt 或 Snap 服务。" \
                "Servers usually do not need CUPS; stop and remove the apt or Snap service if printing is not required."
            fi ;;
          tcp/2375|tcp/2376)
            record FAIL "port.docker_api.$port" "Docker API 正在全部接口监听 tcp/$port" "Docker API is listening on all interfaces at tcp/$port" "$detail" \
              "立即限制 Docker API，并使用双向 TLS 或仅绑定本机。" "Restrict Docker API immediately; use mutual TLS or bind it locally only." ;;
          tcp/3306|tcp/5432|tcp/6379|tcp/9200|tcp/27017)
            record WARN "port.database.$port" "数据库或数据服务正在全部接口监听 $key" "Database or data service is listening on all interfaces at $key" "$detail" \
              "确认确需外部访问，并限制来源 IP；否则仅绑定本机或私网。" "Confirm external access is required and restrict source IPs; otherwise bind locally or privately." ;;
          *)
            if [[ -n "$known" ]]; then
              record INFO "port.$proto.$port" "发现常见或已声明的全接口监听端口 $key" "Common or declared all-interface listener detected: $key" "$detail"
            else
              record WARN "port.$proto.$port" "发现需要确认的全接口监听端口 $key" "All-interface listener requires review: $key" "$detail" \
                "本地检测不能证明互联网可达；请结合主机防火墙、云防火墙和路由确认。" \
                "A local audit cannot prove Internet reachability; verify host firewall, provider firewall and routing."
            fi ;;
        esac
      done
      if ((avahi_seen)); then
        avahi_detail="$(printf '%s\n' "${avahi_ports[@]}" | sort -u | xargs)"
        if [[ "$HOST_PROFILE" == desktop ]]; then
          record INFO port.avahi "检测到局域网发现服务 Avahi/mDNS" "Avahi/mDNS local discovery service detected" "$avahi_detail"
        else
          record WARN port.avahi "服务器上检测到 Avahi/mDNS 全接口监听" "Avahi/mDNS all-interface listeners detected on a server" "$avahi_detail" \
            "公网服务器通常不需要 Avahi；确认用途后决定是否关闭。" "Public servers rarely need Avahi; confirm its purpose and disable it when unnecessary."
        fi
      fi
      distinct_count="${#listener_keys[@]}"
      ((distinct_count == 0)) \
        && record PASS ports.none "未发现绑定全部接口的监听端口" "No all-interface listeners detected" \
        || record INFO ports.count "全接口监听端口统计（已合并 IPv4/IPv6）" "All-interface listener count (IPv4/IPv6 merged)" "$distinct_count"
    fi

    section "$(t firewall)"
    firewall_ok=0
    firewall_evaluable=0
    UFW=""
    if have ufw; then
      firewall_evaluable=1
      UFW="$(ufw status verbose 2>/dev/null || true)"
      echo "$UFW"
      if grep -q '^Status: active' <<<"$UFW"; then
        record PASS fw.ufw.active "UFW 已启用" "UFW is active"
        grep -q 'Default: deny (incoming)' <<<"$UFW" && firewall_ok=1
      else
        record WARN fw.ufw.active "UFW 未启用" "UFW is inactive"
      fi
      grep -q 'Default: deny (incoming)' <<<"$UFW" \
        && record PASS fw.ufw.default "UFW 默认拒绝入站连接" "UFW default incoming policy is deny" \
        || record WARN fw.ufw.default "UFW 默认入站策略不是 deny" "UFW default incoming policy is not deny"
      systemctl is-enabled --quiet ufw 2>/dev/null \
        && record PASS fw.ufw.enabled "UFW 已设置开机启动" "UFW is enabled at boot" \
        || record WARN fw.ufw.enabled "UFW 未设置开机启动" "UFW is not enabled at boot"

      if [[ "$PORT_SCAN_AVAILABLE" -eq 1 ]]; then
        stale_rules=()
        while IFS= read -r rule; do
          [[ "$rule" == *"(v6)"* ]] && continue
          target="$(awk '{print $1}' <<<"$rule")"
          [[ "$target" =~ ^([0-9]+)/(tcp|udp)$ ]] || continue
          port="${BASH_REMATCH[1]}"; proto="${BASH_REMATCH[2]}"
          [[ -n "${PUBLIC_LISTENERS["${proto}/${port}"]+x}" ]] || stale_rules+=("${proto}/${port}")
        done < <(awk '$2=="ALLOW" && $3=="IN" {print}' <<<"$UFW")
        if ((${#stale_rules[@]})); then
          stale_joined="$(printf '%s\n' "${stale_rules[@]}" | sort -u | xargs)"
          record WARN fw.ufw.stale "发现已放行但当前无人监听的 UFW 端口" "UFW allows ports with no current listener" "$stale_joined" \
            "确认这些端口是否仍需保留；不需要时删除规则。" "Confirm whether these ports are still needed; remove stale rules when unnecessary."
        else
          record PASS fw.ufw.stale "未发现明显陈旧的 UFW 放行端口" "No obvious stale UFW allow rules detected"
        fi
      else
        record SKIP fw.ufw.stale "缺少监听端口数据，无法检查陈旧 UFW 规则" "Listener data is unavailable; stale UFW rules were not checked"
      fi
    else
      record INFO fw.ufw.absent "系统未安装 UFW" "UFW is not installed"
    fi

    if have firewall-cmd; then
      firewall_evaluable=1
      if firewall-cmd --state >/dev/null 2>&1; then
        record INFO fw.firewalld "firewalld 正在运行" "firewalld is running"
        firewall_ok=1
      else
        record INFO fw.firewalld "已安装 firewalld，但当前未运行" "firewalld is installed but inactive"
      fi
    fi

    NFT=""
    if have nft; then
      firewall_evaluable=1
      NFT="$(nft list ruleset 2>/dev/null || true)"
      nft_tables="$(grep -c '^table ' <<<"$NFT" || true)"
      echo "nftables 表数量：$nft_tables"
      if grep -Eq 'hook input[^;]*;[^}]*policy drop|hook input.*policy drop' <<<"$NFT"; then
        record PASS fw.nft.input "nftables 存在默认丢弃的 input 基链" "nftables has an input base chain with drop policy"
        firewall_ok=1
      else
        record INFO fw.nft.input "未从原生 nftables 规则中确认 input policy drop" "No native nftables input drop policy was confirmed"
      fi
    else
      record SKIP fw.nft.missing "未安装 nft 命令，跳过原生 nftables 检查" "nft command unavailable; native nftables check skipped"
    fi

    IPT=""
    if have iptables; then
      firewall_evaluable=1
      echo "iptables 后端：$(iptables -V 2>/dev/null || true)"
      IPT="$(iptables -S INPUT 2>/dev/null || true)"
      echo "$IPT"
      grep -q '^-P INPUT DROP' <<<"$IPT" \
        && { record PASS fw.iptables.input "iptables INPUT 默认策略为 DROP" "iptables INPUT policy is DROP"; firewall_ok=1; } \
        || record INFO fw.iptables.input "iptables INPUT 默认策略不是 DROP" "iptables INPUT policy is not DROP"

      pre_ufw_accept="$(awk '
        /-j ufw-before-logging-input|-j ufw-before-input/ {exit}
        /^-A INPUT / && / -j ACCEPT([[:space:]]|$)/ {print}
      ' <<<"$IPT")"
      if [[ -n "$pre_ufw_accept" ]]; then
        count="$(wc -l <<<"$pre_ufw_accept" | tr -d ' ')"
        record WARN fw.pre_ufw_accept "发现位于 UFW 链之前的额外 ACCEPT 规则" "Extra ACCEPT rules exist before UFW chains" "$count 条规则" \
          "这些规则可能绕过 UFW；确认来源后再处理。" "These rules may bypass UFW; verify their source before changing them."
        echo "$pre_ufw_accept"
      else
        record PASS fw.pre_ufw_accept "未发现位于 UFW 链之前的额外 ACCEPT 规则" "No extra ACCEPT rules were found before UFW chains"
      fi
    else
      record SKIP fw.iptables.missing "未安装 iptables 命令" "iptables command is unavailable"
    fi

    if ((firewall_ok == 0)); then
      if [[ "$IS_CONTAINER" -eq 1 ]]; then
        record SKIP fw.none "容器内无法确认宿主机默认拒绝防火墙" "The host default-deny firewall cannot be confirmed from this container"
      elif ((firewall_evaluable == 0)); then
        record FAIL fw.none "缺少可用的防火墙工具，无法确认默认拒绝策略" "No usable firewall tool was found to confirm a default-deny policy" "" \
          "安装并配置 UFW、nftables 或其他主机防火墙。" "Install and configure UFW, nftables, or another host firewall."
      else
        record FAIL fw.none "未确认存在默认拒绝策略的主机防火墙" "No confirmed default-deny host firewall" "" \
          "至少配置一种主机防火墙，并采用默认拒绝入站策略。" "Configure a host firewall with a default-deny incoming policy."
      fi
    fi
}
