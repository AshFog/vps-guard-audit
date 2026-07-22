#!/usr/bin/env bash
# shellcheck shell=bash

audit_containers() {
    section "$(t docker)"
    if have docker; then
      if docker info >/dev/null 2>&1; then
        record INFO docker.active "Docker 守护进程正在运行" "Docker daemon is active"
        DOCKER_PS="$(docker ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' 2>/dev/null || true)"
        echo -e "ID\tNAME\tIMAGE\tPORTS\tSTATUS"
        printf '%s\n' "$DOCKER_PS" | trim_lines
        ids="$(docker ps -q 2>/dev/null || true)"
        if [[ -n "$ids" ]]; then
          PUBLISHED=""
          while IFS= read -r id; do
            [[ -z "$id" ]] && continue
            cname="$(docker inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')"
            ports="$(docker port "$id" 2>/dev/null || true)"
            while IFS= read -r mapping; do
              [[ -z "$mapping" ]] && continue
              if grep -Eq '-> (0\.0\.0\.0:|\[::\]:)' <<<"$mapping"; then PUBLISHED+="$cname $mapping"$'\n'; fi
            done <<<"$ports"
          done <<<"$ids"
          if [[ -n "$PUBLISHED" ]]; then
            record WARN docker.published "Docker 容器端口发布到全部接口" "Docker container ports are published on all interfaces" "$(sed '/^$/d' <<<"$PUBLISHED" | wc -l | tr -d ' ') mapping(s)" \
              "UFW INPUT 规则不能单独证明这些端口已被阻止；请检查 Docker 转发链、云防火墙和绑定地址。" \
              "UFW INPUT rules alone do not prove these ports are blocked; inspect Docker forwarding chains, provider firewall and bind addresses."
            printf '%s' "$PUBLISHED" | trim_lines
          else
            record PASS docker.published "未发现发布到全部接口的 Docker 容器端口" "No Docker container ports are published on all interfaces"
          fi

          INSPECT="$(docker inspect $ids --format '{{.Name}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}} ipc={{.HostConfig.IpcMode}} user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} security={{json .HostConfig.SecurityOpt}} caps={{json .HostConfig.CapAdd}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' 2>/dev/null || true)"
          PRIV="$(grep -E 'privileged=true' <<<"$INSPECT" || true)"
          [[ -z "$PRIV" ]] && record PASS docker.priv "未发现特权 Docker 容器" "No running privileged Docker containers" || { record WARN docker.priv "发现特权 Docker 容器" "Privileged Docker containers detected" "$(wc -l <<<"$PRIV" | tr -d ' ')"; echo "$PRIV"; }
          HOSTMODES="$(grep -E 'network=host|pid=host|ipc=host' <<<"$INSPECT" || true)"
          [[ -z "$HOSTMODES" ]] || { record WARN docker.host_modes "容器使用宿主机 network/PID/IPC 命名空间" "Containers use host network/PID/IPC namespaces"; echo "$HOSTMODES"; }
          WEAKSEC="$(grep -Ei 'apparmor=unconfined|seccomp=unconfined|SYS_ADMIN|NET_ADMIN|"ALL"' <<<"$INSPECT" || true)"
          [[ -z "$WEAKSEC" ]] || { record WARN docker.weak_isolation "容器存在弱化隔离设置或高风险 capability" "Containers weaken isolation or add high-risk capabilities"; echo "$WEAKSEC"; }
          SENSITIVE_MOUNTS="$(grep -E '(/var/run/docker\.sock| /:|:/etc |:/root |:/proc |:/sys )' <<<"$INSPECT" || true)"
          [[ -z "$SENSITIVE_MOUNTS" ]] || { record WARN docker.mounts "容器挂载了敏感宿主资源" "Containers mount sensitive host resources"; echo "$SENSITIVE_MOUNTS"; }
        else
          record INFO docker.none "没有运行中的 Docker 容器" "No running Docker containers"
        fi
        if have iptables && iptables -S DOCKER-USER >/dev/null 2>&1; then
          rules="$(iptables -S DOCKER-USER 2>/dev/null || true)"
          echo "$rules"
          grep -Eq -- '-j (DROP|REJECT)' <<<"$rules" \
            && record PASS docker.user_chain "DOCKER-USER 链包含限制规则" "DOCKER-USER chain contains restrictive rules" \
            || record INFO docker.user_chain "DOCKER-USER 链未发现明显 DROP/REJECT 规则" "No obvious DROP/REJECT rule found in DOCKER-USER chain"
        else
          record INFO docker.user_chain "未从 iptables 读取到 DOCKER-USER 链，Docker 可能使用其他后端" "DOCKER-USER chain was not available through iptables; Docker may use another backend"
        fi
        DOCKER_GROUP="$(getent group docker 2>/dev/null || true)"
        [[ -n "$DOCKER_GROUP" ]] && record INFO docker.group "docker 组成员可获得近似 root 权限，请确认成员" "Docker group members effectively have root-level access; review membership" "$DOCKER_GROUP"
      else
        record INFO docker.inactive "Docker 已安装但守护进程未运行或不可访问" "Docker is installed but the daemon is inactive or inaccessible"
      fi
    else
      record SKIP docker.absent "未安装 Docker" "Docker is not installed"
    fi
    section "$(t malware)"
    echo "--- deleted executables still running ---"
    if have lsof; then
      DELETED="$(lsof +L1 2>/dev/null | awk '$4 ~ /txt/ || $9 ~ /\(deleted\)/' | head -n 100 || true)"
      [[ -z "$DELETED" ]] \
        && record PASS malware.deleted "未发现仍在运行的已删除可执行文件" "No deleted executables remain in use" \
        || { record WARN malware.deleted "发现已删除但仍在使用的文件" "Deleted files are still in use"; echo "$DELETED"; }
    else
      record SKIP malware.deleted "未安装 lsof，跳过已删除可执行文件检查" "lsof is unavailable; deleted-executable check skipped"
    fi
    echo "--- executable files recently modified in temporary directories ---"
    TMP_EXEC="$(find /tmp /var/tmp /dev/shm -xdev -type f -mtime -7 -perm /111 ! -path "$SELF_PATH" ! -path "$TMP_DIR/*" -ls 2>/dev/null | head -n 100 || true)"
    [[ -z "$TMP_EXEC" ]] \
      && record PASS malware.tmp "临时目录中未发现除审计脚本外的近期可执行文件" "No recent temporary executables were found other than the audit script" \
      || { record WARN malware.tmp "临时目录中存在近期可执行文件" "Recent executable files found in temporary directories"; echo "$TMP_EXEC"; }
    echo "--- suspicious process names ---"
    SUS_PROC="$(ps auxww 2>/dev/null | grep -Ei 'xmrig|minerd|kinsing|kdevtmpfsi|cryptominer|watchbog|masscan|zmap' | grep -vE 'grep|vps-guard-audit' || true)"
    [[ -z "$SUS_PROC" ]] \
      && record PASS malware.process "未发现常见挖矿或扫描器进程名称" "No common miner or scanner process names detected" \
      || record FAIL malware.process "发现常见恶意进程特征" "Common malicious process signature detected" "$SUS_PROC"
    section "$(t proxy)"
    PATTERN='sing-box|xray|v2ray|hysteria|tuic|naive|anytls|3x-ui|x-ui|hiddify|mihomo|clash|v2ray-agent|wireguard'
    systemctl list-unit-files --type=service 2>/dev/null | grep -Ei "$PATTERN" || true
    ps aux 2>/dev/null | grep -Ei "$PATTERN" | grep -vE 'grep|vps-guard-audit' || true
    for risky in ufw_remove.sh empty_login_history.sh; do
      found="$(find /root /tmp /etc /usr/local -type f -name "$risky" -print 2>/dev/null | head -n 5)"
      [[ -z "$found" ]] \
        && record PASS "proxy.$risky" "未发现 $risky" "$risky not found" \
        || record WARN "proxy.$risky" "发现高风险辅助脚本 $risky" "Risky helper script found: $risky" "$found"
    done
    section "$(t rootkit)"
    if [[ "$CHECK_ROOTKITS" -eq 1 ]]; then
      if have rkhunter; then
        if rkhunter --check --sk --nocolors; then
          record PASS rootkit.rkhunter "rkhunter 扫描已完成" "rkhunter scan completed"
        else
          record WARN rootkit.rkhunter "rkhunter 返回警告或执行错误" "rkhunter returned warnings or an execution error"
        fi
      else
        record SKIP rootkit.rkhunter "未安装 rkhunter" "rkhunter is not installed"
      fi
      if have chkrootkit; then
        if chkrootkit; then
          record PASS rootkit.chkrootkit "chkrootkit 扫描已完成" "chkrootkit scan completed"
        else
          record WARN rootkit.chkrootkit "chkrootkit 返回警告或执行错误" "chkrootkit returned warnings or an execution error"
        fi
      else
        record SKIP rootkit.chkrootkit "未安装 chkrootkit" "chkrootkit is not installed"
      fi
    else
      record SKIP rootkit.disabled "默认不运行 Rootkit 扫描器；可加 --rootkit-check" "Rootkit scanners are disabled by default; use --rootkit-check"
    fi
}
