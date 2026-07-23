#!/usr/bin/env bash
# shellcheck shell=bash
# 第一批低风险动作。所有动作必须由事务包装器调用。

hardening_system_path() {
  local path="$1" root="${VPSGA_SYSTEM_ROOT:-}"
  [[ "$path" == /* ]] || return 64
  printf '%s%s' "${root%/}" "$path"
}

hardening_capture_and_mode() {
  local path="$1" owner="$2" mode="$3"
  [[ -e "$path" && ! -L "$path" ]] || return 0
  hardening_tx_capture "$path" || return
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown "$owner" -- "$path" || return
  fi
  chmod "$mode" -- "$path"
}

hardening_action_1001() {
  local shadow_group="root" path
  getent group shadow >/dev/null 2>&1 && shadow_group="shadow"
  path="$(hardening_system_path /etc/passwd)";  hardening_capture_and_mode "$path" root:root 0644 || return
  path="$(hardening_system_path /etc/group)";   hardening_capture_and_mode "$path" root:root 0644 || return
  path="$(hardening_system_path /etc/shadow)";  hardening_capture_and_mode "$path" "root:$shadow_group" 0640 || return
  path="$(hardening_system_path /etc/gshadow)"; hardening_capture_and_mode "$path" "root:$shadow_group" 0640 || return
}

hardening_validate_1001() {
  local path expected
  for expected in '/etc/passwd:644' '/etc/group:644' '/etc/shadow:640' '/etc/gshadow:640'; do
    path="$(hardening_system_path "${expected%:*}")"
    [[ ! -e "$path" || "$(stat -c %a "$path")" == "${expected##*:}" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || ! -e "$path" || "$(stat -c %u "$path")" == 0 ]] || return 1
  done
}

hardening_action_1002() {
  local passwd_file path home shell uid gid user key ssh_dir
  passwd_file="$(hardening_system_path /etc/passwd)"
  while IFS=: read -r user _ uid gid _ home shell; do
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    ssh_dir="$(hardening_system_path "$home/.ssh")"
    key="$ssh_dir/authorized_keys"
    [[ -f "$key" && ! -L "$key" ]] || continue
    hardening_capture_and_mode "$ssh_dir" "$uid:$gid" 0700 || return
    hardening_capture_and_mode "$key" "$uid:$gid" 0600 || return
  done <"$passwd_file"
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    hardening_capture_and_mode "$path" root:root 0600 || return
  done < <(find "$(hardening_system_path /etc/ssh)" -maxdepth 1 -type f -name 'ssh_host_*_key' -print 2>/dev/null)
}

hardening_validate_1002() {
  local passwd_file path home shell uid gid user key ssh_dir
  passwd_file="$(hardening_system_path /etc/passwd)"
  while IFS=: read -r user _ uid gid _ home shell; do
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    ssh_dir="$(hardening_system_path "$home/.ssh")"; key="$ssh_dir/authorized_keys"
    [[ ! -f "$key" ]] && continue
    [[ "$(stat -c %a "$ssh_dir")" == 700 ]] || return 1
    [[ "$(stat -c %a "$key")" == 600 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$ssh_dir")" == "$uid" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$key")" == "$uid" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %g "$ssh_dir")" == "$gid" ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %g "$key")" == "$gid" ]] || return 1
  done <"$passwd_file"
  while IFS= read -r path; do
    [[ "$(stat -c %a "$path")" == 600 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  done < <(find "$(hardening_system_path /etc/ssh)" -maxdepth 1 -type f -name 'ssh_host_*_key' -print 2>/dev/null)
}

hardening_action_1003() {
  local root path
  root="$(hardening_system_path /etc)"
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]] && command -v visudo >/dev/null 2>&1; then
    visudo -c >/dev/null 2>&1 || return 1
  fi
  path="$root/sudoers"; hardening_capture_and_mode "$path" root:root 0440 || return
  while IFS= read -r path; do
    hardening_capture_and_mode "$path" root:root 0440 || return
  done < <(find "$root/sudoers.d" -xdev -type f -print 2>/dev/null)
}

hardening_validate_1003() {
  local root path
  root="$(hardening_system_path /etc)"
  for path in "$root/sudoers" "$root"/sudoers.d/*; do
    [[ -f "$path" ]] || continue
    [[ "$(stat -c %a "$path")" == 440 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  done
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]] || ! command -v visudo >/dev/null 2>&1 || visudo -c >/dev/null 2>&1
}

hardening_action_1004() {
  local root path mode
  root="$(hardening_system_path /etc)"
  for path in "$root/crontab" "$root"/cron.d/* "$root"/cron.daily/* "$root"/cron.hourly/* "$root"/cron.weekly/* "$root"/cron.monthly/*; do
    [[ -f "$path" ]] || continue
    mode="$(stat -c %a "$path")"
    # 仅移除组用户和其他用户的写权限，保留发行版原有的读取/执行语义。
    if (( (8#$mode & 8#022) != 0 )); then
      hardening_tx_capture "$path" || return
      chmod go-w -- "$path" || return
    fi
  done
}

hardening_validate_1004() {
  local root path
  root="$(hardening_system_path /etc)"
  path="$root/crontab"
  if [[ -f "$path" ]]; then
    (( (8#$(stat -c %a "$path") & 8#022) == 0 )) || return 1
  fi
  ! find "$root/cron.d" "$root/cron.daily" "$root/cron.hourly" "$root/cron.weekly" "$root/cron.monthly" \
    -xdev -type f -perm /022 -print -quit 2>/dev/null | grep -q .
}

hardening_ssh_managed_path() {
  hardening_system_path /etc/ssh/sshd_config.d/90-vpsga-hardening.conf
}

hardening_ssh_main_config() {
  hardening_system_path /etc/ssh/sshd_config
}

hardening_ssh_preflight() {
  local main include_dir managed mode path
  main="$(hardening_ssh_main_config)"
  include_dir="$(hardening_system_path /etc/ssh/sshd_config.d)"
  managed="$(hardening_ssh_managed_path)"
  [[ -f "$main" && ! -L "$main" ]] || {
    echo "未找到安全可用的 SSH 主配置：$main" >&2
    return 69
  }
  [[ -d "$include_dir" && ! -L "$include_dir" ]] || {
    echo "SSH drop-in 目录不存在或不安全：$include_dir" >&2
    return 69
  }
  for path in "$main" "$include_dir"; do
    mode="$(stat -c %a "$path")" || return 74
    (( (8#$mode & 8#022) == 0 )) || {
      echo "SSH 配置路径可被非 root 用户写入，拒绝修改：$path" >&2
      return 76
    }
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$path")" == 0 ]] || {
      echo "SSH 配置路径不属于 root，拒绝修改：$path" >&2
      return 76
    }
  done
  if [[ -e "$managed" || -L "$managed" ]]; then
    [[ -f "$managed" && ! -L "$managed" ]] || {
      echo "拒绝覆盖非普通文件或符号链接：$managed" >&2
      return 76
    }
    grep -qx '# Managed by VPS Guard Audit. Local edits may be replaced.' "$managed" || {
      echo "目标文件并非由 VPS Guard Audit 管理，拒绝覆盖：$managed" >&2
      return 76
    }
  fi
  # Debian/Ubuntu 的 drop-in 必须由主配置显式 Include。忽略注释和大小写。
  awk '
    /^[[:space:]]*#/ { next }
    tolower($1) == "include" {
      for (i = 2; i <= NF; i++)
        if ($i == "/etc/ssh/sshd_config.d/*.conf") found = 1
    }
    END { exit(found ? 0 : 1) }
  ' "$main" || {
    echo "SSH 主配置没有启用 /etc/ssh/sshd_config.d/*.conf，无法安全使用 drop-in。" >&2
    return 78
  }
}

hardening_sshd_test() {
  local main
  main="$(hardening_ssh_main_config)"
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_SSHD_BIN:-}" ]] || {
      echo "隔离根目录测试必须设置 VPSGA_TEST_SSHD_BIN。" >&2
      return 69
    }
    "$VPSGA_TEST_SSHD_BIN" -t -f "$main"
  else
    command -v sshd >/dev/null 2>&1 || {
      echo "找不到 sshd，无法验证 SSH 配置。" >&2
      return 69
    }
    sshd -t -f "$main"
  fi
}

hardening_sshd_effective_value() {
  local key="$1" main output
  main="$(hardening_ssh_main_config)"
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_SSHD_BIN:-}" ]] || return 69
    output="$("$VPSGA_TEST_SSHD_BIN" -T -f "$main")" || return
  else
    command -v sshd >/dev/null 2>&1 || return 69
    output="$(sshd -T -f "$main")" || return
  fi
  awk -v key="${key,,}" '$1 == key { print $2; found=1; exit } END { if (!found) exit 1 }' <<<"$output"
}

hardening_ssh_reload() {
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    if [[ -n "${VPSGA_TEST_SSH_RELOAD_BIN:-}" ]]; then
      "$VPSGA_TEST_SSH_RELOAD_BIN" "$(hardening_ssh_main_config)"
      return
    fi
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
  elif command -v service >/dev/null 2>&1; then
    service ssh reload 2>/dev/null || service sshd reload
  else
    echo "找不到可用的 SSH 服务重载方式。" >&2
    return 69
  fi
}

hardening_ssh_write_setting() {
  local managed tmp dir line key value
  local first="" second="" third="" fourth="" fifth="" sixth="" seventh=""
  (($# >= 2 && $# % 2 == 0)) || return 64
  managed="$(hardening_ssh_managed_path)"
  dir="${managed%/*}"
  hardening_ssh_preflight || return
  hardening_tx_capture "$managed" || return

  if [[ -f "$managed" ]]; then
    while IFS= read -r line; do
      case "${line%%[[:space:]]*}" in
        PermitEmptyPasswords) first="$line" ;;
        MaxAuthTries) second="$line" ;;
        X11Forwarding) third="$line" ;;
        PermitRootLogin) fourth="$line" ;;
        PasswordAuthentication) fifth="$line" ;;
        KbdInteractiveAuthentication) sixth="$line" ;;
        AllowTcpForwarding) seventh="$line" ;;
      esac
    done <"$managed"
  fi
  while (($#)); do
    key="$1"; value="$2"; shift 2
    case "$key" in
      PermitEmptyPasswords) first="$key $value" ;;
      MaxAuthTries) second="$key $value" ;;
      X11Forwarding) third="$key $value" ;;
      PermitRootLogin) fourth="$key $value" ;;
      PasswordAuthentication) fifth="$key $value" ;;
      KbdInteractiveAuthentication) sixth="$key $value" ;;
      AllowTcpForwarding) seventh="$key $value" ;;
      *) return 64 ;;
    esac
  done

  tmp="$(mktemp "$dir/.90-vpsga-hardening.conf.XXXXXX")" || return 73
  {
    echo '# Managed by VPS Guard Audit. Local edits may be replaced.'
    echo '# Changes are backed up under /var/lib/vps-guard-audit/hardening.'
    [[ -z "$first" ]] || echo "$first"
    [[ -z "$second" ]] || echo "$second"
    [[ -z "$third" ]] || echo "$third"
    [[ -z "$fourth" ]] || echo "$fourth"
    [[ -z "$fifth" ]] || echo "$fifth"
    [[ -z "$sixth" ]] || echo "$sixth"
    [[ -z "$seventh" ]] || echo "$seventh"
  } >"$tmp" || { rm -f -- "$tmp"; return 73; }
  chmod 0600 -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown root:root -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  fi
  mv -f -- "$tmp" "$managed" || { rm -f -- "$tmp"; return 73; }
  hardening_sshd_test || return
  hardening_ssh_reload
}

hardening_action_1005() { hardening_ssh_write_setting PermitEmptyPasswords no; }
hardening_action_1006() { hardening_ssh_write_setting MaxAuthTries 4; }
hardening_action_1007() { hardening_ssh_write_setting X11Forwarding no; }
hardening_action_2001() { hardening_ssh_write_setting PermitRootLogin no; }
hardening_action_2002() {
  hardening_ssh_write_setting PasswordAuthentication no KbdInteractiveAuthentication no
}
hardening_action_2006() {
  [[ "${VPSGA_SSH_FORWARD_ACK:-}" == 'NO SSH FORWARDING' ]] || {
    echo "关闭 SSH TCP 转发前必须明确确认没有 SSH 隧道或远程开发依赖。" >&2
    return 65
  }
  hardening_ssh_write_setting AllowTcpForwarding no
}

hardening_ssh_validate_setting() {
  local key="$1" value="$2" managed
  managed="$(hardening_ssh_managed_path)"
  [[ -f "$managed" && ! -L "$managed" ]] || return 1
  [[ "$(stat -c %a "$managed")" == 600 ]] || return 1
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$managed")" == '0:0' ]] || return 1
  [[ "$(awk -v key="$key" '
    $1 == key { count++; result=$2 }
    END { if (count == 1) print result; else exit 1 }
  ' "$managed")" == "$value" ]] || return 1
  hardening_sshd_test || return
  [[ "$(hardening_sshd_effective_value "$key")" == "${value,,}" ]]
}

hardening_validate_1005() { hardening_ssh_validate_setting PermitEmptyPasswords no; }
hardening_validate_1006() { hardening_ssh_validate_setting MaxAuthTries 4; }
hardening_validate_1007() { hardening_ssh_validate_setting X11Forwarding no; }
hardening_validate_2001() { hardening_ssh_validate_setting PermitRootLogin no; }
hardening_validate_2002() {
  hardening_ssh_validate_setting PasswordAuthentication no &&
    hardening_ssh_validate_setting KbdInteractiveAuthentication no
}
hardening_validate_2006() { hardening_ssh_validate_setting AllowTcpForwarding no; }

hardening_ufw_command() {
  if [[ -n "${VPSGA_TEST_UFW_BIN:-}" ]]; then
    bash "$VPSGA_TEST_UFW_BIN" "$@"
  else
    LC_ALL=C command ufw "$@"
  fi
}

hardening_systemctl_command() {
  if [[ -n "${VPSGA_TEST_SYSTEMCTL_BIN:-}" ]]; then
    bash "$VPSGA_TEST_SYSTEMCTL_BIN" "$@"
  else
    command systemctl "$@"
  fi
}

hardening_candidate_units() {
  case "$1" in
    cups) printf '%s\n' cups.service cups.socket cups.path cups-browsed.service ;;
    avahi) printf '%s\n' avahi-daemon.service avahi-daemon.socket ;;
    *) return 64 ;;
  esac
}

hardening_systemd_unit_load_state() {
  hardening_systemctl_command show "$1" --property=LoadState --value 2>/dev/null
}

hardening_systemd_unit_file_state() {
  local state
  state="$(hardening_systemctl_command is-enabled "$1" 2>/dev/null || true)"
  [[ "$state" =~ ^(enabled|enabled-runtime|disabled|static|indirect|generated|transient|masked|masked-runtime|alias)$ ]] || return 69
  printf '%s\n' "$state"
}

hardening_systemd_unit_is_active() {
  local state
  state="$(hardening_systemctl_command is-active "$1" 2>/dev/null || true)"
  grep -Fqx active <<<"$state"
}

hardening_workload_plan() {
  local context value unit load active enabled group output line
  echo "业务用途检查（只读）"
  if context="$(connection_guard_current_context 2>/dev/null)"; then
    printf '  当前 SSH：%s:%s → %s:%s\n' \
      "$(cut -f1 <<<"$context")" "$(cut -f2 <<<"$context")" \
      "$(cut -f3 <<<"$context")" "$(cut -f4 <<<"$context")"
  else
    echo "  当前不是可验证的 SSH 会话；连接敏感动作仍会拒绝执行。"
  fi

  value="$(hardening_sshd_effective_value AllowTcpForwarding 2>/dev/null || true)"
  echo "  SSH TCP 转发：${value:-无法读取}"
  echo "  请人工确认：ssh -L/-R/-D、VS Code Remote、数据库隧道、跳板机和代理转发。"

  echo "  网络转发状态："
  for unit in net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.all.disable_ipv6; do
    value="$(hardening_sysctl_command -n "$unit" 2>/dev/null || true)"
    printf '    - %s = %s\n' "$unit" "${value:-不可用}"
  done
  if command -v ip >/dev/null 2>&1; then
    output="$(ip -brief link 2>/dev/null | awk '$1 ~ /^(docker|br-|veth|virbr|wg|tun|tap|tailscale|zt|cni|flannel)/ {print}' || true)"
    if [[ -n "$output" ]]; then
      echo "  检测到可能依赖转发的网络接口："
      while IFS= read -r line; do
        printf '    - %s\n' "$line"
      done <<<"$output"
    fi
  fi
  for unit in docker.service containerd.service 'wg-quick@*.service' openvpn.service tailscaled.service; do
    if hardening_systemd_unit_is_active "$unit"; then
      echo "  [运行中] $unit（关闭转发或 IPv6 前必须确认）"
    fi
  done

  echo "  可停用服务候选："
  for group in cups avahi; do
    while IFS= read -r unit; do
      load="$(hardening_systemd_unit_load_state "$unit" 2>/dev/null || true)"
      [[ "$load" == loaded ]] || continue
      if hardening_systemd_unit_is_active "$unit"; then active=active; else active=inactive; fi
      enabled="$(hardening_systemd_unit_file_state "$unit" 2>/dev/null || echo unknown)"
      printf '    - %-28s 运行=%s 启动=%s\n' "$unit" "$active" "$enabled"
    done < <(hardening_candidate_units "$group")
  done
  echo "  这里只列出 CUPS 与 Avahi 候选；不会自动选择，也不会卸载软件包。"
}

hardening_firewall_plan() {
  local context ssh_port listeners listener
  context="$(connection_guard_current_context)" || return
  ssh_port="$(cut -f4 <<<"$context")"
  echo "防火墙端口计划（只读）"
  echo "  当前 SSH 必须保留：$ssh_port/tcp"
  if command -v ss >/dev/null 2>&1; then
    listeners="$(ss -H -lntu 2>/dev/null | awk '
      {
        proto=$1; endpoint=$5
        if (proto !~ /^(tcp|udp)$/) next
        sub(/^.*:/, "", endpoint)
        if (endpoint ~ /^[0-9]+$/) seen[endpoint "/" proto]=1
      }
      END { for (item in seen) print item }
    ' | sort -t/ -k1,1n -k2,2)"
    if [[ -n "$listeners" ]]; then
      echo "  当前监听端口（仅供审核，不会自动全部放行）："
      while IFS= read -r listener; do
        printf '    - %s\n' "$listener"
      done <<<"$listeners"
    else
      echo "  未取得监听端口；请通过业务配置人工确认。"
    fi
  else
    echo "  缺少 ss，无法列出监听端口。"
  fi
  if command -v docker >/dev/null 2>&1; then
    listeners="$(docker ps --format '{{.Ports}}' 2>/dev/null | sed '/^[[:space:]]*$/d' || true)"
    if [[ -n "$listeners" ]]; then
      echo "  Docker 发布端口（请逐项确认）："
      while IFS= read -r listener; do
        printf '    - %s\n' "$listener"
      done <<<"$listeners"
      echo "    警告：Docker 发布端口可能绕过 UFW 的普通入站规则；本动作不会改写 DOCKER-USER 链。"
    fi
  fi
  if command -v ufw >/dev/null 2>&1 || [[ -n "${VPSGA_TEST_UFW_BIN:-}" ]]; then
    echo "  当前 UFW 规则："
    hardening_ufw_command status numbered 2>/dev/null | sed 's/^/    /' || true
  fi
  echo "  注意：127.0.0.1/::1 上的服务不需要公网放行；UDP 必须明确写成 端口/udp。"
}

hardening_install_official_package() {
  local command_name="$1" package="$2"
  command -v "$command_name" >/dev/null 2>&1 && return 0
  command -v apt-get >/dev/null 2>&1 || {
    echo "缺少 $command_name，且当前系统没有 apt-get。" >&2
    return 69
  }
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" || return
  command -v "$command_name" >/dev/null 2>&1
}

hardening_parse_ufw_specs() {
  local raw="$1" required_port="$2" item port proto found=0
  local -A seen=()
  [[ -n "$raw" && "$raw" != *$'\n'* && "$raw" != *$'\t'* ]] || return 64
  for item in $raw; do
    [[ "$item" =~ ^([0-9]{1,5})/(tcp|udp)$ ]] || return 64
    port="${BASH_REMATCH[1]}"; proto="${BASH_REMATCH[2]}"
    ((10#$port >= 1 && 10#$port <= 65535)) || return 64
    [[ -z "${seen[$port/$proto]+x}" ]] || continue
    seen[$port/$proto]=1
    printf '%s/%s\n' "$((10#$port))" "$proto"
    [[ "$proto" == tcp && "$((10#$port))" == "$required_port" ]] && found=1
  done
  ((found == 1)) || {
    echo "放行清单必须包含当前 SSH 端口 ${required_port}/tcp。" >&2
    return 65
  }
}

hardening_ufw_capture_state() {
  local path status
  status="$(hardening_ufw_command status 2>/dev/null | sed -n 's/^Status: //p' | head -n1)"
  [[ "$status" == active || "$status" == inactive ]] || {
    echo "无法可靠识别 UFW 当前状态，拒绝修改。" >&2
    return 69
  }
  printf '%s\n' "$status" >"$HARDENING_TX_DIR/ufw-before"
  chmod 0600 -- "$HARDENING_TX_DIR/ufw-before"
  for path in /etc/default/ufw /etc/ufw/user.rules /etc/ufw/user6.rules /lib/ufw/user.rules /lib/ufw/user6.rules; do
    hardening_tx_capture "$(hardening_system_path "$path")" || return
  done
}

hardening_action_2003() {
  local context ssh_port specs spec
  context="$(connection_guard_current_context)" || return
  ssh_port="$(cut -f4 <<<"$context")"
  specs="$(hardening_parse_ufw_specs "${VPSGA_UFW_ALLOW_SPECS:-}" "$ssh_port")" || return
  hardening_ufw_capture_state || return
  hardening_ufw_command default deny incoming || return
  hardening_ufw_command default allow outgoing || return
  while IFS= read -r spec; do
    hardening_ufw_command allow "$spec" || return
  done <<<"$specs"
  hardening_ufw_command --force enable
}

hardening_validate_2003() {
  local context ssh_port specs spec status
  context="$(connection_guard_current_context)" || return
  ssh_port="$(cut -f4 <<<"$context")"
  specs="$(hardening_parse_ufw_specs "${VPSGA_UFW_ALLOW_SPECS:-}" "$ssh_port")" || return
  status="$(hardening_ufw_command status verbose)" || return
  grep -q '^Status: active' <<<"$status" || return 1
  grep -q 'Default: deny (incoming)' <<<"$status" || return 1
  while IFS= read -r spec; do
    grep -Eq "^${spec//\//\\/}[[:space:]]+ALLOW[[:space:]]+IN" <<<"$status" || return 1
  done <<<"$specs"
}

hardening_parse_ufw_delete_numbers() {
  local raw="$1" item
  local -A seen=()
  [[ -n "$raw" && "$raw" != *$'\n'* && "$raw" != *$'\t'* ]] || return 64
  for item in $raw; do
    [[ "$item" =~ ^[1-9][0-9]*$ ]] || return 64
    ((item <= 9999)) || return 64
    seen[$item]=1
  done
  printf '%s\n' "${!seen[@]}" | sort -rn
}

hardening_action_2004() {
  local numbers number before selected
  numbers="$(hardening_parse_ufw_delete_numbers "${VPSGA_UFW_DELETE_NUMBERS:-}")" || return
  before="$(hardening_ufw_command status numbered)" || return
  grep -q '^Status: active' <<<"$before" || {
    echo "UFW 当前未启用，拒绝清理规则。" >&2
    return 65
  }
  while IFS= read -r number; do
    grep -Eq "^\[[[:space:]]*${number}\]" <<<"$before" || {
      echo "UFW 规则编号不存在：$number" >&2
      return 65
    }
  done <<<"$numbers"
  hardening_ufw_capture_state || return
  selected="$(while IFS= read -r number; do
    sed -n -E "s/^\[[[:space:]]*${number}\][[:space:]]*//p" <<<"$before"
  done <<<"$numbers")"
  [[ -n "$selected" ]] || return 65
  printf '%s\n' "$selected" >"$HARDENING_TX_DIR/ufw-deleted-rules"
  printf '%s\n' "$numbers" >"$HARDENING_TX_DIR/ufw-deleted-numbers"
  chmod 0600 -- "$HARDENING_TX_DIR/ufw-deleted-numbers" "$HARDENING_TX_DIR/ufw-deleted-rules"
  while IFS= read -r number; do
    hardening_ufw_command --force delete "$number" || return
  done <<<"$numbers"
}

hardening_validate_2004() {
  local after rule
  after="$(hardening_ufw_command status numbered)" || return
  grep -q '^Status: active' <<<"$after" || return 1
  while IFS= read -r rule; do
    [[ -n "$rule" ]] || continue
    ! sed -E 's/^\[[[:space:]]*[0-9]+\][[:space:]]*//' <<<"$after" | grep -Fqx -- "$rule" || return 1
  done <"$HARDENING_TX_DIR/ufw-deleted-rules"
}

hardening_fail2ban_path() {
  hardening_system_path /etc/fail2ban/jail.d/vpsga-sshd.local
}

hardening_action_2005() {
  local context ssh_port client_ip marker content enabled active
  context="$(connection_guard_current_context)" || return
  client_ip="$(cut -f1 <<<"$context")"; ssh_port="$(cut -f4 <<<"$context")"
  [[ "$client_ip" =~ ^[0-9A-Fa-f:.]+$ ]] || return 65
  enabled=0; active=0
  if [[ "${VPSGA_FAIL2BAN_PREINSTALL_STATE:-}" != missing ]]; then
    hardening_systemctl_command is-enabled --quiet fail2ban 2>/dev/null && enabled=1
    hardening_systemctl_command is-active --quiet fail2ban 2>/dev/null && active=1
  fi
  printf 'enabled=%s\nactive=%s\n' "$enabled" "$active" >"$HARDENING_TX_DIR/fail2ban-before"
  chmod 0600 -- "$HARDENING_TX_DIR/fail2ban-before"
  unset VPSGA_FAIL2BAN_PREINSTALL_STATE
  hardening_ensure_managed_directory "$(hardening_system_path /etc/fail2ban/jail.d)" || return
  marker='# Managed by VPS Guard Audit. Local edits may be replaced.'
  content="$marker
[sshd]
enabled = true
port = $ssh_port
backend = systemd
maxretry = 5
findtime = 10m
bantime = 10m
ignoreip = 127.0.0.1/8 ::1 $client_ip
"
  hardening_write_managed_file "$(hardening_fail2ban_path)" "$content" "$marker" || return
  if [[ -n "${VPSGA_TEST_FAIL2BAN_BIN:-}" ]]; then
    bash "$VPSGA_TEST_FAIL2BAN_BIN" test || return
  else
    fail2ban-client -t || return
  fi
  hardening_systemctl_command enable --now fail2ban || return
  hardening_systemctl_command restart fail2ban
}

hardening_sensitive_preflight() {
  case "$1" in
    HARD-2003|HARD-2004)
      if [[ -z "${VPSGA_TEST_UFW_BIN:-}" ]]; then
        hardening_install_official_package ufw ufw || return
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
          echo "firewalld 正在运行，拒绝同时使用 UFW。请先选择唯一的防火墙方案。" >&2
          return 65
        fi
      fi
      ;;
    HARD-2005)
      if [[ -z "${VPSGA_TEST_FAIL2BAN_BIN:-}" ]] && ! command -v fail2ban-client >/dev/null 2>&1; then
        VPSGA_FAIL2BAN_PREINSTALL_STATE=missing
        hardening_install_official_package fail2ban-client fail2ban || return
        # Debian/Ubuntu 的软件包安装脚本可能自动启动服务；真正启用必须留在受保护事务内。
        hardening_systemctl_command stop fail2ban || return
        hardening_systemctl_command disable fail2ban || return
      fi
      ;;
  esac
}

hardening_validate_2005() {
  local context ssh_port path status
  context="$(connection_guard_current_context)" || return
  ssh_port="$(cut -f4 <<<"$context")"; path="$(hardening_fail2ban_path)"
  [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
  grep -Eq "^[[:space:]]*port[[:space:]]*=[[:space:]]*${ssh_port}[[:space:]]*$" "$path" || return 1
  hardening_systemctl_command is-active --quiet fail2ban || return 1
  if [[ -n "${VPSGA_TEST_FAIL2BAN_BIN:-}" ]]; then
    status="$(bash "$VPSGA_TEST_FAIL2BAN_BIN" status)" || return
  else
    status="$(fail2ban-client status)" || return
  fi
  grep -q 'Jail list:.*sshd' <<<"$status"
}

hardening_require_safe_directory() {
  local path="$1" mode
  [[ -d "$path" && ! -L "$path" ]] || {
    echo "目标目录不存在或不安全：$path" >&2
    return 69
  }
  mode="$(stat -c %a "$path")" || return 74
  (( (8#$mode & 8#022) == 0 )) || {
    echo "目标目录可被非 root 用户写入，拒绝修改：$path" >&2
    return 76
  }
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c %u "$path")" == 0 ]] || {
    echo "目标目录不属于 root，拒绝修改：$path" >&2
    return 76
  }
}

hardening_write_managed_file() {
  local path="$1" content="$2" marker="$3" dir tmp
  dir="${path%/*}"
  hardening_require_safe_directory "$dir" || return
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -f "$path" && ! -L "$path" ]] || {
      echo "拒绝覆盖非普通文件或符号链接：$path" >&2
      return 76
    }
    grep -Fqx "$marker" "$path" || {
      echo "目标文件并非由 VPS Guard Audit 管理，拒绝覆盖：$path" >&2
      return 76
    }
  fi
  hardening_tx_capture "$path" || return
  tmp="$(mktemp "$dir/.vpsga-managed.XXXXXX")" || return 73
  printf '%s' "$content" >"$tmp" || { rm -f -- "$tmp"; return 73; }
  chmod 0600 -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown root:root -- "$tmp" || { rm -f -- "$tmp"; return 73; }
  fi
  mv -f -- "$tmp" "$path" || { rm -f -- "$tmp"; return 73; }
}

hardening_ensure_managed_directory() {
  local path="$1" parent
  if [[ -e "$path" || -L "$path" ]]; then
    hardening_require_safe_directory "$path"
    return
  fi
  parent="${path%/*}"
  hardening_require_safe_directory "$parent" || return
  hardening_tx_capture "$path" || return
  mkdir -- "$path" || return 73
  chmod 0755 -- "$path" || return 73
  if [[ -z "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    chown root:root -- "$path" || return 73
  fi
}

hardening_apt_config_path() {
  hardening_system_path /etc/apt/apt.conf.d/52-vpsga-auto-upgrades
}

hardening_apt_package_installed() {
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_DPKG_QUERY_BIN:-}" ]] || return 69
    "$VPSGA_TEST_DPKG_QUERY_BIN" unattended-upgrades
  else
    dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'ok installed'
  fi
}

hardening_apt_install_unattended() {
  hardening_apt_package_installed && return 0
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_APT_GET_BIN:-}" ]] || return 69
    "$VPSGA_TEST_APT_GET_BIN" install -y unattended-upgrades
  else
    command -v apt-get >/dev/null 2>&1 || return 69
    DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
  fi
  hardening_apt_package_installed
}

hardening_action_1008() {
  local path content marker='# Managed by VPS Guard Audit. Local edits may be replaced.'
  path="$(hardening_apt_config_path)"
  hardening_require_safe_directory "$(hardening_system_path /etc/apt/apt.conf.d)" || return
  hardening_apt_install_unattended || return
  content="$marker
// The distribution package keeps the allowed security origins in 50unattended-upgrades.
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
"
  hardening_write_managed_file "$path" "$content" "$marker"
}

hardening_validate_1008() {
  local path
  path="$(hardening_apt_config_path)"
  hardening_apt_package_installed || return
  [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  [[ "$(grep -Ec '^[[:space:]]*APT::Periodic::Update-Package-Lists[[:space:]]+\"1\";' "$path")" == 1 ]] || return 1
  [[ "$(grep -Ec '^[[:space:]]*APT::Periodic::Unattended-Upgrade[[:space:]]+\"1\";' "$path")" == 1 ]]
}

hardening_sysctl_path() {
  hardening_system_path /etc/sysctl.d/90-vpsga-hardening.conf
}

hardening_sysctl_command() {
  if [[ -n "${VPSGA_SYSTEM_ROOT:-}" ]]; then
    [[ -n "${VPSGA_TEST_SYSCTL_BIN:-}" ]] || return 69
    "$VPSGA_TEST_SYSCTL_BIN" "$@"
  else
    command sysctl "$@"
  fi
}

hardening_sysctl_pairs() {
  cat <<'EOF'
kernel.randomize_va_space=2
kernel.kptr_restrict=1
kernel.yama.ptrace_scope=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF
}

hardening_sysctl_capture_runtime() {
  local key value snapshot="$HARDENING_TX_DIR/sysctl-before.tsv"
  : >"$snapshot" || return 73
  while IFS='=' read -r key _; do
    if ! value="$(hardening_sysctl_command -n "$key" 2>/dev/null)"; then
      echo "跳过当前内核不存在的参数：$key" >&2
      continue
    fi
    [[ "$value" =~ ^-?[0-9]+$ ]] || {
      echo "内核参数返回了无法安全保存的值，拒绝修改：$key" >&2
      return 76
    }
    printf '%s\t%s\n' "$key" "$value" >>"$snapshot"
  done < <(hardening_sysctl_pairs)
  chmod 0600 -- "$snapshot"
}

hardening_sysctl_apply_file() {
  hardening_sysctl_command -p "$(hardening_sysctl_path)" >/dev/null
}

hardening_sysctl_restore_runtime() {
  local key value snapshot="$HARDENING_TX_DIR/sysctl-before.tsv" failed=0
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 74
  while IFS=$'\t' read -r key value; do
    [[ "$key" =~ ^[a-z0-9_.]+$ && "$value" =~ ^-?[0-9]+$ ]] || return 76
    hardening_sysctl_command -w "$key=$value" >/dev/null || failed=1
  done <"$snapshot"
  [[ "$failed" -eq 0 ]]
}

hardening_action_1009() {
  local path content marker='# Managed by VPS Guard Audit. Local edits may be replaced.' key expected
  path="$(hardening_sysctl_path)"
  hardening_sysctl_capture_runtime || return
  content="$marker
# Does not change IP forwarding or disable IPv6.
"
  while IFS='=' read -r key expected; do
    hardening_sysctl_command -n "$key" >/dev/null 2>&1 || continue
    content+="$key = $expected"$'\n'
  done < <(hardening_sysctl_pairs)
  hardening_write_managed_file "$path" "$content" "$marker" || return
  hardening_sysctl_apply_file
}

hardening_validate_1009() {
  local path key expected actual
  path="$(hardening_sysctl_path)"
  [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
  [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  while IFS='=' read -r key expected; do
    actual="$(hardening_sysctl_command -n "$key" 2>/dev/null)" || continue
    [[ "$(grep -Ec "^[[:space:]]*${key//./\\.}[[:space:]]*=[[:space:]]*${expected}[[:space:]]*$" "$path")" == 1 ]] || return 1
    [[ "$actual" == "$expected" ]] || return 1
  done < <(hardening_sysctl_pairs)
}

hardening_network_policy_path() {
  hardening_system_path /etc/sysctl.d/91-vpsga-network-policy.conf
}

hardening_network_policy_pairs() {
  local policy="$1" path line key value
  local -A values=() counts=()
  path="$(hardening_network_policy_path)"
  case "$policy" in
    ipv4-forwarding-off|ipv6-forwarding-off|ipv6-off) ;;
    *) return 64 ;;
  esac
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -f "$path" && ! -L "$path" ]] || return 76
    grep -Fqx '# Managed by VPS Guard Audit. Local edits may be replaced.' "$path" || return 76
    while IFS= read -r line; do
      [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]] && continue
      [[ "$line" =~ ^[[:space:]]*([a-z0-9_.]+)[[:space:]]*=[[:space:]]*([01])[[:space:]]*$ ]] || return 76
      key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
      case "$key" in
        net.ipv4.ip_forward|net.ipv6.conf.all.forwarding|net.ipv6.conf.all.disable_ipv6|net.ipv6.conf.default.disable_ipv6) ;;
        *) return 76 ;;
      esac
      counts[$key]=$((${counts[$key]:-0} + 1))
      ((counts[$key] == 1)) || return 76
      values[$key]="$value"
    done <"$path"
  fi
  case "$policy" in
    ipv4-forwarding-off) values[net.ipv4.ip_forward]=0 ;;
    ipv6-forwarding-off) values[net.ipv6.conf.all.forwarding]=0 ;;
    ipv6-off)
      values[net.ipv6.conf.all.disable_ipv6]=1
      values[net.ipv6.conf.default.disable_ipv6]=1
      ;;
  esac
  for key in net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
    net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6; do
    [[ -n "${values[$key]+x}" ]] && printf '%s=%s\n' "$key" "${values[$key]}"
  done
  return 0
}

hardening_network_snapshot_runtime() {
  local pairs="$1" output="$2" key _expected value
  : >"$output" || return 73
  while IFS='=' read -r key _expected; do
    [[ -n "$key" ]] || continue
    value="$(hardening_sysctl_command -n "$key" 2>/dev/null)" || {
      echo "当前内核不支持所选网络参数：$key" >&2
      return 69
    }
    [[ "$value" =~ ^[01]$ ]] || return 76
    printf '%s\t%s\n' "$key" "$value" >>"$output"
  done <<<"$pairs"
  chmod 0600 -- "$output"
}

hardening_network_runtime_matches() {
  local snapshot="$1" key expected actual
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 74
  while IFS=$'\t' read -r key expected; do
    [[ "$key" =~ ^[a-z0-9_.]+$ && "$expected" =~ ^[01]$ ]] || return 76
    actual="$(hardening_sysctl_command -n "$key" 2>/dev/null)" || return
    [[ "$actual" == "$expected" ]] || return 1
  done <"$snapshot"
}

hardening_network_restore_runtime() {
  local snapshot="$HARDENING_TX_DIR/network-before.tsv" key value failed=0
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 0
  while IFS=$'\t' read -r key value; do
    [[ "$key" =~ ^[a-z0-9_.]+$ && "$value" =~ ^[01]$ ]] || return 76
    hardening_sysctl_command -w "$key=$value" >/dev/null || failed=1
  done <"$snapshot"
  [[ "$failed" -eq 0 ]]
}

hardening_action_2007() {
  local policy="${VPSGA_NETWORK_POLICY:-}" context client_ip server_ip pairs content path marker
  marker='# Managed by VPS Guard Audit. Local edits may be replaced.'
  [[ "${VPSGA_NETWORK_USAGE_ACK:-}" == 'NO ROUTING REQUIRED' ]] || {
    echo "必须明确确认 Docker、VPN、代理和软路由不依赖所选网络能力。" >&2
    return 65
  }
  if [[ "$policy" == ipv6-off ]]; then
    context="$(connection_guard_current_context)" || return
    client_ip="$(cut -f1 <<<"$context")"; server_ip="$(cut -f3 <<<"$context")"
    if [[ "$client_ip" == *:* || "$server_ip" == *:* ]]; then
      echo "当前 SSH 会话使用 IPv6，拒绝在此连接中关闭 IPv6。" >&2
      return 65
    fi
  fi
  pairs="$(hardening_network_policy_pairs "$policy")" || return
  path="$(hardening_network_policy_path)"
  hardening_network_snapshot_runtime "$pairs" "$HARDENING_TX_DIR/network-before.tsv" || return
  printf '%s\n' "$policy" >"$HARDENING_TX_DIR/network-policy"
  chmod 0600 -- "$HARDENING_TX_DIR/network-policy"
  content="$marker
# Each setting was selected explicitly after a workload review.
"
  while IFS='=' read -r key value; do
    [[ -n "$key" ]] && content+="$key = $value"$'\n'
  done <<<"$pairs"
  hardening_write_managed_file "$path" "$content" "$marker" || return
  hardening_sysctl_command -p "$path" >/dev/null || return
  hardening_network_snapshot_runtime "$pairs" "$HARDENING_TX_DIR/network-after.tsv"
}

hardening_validate_2007() {
  local policy pairs path key expected actual
  policy="$(cat "$HARDENING_TX_DIR/network-policy" 2>/dev/null)" || return
  pairs="$(hardening_network_policy_pairs "$policy")" || return
  path="$(hardening_network_policy_path)"
  [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
  while IFS='=' read -r key expected; do
    [[ "$(grep -Ec "^[[:space:]]*${key//./\\.}[[:space:]]*=[[:space:]]*${expected}[[:space:]]*$" "$path")" == 1 ]] || return 1
    actual="$(hardening_sysctl_command -n "$key" 2>/dev/null)" || return
    [[ "$actual" == "$expected" ]] || return 1
  done <<<"$pairs"
  hardening_network_runtime_matches "$HARDENING_TX_DIR/network-after.tsv"
}

hardening_service_group_valid() {
  [[ "$1" == cups || "$1" == avahi ]]
}

hardening_service_group_available() {
  local unit
  hardening_service_group_valid "$1" || return 64
  while IFS= read -r unit; do
    [[ "$(hardening_systemd_unit_load_state "$unit" 2>/dev/null || true)" == loaded ]] && return 0
  done < <(hardening_candidate_units "$1")
  return 1
}

hardening_service_snapshot() {
  local group="$1" output="$2" unit load active enabled count=0
  hardening_service_group_valid "$group" || return 64
  : >"$output" || return 73
  while IFS= read -r unit; do
    load="$(hardening_systemd_unit_load_state "$unit" 2>/dev/null || true)"
    [[ "$load" == loaded ]] || continue
    if hardening_systemd_unit_is_active "$unit"; then active=1; else active=0; fi
    enabled="$(hardening_systemd_unit_file_state "$unit")" || return
    printf '%s\t%s\t%s\n' "$unit" "$active" "$enabled" >>"$output"
    count=$((count + 1))
  done < <(hardening_candidate_units "$group")
  ((count > 0)) || {
    echo "没有找到可管理的 $group systemd 单元。" >&2
    return 69
  }
  chmod 0600 -- "$output"
}

hardening_service_state_matches() {
  local snapshot="$1" unit expected_active expected_enabled active enabled
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 74
  while IFS=$'\t' read -r unit expected_active expected_enabled; do
    [[ "$unit" =~ ^[a-zA-Z0-9_.@-]+\.(service|socket|path)$ && "$expected_active" =~ ^[01]$ ]] || return 76
    if hardening_systemd_unit_is_active "$unit"; then active=1; else active=0; fi
    enabled="$(hardening_systemd_unit_file_state "$unit")" || return
    [[ "$active" == "$expected_active" && "$enabled" == "$expected_enabled" ]] || return 1
  done <"$snapshot"
}

hardening_action_2008() {
  local group="${VPSGA_SERVICE_GROUP:-}" before="$HARDENING_TX_DIR/service-before.tsv"
  local after="$HARDENING_TX_DIR/service-after.tsv" unit _active enabled
  local -a units=()
  [[ "${VPSGA_SERVICE_USAGE_ACK:-}" == 'SERVICE NOT NEEDED' ]] || {
    echo "必须明确确认所选服务没有业务用途。" >&2
    return 65
  }
  hardening_service_group_valid "$group" || return 64
  hardening_service_snapshot "$group" "$before" || return
  printf '%s\n' "$group" >"$HARDENING_TX_DIR/service-group"
  chmod 0600 -- "$HARDENING_TX_DIR/service-group"
  while IFS=$'\t' read -r unit _active enabled; do
    units+=("$unit")
    case "$enabled" in
      enabled) hardening_systemctl_command disable "$unit" || return ;;
      enabled-runtime) hardening_systemctl_command disable --runtime "$unit" || return ;;
    esac
  done <"$before"
  for ((unit=${#units[@]}-1; unit>=0; unit--)); do
    hardening_systemctl_command stop "${units[$unit]}" || return
  done
  hardening_service_snapshot "$group" "$after"
}

hardening_validate_2008() {
  local group unit active enabled
  group="$(cat "$HARDENING_TX_DIR/service-group" 2>/dev/null)" || return
  hardening_service_group_valid "$group" || return 64
  hardening_service_state_matches "$HARDENING_TX_DIR/service-after.tsv" || return
  while IFS=$'\t' read -r unit active enabled; do
    [[ "$active" == 0 ]] || return 1
    [[ "$enabled" != enabled && "$enabled" != enabled-runtime ]] || return 1
  done <"$HARDENING_TX_DIR/service-after.tsv"
}

hardening_service_restore_state() {
  local snapshot="$HARDENING_TX_DIR/service-before.tsv" unit active enabled failed=0
  [[ -f "$snapshot" && ! -L "$snapshot" ]] || return 0
  while IFS=$'\t' read -r unit _active enabled; do
    case "$enabled" in
      enabled) hardening_systemctl_command enable "$unit" || failed=1 ;;
      enabled-runtime) hardening_systemctl_command enable --runtime "$unit" || failed=1 ;;
      disabled) hardening_systemctl_command disable "$unit" || failed=1 ;;
    esac
  done <"$snapshot"
  while IFS=$'\t' read -r unit active _enabled; do
    if [[ "$active" == 1 ]]; then
      hardening_systemctl_command start "$unit" || failed=1
    fi
  done <"$snapshot"
  [[ "$failed" -eq 0 ]]
}

hardening_before_rollback() {
  case "$1" in
    HARD-2007)
      hardening_network_runtime_matches "$HARDENING_TX_DIR/network-after.tsv" || {
        echo "网络运行时状态已在事务后变化，拒绝覆盖。" >&2
        return 75
      }
      ;;
    HARD-2008)
      hardening_service_state_matches "$HARDENING_TX_DIR/service-after.tsv" || {
        echo "服务状态已在事务后变化，拒绝覆盖。" >&2
        return 75
      }
      ;;
  esac
}

hardening_core_limits_path() {
  hardening_system_path /etc/security/limits.d/90-vpsga-hardening.conf
}

hardening_coredump_path() {
  hardening_system_path /etc/systemd/coredump.conf.d/90-vpsga.conf
}

hardening_action_1010() {
  local marker='# Managed by VPS Guard Audit. Local edits may be replaced.' limits coredump
  limits="$marker
* hard core 0
"
  coredump="$marker
[Coredump]
Storage=none
ProcessSizeMax=0
"
  hardening_ensure_managed_directory "$(hardening_system_path /etc/systemd/coredump.conf.d)" || return
  hardening_write_managed_file "$(hardening_core_limits_path)" "$limits" "$marker" || return
  hardening_write_managed_file "$(hardening_coredump_path)" "$coredump" "$marker"
}

hardening_validate_1010() {
  local limits coredump path
  limits="$(hardening_core_limits_path)"; coredump="$(hardening_coredump_path)"
  for path in "$limits" "$coredump"; do
    [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 600 ]] || return 1
    [[ -n "${VPSGA_SYSTEM_ROOT:-}" || "$(stat -c '%u:%g' "$path")" == '0:0' ]] || return 1
  done
  [[ "$(grep -Ec '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0([[:space:]]|$)' "$limits")" == 1 ]] || return 1
  [[ "$(grep -Eic '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none[[:space:]]*$' "$coredump")" == 1 ]] || return 1
  [[ "$(grep -Eic '^[[:space:]]*ProcessSizeMax[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$coredump")" == 1 ]]
}

hardening_after_rollback() {
  case "$1" in
    HARD-1005|HARD-1006|HARD-1007|HARD-2001|HARD-2002|HARD-2006)
      hardening_sshd_test && hardening_ssh_reload
      ;;
    HARD-2003|HARD-2004)
      [[ -f "$HARDENING_TX_DIR/ufw-before" && ! -L "$HARDENING_TX_DIR/ufw-before" ]] || return 0
      if [[ "$(cat "$HARDENING_TX_DIR/ufw-before")" == inactive ]]; then
        hardening_ufw_command --force disable
      else
        hardening_ufw_command reload
      fi
      ;;
    HARD-2005)
      [[ -f "$HARDENING_TX_DIR/fail2ban-before" && ! -L "$HARDENING_TX_DIR/fail2ban-before" ]] || return 0
      if grep -q '^active=1$' "$HARDENING_TX_DIR/fail2ban-before" 2>/dev/null; then
        hardening_systemctl_command restart fail2ban
      else
        hardening_systemctl_command stop fail2ban
      fi
      if grep -q '^enabled=1$' "$HARDENING_TX_DIR/fail2ban-before" 2>/dev/null; then
        hardening_systemctl_command enable fail2ban
      else
        hardening_systemctl_command disable fail2ban
      fi
      ;;
    HARD-1009)
      hardening_sysctl_restore_runtime
      ;;
    HARD-2007)
      hardening_network_restore_runtime
      ;;
    HARD-2008)
      hardening_service_restore_state
      ;;
    *) return 0 ;;
  esac
}

hardening_run_after_rollback() {
  case "$1" in
    HARD-2007) [[ -f "$HARDENING_TX_DIR/network-before.tsv" ]] || return 0 ;;
    HARD-2008) [[ -f "$HARDENING_TX_DIR/service-before.tsv" ]] || return 0 ;;
    *) [[ -s "$HARDENING_TX_MANIFEST" ]] || return 0 ;;
  esac
  hardening_after_rollback "$1"
}

run_hardening_action_body() {
  case "$1" in
    HARD-1001) hardening_action_1001 ;;
    HARD-1002) hardening_action_1002 ;;
    HARD-1003) hardening_action_1003 ;;
    HARD-1004) hardening_action_1004 ;;
    HARD-1005) hardening_action_1005 ;;
    HARD-1006) hardening_action_1006 ;;
    HARD-1007) hardening_action_1007 ;;
    HARD-1008) hardening_action_1008 ;;
    HARD-1009) hardening_action_1009 ;;
    HARD-1010) hardening_action_1010 ;;
    HARD-2001) hardening_action_2001 ;;
    HARD-2002) hardening_action_2002 ;;
    HARD-2003) hardening_action_2003 ;;
    HARD-2004) hardening_action_2004 ;;
    HARD-2005) hardening_action_2005 ;;
    HARD-2006) hardening_action_2006 ;;
    HARD-2007) hardening_action_2007 ;;
    HARD-2008) hardening_action_2008 ;;
    *) echo "该项目尚未开放自动执行：$1" >&2; return 78 ;;
  esac
}

validate_hardening_action() {
  case "$1" in
    HARD-1001) hardening_validate_1001 ;;
    HARD-1002) hardening_validate_1002 ;;
    HARD-1003) hardening_validate_1003 ;;
    HARD-1004) hardening_validate_1004 ;;
    HARD-1005) hardening_validate_1005 ;;
    HARD-1006) hardening_validate_1006 ;;
    HARD-1007) hardening_validate_1007 ;;
    HARD-1008) hardening_validate_1008 ;;
    HARD-1009) hardening_validate_1009 ;;
    HARD-1010) hardening_validate_1010 ;;
    HARD-2001) hardening_validate_2001 ;;
    HARD-2002) hardening_validate_2002 ;;
    HARD-2003) hardening_validate_2003 ;;
    HARD-2004) hardening_validate_2004 ;;
    HARD-2005) hardening_validate_2005 ;;
    HARD-2006) hardening_validate_2006 ;;
    HARD-2007) hardening_validate_2007 ;;
    HARD-2008) hardening_validate_2008 ;;
    *) return 78 ;;
  esac
}

execute_hardening_action() {
  local action="$1" rc=0 tx_id
  [[ "$action" =~ ^HARD-1[0-9]{3}$ ]] || {
    echo "连接敏感动作必须使用防失联执行流程：$action" >&2
    return 78
  }
  hardening_tx_begin "$action" || return
  tx_id="$HARDENING_TX_ID"
  if run_hardening_action_body "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "动作执行失败" || rc=74
    hardening_run_after_rollback "$action" || rc=74
    echo "[$action] 执行失败，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if validate_hardening_action "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "修改后验证失败" || rc=74
    hardening_run_after_rollback "$action" || rc=74
    echo "[$action] 验证失败，已自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if hardening_tx_commit; then
    :
  else
    rc=$?
    hardening_tx_rollback "事务提交失败" || rc=74
    hardening_run_after_rollback "$action" || rc=74
    echo "[$action] 无法提交事务，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  echo "[$action] 已完成并通过验证。事务：$tx_id"
  hardening_tx_close
}

stage_sensitive_hardening_action() {
  local action="$1" token="$2" rc=0 tx_id
  [[ "$action" =~ ^HARD-200[1-8]$ ]] || return 78
  # 软件包安装不改变连接策略，并可能耗时较长；必须在5分钟网络回滚计时器启动前完成。
  hardening_sensitive_preflight "$action" || return
  hardening_tx_begin "$action" || return
  tx_id="$HARDENING_TX_ID"

  # Timer is armed before SSH is changed. It only becomes eligible to restore
  # after the transaction reaches pending_confirmation.
  if connection_guard_arm_rollback "$tx_id" 300; then
    :
  else
    rc=$?
    hardening_tx_rollback "无法建立延时自动回滚" >/dev/null 2>&1 || true
    hardening_tx_close
    return "$rc"
  fi
  if run_hardening_action_body "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "连接敏感动作执行失败" || rc=74
    hardening_run_after_rollback "$action" || rc=74
    connection_guard_cancel_rollback "$tx_id" >/dev/null 2>&1 || true
    echo "[$action] 执行失败，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if validate_hardening_action "$action"; then
    :
  else
    rc=$?
    hardening_tx_rollback "连接敏感修改验证失败" || rc=74
    hardening_run_after_rollback "$action" || rc=74
    connection_guard_cancel_rollback "$tx_id" >/dev/null 2>&1 || true
    echo "[$action] 验证失败，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
  if hardening_tx_mark_pending_confirmation && connection_guard_bind_transaction "$token" "$tx_id"; then
    :
  else
    rc=$?
    hardening_tx_rollback "无法绑定第二终端确认" || rc=74
    hardening_run_after_rollback "$action" || rc=74
    connection_guard_cancel_rollback "$tx_id" >/dev/null 2>&1 || true
    echo "[$action] 无法进入第二终端确认，已尝试自动回滚。事务：$tx_id" >&2
    hardening_tx_close
    return "$rc"
  fi
}
