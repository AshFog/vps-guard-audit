#!/usr/bin/env bash
# VPS Guard Audit
# Interactive bilingual, read-only security audit for new VPS users.
# Supported: Ubuntu 26.04/24.04/22.04 LTS and Debian 13/12/11.
# Version: 4.0.0

set -uo pipefail
IFS=$'\n\t'

VERSION="4.0.0"
LANGUAGE=""
OUTPUT_DIR="${PWD}"
FORMAT="both"
QUIET=0
LOGIN_LINES=30
CONFIG_FILE=""
CHECK_UPDATES=1
CHECK_ROOTKITS=0

PASS=0
WARN=0
FAIL=0
INFO=0
SKIP=0

declare -a RESULTS=()
declare -a WARNINGS=()
declare -a FAILURES=()
declare -a RECOMMENDATIONS=()

usage() {
  cat <<'EOF'
Usage:
  sudo ./vps-guard-audit.sh

Options:
  --lang zh|en
  --output-dir DIR
  --format text|json|both
  --config FILE
  --login-lines N
  --no-update-check
  --rootkit-check
  --quiet
  -h, --help
  -v, --version
EOF
}

while (($#)); do
  case "$1" in
    --lang) LANGUAGE="${2:?missing language}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?missing directory}"; shift 2 ;;
    --format) FORMAT="${2:?missing format}"; shift 2 ;;
    --config) CONFIG_FILE="${2:?missing config file}"; shift 2 ;;
    --login-lines) LOGIN_LINES="${2:?missing number}"; shift 2 ;;
    --no-update-check) CHECK_UPDATES=0; shift ;;
    --rootkit-check) CHECK_ROOTKITS=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "$VERSION"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$FORMAT" in text|json|both) ;; *) echo "Invalid format: $FORMAT" >&2; exit 64 ;; esac
[[ "$LOGIN_LINES" =~ ^[0-9]+$ ]] || { echo "--login-lines must be an integer" >&2; exit 64; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "请使用 root 权限运行 / Run as root:"
  echo "sudo ./vps-guard-audit.sh"
  exit 77
fi

choose_language() {
  clear 2>/dev/null || true
  cat <<'EOF'
============================================================
             VPS Guard Audit / VPS 安全卫士
============================================================

Please select a language / 请选择语言：

  1) 中文
  2) English

EOF
  while true; do
    printf "请输入选项 / Enter choice [1-2]: "
    read -r choice
    case "$choice" in
      1|zh|ZH|cn|CN|中文) LANGUAGE="zh"; break ;;
      2|en|EN|English|english) LANGUAGE="en"; break ;;
      *) echo "无效选项，请输入 1 或 2。 / Invalid choice. Enter 1 or 2." ;;
    esac
  done
}

[[ -z "$LANGUAGE" ]] && choose_language
case "$LANGUAGE" in zh|en) ;; *) echo "Invalid language: $LANGUAGE" >&2; exit 64 ;; esac

declare -A ZH EN
ZH[title]="VPS 安全审计报告"
EN[title]="VPS Security Audit Report"
ZH[readonly]="只读模式：不会修改防火墙、SSH、用户、软件包或任何系统配置"
EN[readonly]="Read-only mode: firewall, SSH, users, packages and system settings will not be changed"
ZH[start]="即将开始全面安全检测"
EN[start]="The full security audit is about to begin"
ZH[press]="按 Enter 键开始检测..."
EN[press]="Press Enter to start..."
ZH[system]="1. 操作系统支持状态与基础防护"
EN[system]="1. OS support status and baseline protection"
ZH[ports]="2. 公网监听端口与网络暴露"
EN[ports]="2. Public listening ports and network exposure"
ZH[firewall]="3. 防火墙与默认入站策略"
EN[firewall]="3. Firewall and default incoming policy"
ZH[ssh]="4. SSH 登录安全"
EN[ssh]="4. SSH login security"
ZH[f2b]="5. 暴力破解防护"
EN[f2b]="5. Brute-force protection"
ZH[accounts]="6. 用户、sudo、密码与 SSH 密钥"
EN[accounts]="6. Accounts, sudo, passwords and SSH keys"
ZH[logins]="7. 登录记录与可疑来源"
EN[logins]="7. Login history and suspicious sources"
ZH[persistence]="8. 开机服务、Cron 与持久化项目"
EN[persistence]="8. Enabled services, cron and persistence"
ZH[packages]="9. 软件包、漏洞修复与自动更新"
EN[packages]="9. Packages, security fixes and automatic updates"
ZH[sysctl]="10. 内核与网络安全参数"
EN[sysctl]="10. Kernel and network hardening"
ZH[files]="11. 敏感文件权限与全局可写文件"
EN[files]="11. Sensitive permissions and world-writable files"
ZH[docker]="12. Docker 与容器风险"
EN[docker]="12. Docker and container risks"
ZH[malware]="13. 可疑进程、临时目录与下载执行痕迹"
EN[malware]="13. Suspicious processes, temporary files and download-execute traces"
ZH[proxy]="14. 代理、VPN 与高风险辅助脚本"
EN[proxy]="14. Proxy, VPN and risky helper scripts"
ZH[rootkit]="15. Rootkit 扫描器状态"
EN[rootkit]="15. Rootkit scanner status"
ZH[summary]="16. 最终风险报告与修复建议"
EN[summary]="16. Final risk report and recommendations"
ZH[reports]="报告保存位置"
EN[reports]="Report location"
ZH[done]="检测完成"
EN[done]="Audit completed"
ZH[low]="低风险：未发现明显高危问题"
EN[low]="LOW: no obvious high-risk findings"
ZH[medium]="中等风险：存在需要人工确认或加固的项目"
EN[medium]="MEDIUM: warnings require review or hardening"
ZH[high]="高风险：存在需要尽快处理的问题"
EN[high]="HIGH: remediation is required"

t() {
  local key="$1"
  [[ "$LANGUAGE" == "zh" ]] && printf '%s' "${ZH[$key]}" || printf '%s' "${EN[$key]}"
}

if [[ -t 0 ]]; then
  echo
  echo "$(t readonly)"
  echo "$(t start)"
  printf "%s" "$(t press)"
  read -r _
fi

mkdir -p "$OUTPUT_DIR"
HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d-%H%M%S)"
TEXT_REPORT="${OUTPUT_DIR}/vps-guard-audit-${HOST}-${STAMP}-${LANGUAGE}.txt"
JSON_REPORT="${OUTPUT_DIR}/vps-guard-audit-${HOST}-${STAMP}-${LANGUAGE}.json"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Generic defaults. Optional config can extend or override these.
TRUSTED_LOGIN_IPS=""
EXPECTED_UID0_USERS="root"
CUSTOM_ALLOWED_TCP_PORTS=""
CUSTOM_ALLOWED_UDP_PORTS=""

if [[ -n "$CONFIG_FILE" ]]; then
  [[ -r "$CONFIG_FILE" ]] || { echo "Cannot read config: $CONFIG_FILE" >&2; exit 66; }
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

json_escape() {
  local s=${1-}
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

record() {
  local level="$1" id="$2" zh_title="$3" en_title="$4" detail="${5-}" zh_rec="${6-}" en_rec="${7-}"
  local title rec
  [[ "$LANGUAGE" == "zh" ]] && { title="$zh_title"; rec="$zh_rec"; } || { title="$en_title"; rec="$en_rec"; }
  case "$level" in
    PASS) PASS=$((PASS+1)) ;;
    WARN) WARN=$((WARN+1)); WARNINGS+=("$title${detail:+ — $detail}") ;;
    FAIL) FAIL=$((FAIL+1)); FAILURES+=("$title${detail:+ — $detail}") ;;
    INFO) INFO=$((INFO+1)) ;;
    SKIP) SKIP=$((SKIP+1)) ;;
  esac
  [[ -n "$rec" ]] && RECOMMENDATIONS+=("$rec")
  printf '[%s] %s' "$level" "$title"
  [[ -n "$detail" ]] && printf ' — %s' "$detail"
  printf '\n'
  RESULTS+=("{\"id\":\"$(json_escape "$id")\",\"level\":\"$level\",\"title\":\"$(json_escape "$title")\",\"detail\":\"$(json_escape "$detail")\",\"recommendation\":\"$(json_escape "$rec")\"}")
}

section() { printf '\n==============================================================================\n%s\n==============================================================================\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
safe() { "$@" 2>&1 || true; }
contains_word() { [[ " $1 " == *" $2 "* ]]; }

supported_os_check() {
  OS_ID="unknown"; OS_VERSION="unknown"; OS_CODENAME=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-}"
  fi

  case "${OS_ID}:${OS_VERSION}" in
    ubuntu:26.04|ubuntu:24.04|ubuntu:22.04)
      record PASS os.supported "当前 Ubuntu 版本在项目支持范围内" "Current Ubuntu version is supported" "${OS_ID} ${OS_VERSION} ${OS_CODENAME}" ;;
    debian:13|debian:12|debian:11)
      record PASS os.supported "当前 Debian 版本在项目支持范围内" "Current Debian version is supported" "${OS_ID} ${OS_VERSION} ${OS_CODENAME}" ;;
    ubuntu:*|debian:*)
      record WARN os.unsupported_version "当前系统版本不在已验证的六个版本中" "Current version is outside the six validated releases" "${OS_ID} ${OS_VERSION}" \
        "建议使用 Ubuntu 26.04/24.04/22.04 LTS 或 Debian 13/12/11。" \
        "Use Ubuntu 26.04/24.04/22.04 LTS or Debian 13/12/11." ;;
    *)
      record FAIL os.unsupported_family "当前系统不是受支持的 Ubuntu 或 Debian" "Unsupported operating-system family" "${OS_ID} ${OS_VERSION}" \
        "请不要在未测试的系统上依赖本报告。" \
        "Do not rely on this report on an untested OS." ;;
  esac
}

run_audit() {
  echo "$(t title)"
  echo "Version: $VERSION"
  echo "Host: $HOST"
  echo "Time: $(date -Is)"
  echo "$(t readonly)"

  section "$(t system)"
  safe hostnamectl
  safe uname -a
  safe uptime
  [[ -r /etc/os-release ]] && cat /etc/os-release
  supported_os_check
  [[ "$(cat /proc/1/comm 2>/dev/null)" == systemd ]] \
    && record PASS platform.systemd "systemd 正常作为 PID 1 运行" "systemd is running as PID 1" \
    || record WARN platform.systemd "systemd 不是 PID 1，部分检查可能不完整" "systemd is not PID 1; some checks may be incomplete"
  if [[ -d /sys/module/apparmor ]]; then
    [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == Y ]] \
      && record PASS kernel.apparmor "AppArmor 已启用" "AppArmor is enabled" \
      || record WARN kernel.apparmor "AppArmor 模块存在但未启用" "AppArmor module exists but is not enabled" "" \
        "启用 AppArmor 并确认配置文件处于 enforce 模式。" "Enable AppArmor and enforce relevant profiles."
  else
    record WARN kernel.apparmor "未检测到 AppArmor" "AppArmor is unavailable"
  fi
  if have aa-status; then safe aa-status; fi

  section "$(t ports)"
  SOCKETS="$(ss -H -lntup 2>/dev/null || true)"
  echo "$SOCKETS"
  public_count=0
  while read -r proto state recvq sendq local peer rest; do
    [[ -z "${proto:-}" ]] && continue
    port="${local##*:}"; port="${port//]/}"
    addr="${local%:*}"
    if [[ "$addr" == "0.0.0.0" || "$addr" == "*" || "$addr" == "[::]" || "$addr" == "::" ]]; then
      public_count=$((public_count+1))
      known=""
      case "${proto}/${port}" in
        tcp/22|tcp/80|tcp/443|udp/443) known=1 ;;
      esac
      [[ "$proto" == tcp* ]] && contains_word "$CUSTOM_ALLOWED_TCP_PORTS" "$port" && known=1
      [[ "$proto" == udp* ]] && contains_word "$CUSTOM_ALLOWED_UDP_PORTS" "$port" && known=1
      if [[ -n "$known" ]]; then
        record INFO "port.${proto}.${port}" "发现常见公网监听端口 ${proto}/${port}" "Common public listener detected: ${proto}/${port}" "$rest"
      else
        record WARN "port.${proto}.${port}" "发现需要确认的公网监听端口 ${proto}/${port}" "Public listener requires review: ${proto}/${port}" "$rest" \
          "确认该端口对应你安装的服务；不需要时关闭服务并删除防火墙放行。" \
          "Confirm the service is intentional; otherwise stop it and remove the firewall rule."
      fi
    fi
  done <<<"$SOCKETS"
  ((public_count == 0)) && record PASS ports.none "未发现公网监听端口" "No public listeners detected"

  section "$(t firewall)"
  firewall_ok=0
  if have ufw; then
    UFW="$(ufw status verbose 2>/dev/null || true)"
    echo "$UFW"
    grep -q '^Status: active' <<<"$UFW" \
      && { record PASS fw.ufw.active "UFW 已启用" "UFW is active"; firewall_ok=1; } \
      || record FAIL fw.ufw.active "UFW 未启用" "UFW is inactive" "" \
        "启用 UFW 前先确保 SSH 端口已放行，避免把自己锁在服务器外。" \
        "Allow SSH before enabling UFW to avoid locking yourself out."
    grep -q 'Default: deny (incoming)' <<<"$UFW" \
      && record PASS fw.ufw.default "UFW 默认拒绝入站连接" "UFW default incoming policy is deny" \
      || record WARN fw.ufw.default "UFW 默认入站策略不是 deny" "UFW default incoming policy is not deny"
  else
    record INFO fw.ufw.absent "系统未安装 UFW" "UFW is not installed"
  fi
  IPT="$(iptables -S INPUT 2>/dev/null || true)"
  echo "$IPT"
  grep -q '^-P INPUT DROP' <<<"$IPT" \
    && { record PASS fw.iptables.input "iptables INPUT 默认策略为 DROP" "iptables INPUT policy is DROP"; firewall_ok=1; } \
    || record WARN fw.iptables.input "iptables INPUT 默认策略不是 DROP" "iptables INPUT policy is not DROP"
  ((firewall_ok == 1)) || record FAIL fw.none "未确认存在默认拒绝策略的主机防火墙" "No confirmed default-deny host firewall" "" \
    "至少配置一种主机防火墙，并采用默认拒绝入站策略。" \
    "Configure a host firewall with a default-deny incoming policy."

  section "$(t ssh)"
  if have sshd; then
    SSHD="$(sshd -T 2>/dev/null || true)"
    echo "$SSHD" | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxauthtries|x11forwarding|allowtcpforwarding|gatewayports|permitemptypasswords|clientaliveinterval|clientalivecountmax|allowusers|allowgroups)' || true
    sshval() { awk -v k="$1" '$1==k {print $2; exit}' <<<"$SSHD"; }
    [[ "$(sshval passwordauthentication)" == no ]] \
      && record PASS ssh.password "SSH 密码登录已关闭" "SSH password authentication is disabled" \
      || record FAIL ssh.password "SSH 密码登录仍然开启" "SSH password authentication is enabled" "" \
        "先确认密钥登录可用，再关闭 PasswordAuthentication。" \
        "Verify key login first, then disable PasswordAuthentication."
    [[ "$(sshval pubkeyauthentication)" == yes ]] \
      && record PASS ssh.pubkey "SSH 公钥登录已启用" "SSH public-key authentication is enabled" \
      || record FAIL ssh.pubkey "SSH 公钥登录未启用" "SSH public-key authentication is disabled"
    case "$(sshval permitrootlogin)" in
      no) record PASS ssh.root "root SSH 登录已关闭" "Root SSH login is disabled" ;;
      prohibit-password|without-password) record WARN ssh.root "root 仍可通过公钥登录" "Root SSH public-key login is still allowed" "" \
        "普通用户 sudo 可用后，建议设置 PermitRootLogin no。" \
        "After sudo access is verified, set PermitRootLogin no." ;;
      *) record FAIL ssh.root "root SSH 登录策略过于宽松" "Root SSH login is broadly allowed" ;;
    esac
    [[ "$(sshval permitemptypasswords)" == no ]] \
      && record PASS ssh.empty "SSH 禁止空密码" "Empty SSH passwords are forbidden" \
      || record FAIL ssh.empty "SSH 可能允许空密码" "Empty SSH passwords may be allowed"
    tries="$(sshval maxauthtries)"
    [[ "$tries" =~ ^[0-9]+$ && "$tries" -le 3 ]] \
      && record PASS ssh.tries "SSH 最大尝试次数合理" "SSH MaxAuthTries is appropriately limited" "$tries" \
      || record WARN ssh.tries "SSH 最大尝试次数偏高" "SSH MaxAuthTries may be too high" "${tries:-unknown}"
    [[ "$(sshval x11forwarding)" == no ]] \
      && record PASS ssh.x11 "SSH X11 转发已关闭" "SSH X11 forwarding is disabled" \
      || record WARN ssh.x11 "SSH X11 转发已开启" "SSH X11 forwarding is enabled"
    [[ "$(sshval allowtcpforwarding)" == no ]] \
      && record PASS ssh.forward "SSH TCP 转发已关闭" "SSH TCP forwarding is disabled" \
      || record WARN ssh.forward "SSH TCP 转发已开启" "SSH TCP forwarding is enabled"
    sshd -t 2>/dev/null \
      && record PASS ssh.syntax "sshd 配置语法正确" "sshd configuration syntax is valid" \
      || record FAIL ssh.syntax "sshd 配置语法错误" "sshd configuration syntax is invalid"
  else
    record FAIL ssh.missing "未找到 sshd" "sshd binary not found"
  fi

  section "$(t f2b)"
  if systemctl cat fail2ban.service >/dev/null 2>&1 || have fail2ban-client; then
    systemctl is-enabled --quiet fail2ban 2>/dev/null \
      && record PASS f2b.enabled "Fail2ban 已设置开机启动" "Fail2ban is enabled at boot" \
      || record WARN f2b.enabled "Fail2ban 未设置开机启动" "Fail2ban is not enabled at boot"
    systemctl is-active --quiet fail2ban 2>/dev/null \
      && record PASS f2b.active "Fail2ban 正在运行" "Fail2ban is active" \
      || record FAIL f2b.active "Fail2ban 未运行" "Fail2ban is inactive"
    safe fail2ban-client status
    safe fail2ban-client status sshd
  else
    record WARN f2b.absent "未安装 Fail2ban" "Fail2ban is not installed" "" \
      "新手公网 VPS 建议安装 Fail2ban，并至少启用 sshd jail。" \
      "Install Fail2ban and enable at least the sshd jail."
  fi

  section "$(t accounts)"
  UID0="$(awk -F: '$3==0{print $1}' /etc/passwd | xargs)"
  [[ "$UID0" == "$EXPECTED_UID0_USERS" ]] \
    && record PASS users.uid0 "UID 0 账户符合预期" "UID 0 accounts match expectation" "$UID0" \
    || record FAIL users.uid0 "发现异常 UID 0 账户" "Unexpected UID 0 accounts" "$UID0"
  echo "--- sudo group ---"; getent group sudo 2>/dev/null || true
  echo "--- login-capable accounts ---"; awk -F: '$7 !~ /(nologin|false)$/ {print $1":"$3":"$6":"$7}' /etc/passwd
  visudo -c >/dev/null 2>&1 \
    && record PASS sudo.syntax "sudoers 配置语法正确" "sudoers syntax is valid" \
    || record FAIL sudo.syntax "sudoers 配置语法错误" "sudoers syntax is invalid"
  EMPTY_PW="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | xargs)"
  [[ -z "$EMPTY_PW" ]] \
    && record PASS users.empty "未发现空密码账户" "No accounts have empty password hashes" \
    || record FAIL users.empty "发现空密码账户" "Accounts with empty password hashes" "$EMPTY_PW"
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    key="$home/.ssh/authorized_keys"
    [[ -f "$key" ]] || continue
    count="$(grep -cEv '^[[:space:]]*(#|$)' "$key" 2>/dev/null || true)"
    perms="$(stat -c '%a %U:%G' "$key" 2>/dev/null || true)"
    record INFO "keys.$user" "$user 的 authorized_keys" "$user authorized_keys" "$count key(s), $perms"
    ssh-keygen -lf "$key" 2>/dev/null || record WARN "keys.$user.invalid" "$user 的密钥文件无法解析" "$user authorized_keys contains an unparsable key"
  done </etc/passwd

  section "$(t logins)"
  echo "--- successful ---"; safe last -a -n "$LOGIN_LINES"
  echo "--- failed ---"; safe lastb -a -n "$LOGIN_LINES"
  if [[ -n "$TRUSTED_LOGIN_IPS" ]]; then
    mapfile -t seen_ips < <(last -a -n 200 2>/dev/null | awk '$1!="reboot" && $NF ~ /^[0-9a-fA-F:.]+$/ {print $NF}' | sort -u)
    for ip in "${seen_ips[@]}"; do
      contains_word "$TRUSTED_LOGIN_IPS" "$ip" || record WARN "login.$ip" "发现来自未列入信任清单的成功登录 IP" "Successful login from unlisted IP" "$ip"
    done
  else
    record INFO login.manual "请人工确认所有成功登录 IP 是否属于自己" "Manually verify every successful-login IP"
  fi

  section "$(t persistence)"
  FAILED_UNITS="$(systemctl --failed --no-legend 2>/dev/null || true)"
  [[ -z "$FAILED_UNITS" ]] \
    && record PASS systemd.failed "没有失败的 systemd 单元" "No failed systemd units" \
    || { record WARN systemd.failed "发现失败的 systemd 单元" "Failed systemd units detected"; echo "$FAILED_UNITS"; }
  echo "--- enabled services ---"; systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null || true
  echo "--- root crontab ---"; crontab -l 2>/dev/null || echo "none"
  echo "--- system cron ---"; grep -RHsEv '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d 2>/dev/null || true
  echo "--- timers ---"; systemctl list-timers --all --no-pager 2>/dev/null || true
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
    apt-get -qq update >/dev/null 2>&1 || record WARN pkg.index "软件源索引刷新失败" "Package index refresh failed"
    UPDATES="$(apt list --upgradable 2>/dev/null | sed '1d' || true)"
    [[ -z "$UPDATES" ]] \
      && record PASS pkg.updates "没有待更新的软件包" "No package updates are pending" \
      || { record WARN pkg.updates "存在待更新的软件包" "Package updates are pending"; echo "$UPDATES"; }
    dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q 'ok installed' \
      && record PASS pkg.unattended "已安装 unattended-upgrades" "unattended-upgrades is installed" \
      || record WARN pkg.unattended "未安装 unattended-upgrades" "unattended-upgrades is not installed" "" \
        "建议安装并启用 unattended-upgrades 自动安装安全更新。" \
        "Install and enable unattended-upgrades for automatic security fixes."
  else
    record SKIP pkg.updates "已跳过软件更新检查" "Package update check skipped"
  fi

  section "$(t sysctl)"
  check_sysctl() {
    local key="$1" expected="$2" val
    val="$(sysctl -n "$key" 2>/dev/null || echo unavailable)"
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

  section "$(t files)"
  for item in "/etc/passwd:644" "/etc/group:644" "/etc/shadow:640" "/etc/gshadow:640" "/etc/ssh/sshd_config:600,644"; do
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
  echo "--- SUID/SGID ---"
  find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%m %u:%g %p\n' 2>/dev/null | sort

  section "$(t docker)"
  if have docker; then
    systemctl is-active --quiet docker \
      && record INFO docker.active "Docker 正在运行" "Docker is active" \
      || record INFO docker.inactive "Docker 已安装但未运行" "Docker is installed but inactive"
    docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' 2>/dev/null || true
    ids="$(docker ps -q 2>/dev/null || true)"
    if [[ -n "$ids" ]]; then
      PRIV="$(docker inspect $ids --format '{{.Name}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}}' 2>/dev/null | grep 'privileged=true' || true)"
      [[ -z "$PRIV" ]] \
        && record PASS docker.priv "未发现特权 Docker 容器" "No running privileged Docker containers" \
        || record WARN docker.priv "发现特权 Docker 容器" "Privileged Docker containers detected" "$PRIV"
      HOSTNET="$(docker inspect $ids --format '{{.Name}} network={{.HostConfig.NetworkMode}}' 2>/dev/null | grep 'network=host' || true)"
      [[ -z "$HOSTNET" ]] || record WARN docker.hostnet "发现使用 host 网络的容器" "Containers using host networking detected" "$HOSTNET"
    else
      record INFO docker.none "没有运行中的 Docker 容器" "No running Docker containers"
    fi
    DOCKER_GROUP="$(getent group docker 2>/dev/null || true)"
    [[ -n "$DOCKER_GROUP" ]] && record INFO docker.group "docker 组成员可获得近似 root 权限，请确认成员" "Docker group members effectively have root-level access; review membership" "$DOCKER_GROUP"
  else
    record SKIP docker.absent "未安装 Docker" "Docker is not installed"
  fi

  section "$(t malware)"
  echo "--- deleted executables still running ---"
  DELETED="$(lsof +L1 2>/dev/null | awk '$4 ~ /txt/ || $9 ~ /\(deleted\)/' | head -n 100 || true)"
  [[ -z "$DELETED" ]] \
    && record PASS malware.deleted "未发现仍在运行的已删除可执行文件" "No deleted executables remain in use" \
    || { record WARN malware.deleted "发现已删除但仍在使用的文件" "Deleted files are still in use"; echo "$DELETED"; }
  echo "--- executable files recently modified in temporary directories ---"
  TMP_EXEC="$(find /tmp /var/tmp /dev/shm -xdev -type f -mtime -7 -perm /111 -ls 2>/dev/null | head -n 100 || true)"
  [[ -z "$TMP_EXEC" ]] \
    && record PASS malware.tmp "临时目录中未发现近期可执行文件" "No recent executable files in temporary directories" \
    || { record WARN malware.tmp "临时目录中存在近期可执行文件" "Recent executable files found in temporary directories"; echo "$TMP_EXEC"; }
  echo "--- suspicious process names ---"
  SUS_PROC="$(ps auxww 2>/dev/null | grep -Ei 'xmrig|minerd|kinsing|kdevtmpfsi|cryptominer|watchbog|masscan|zmap' | grep -v grep || true)"
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
    have rkhunter && safe rkhunter --check --sk --nocolors || record SKIP rootkit.rkhunter "未安装 rkhunter" "rkhunter is not installed"
    have chkrootkit && safe chkrootkit || record SKIP rootkit.chkrootkit "未安装 chkrootkit" "chkrootkit is not installed"
  else
    record SKIP rootkit.disabled "默认不运行 Rootkit 扫描器；可加 --rootkit-check" "Rootkit scanners are disabled by default; use --rootkit-check"
  fi

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

if [[ "$QUIET" -eq 1 ]]; then
  run_audit >"$TEXT_REPORT" 2>&1
else
  run_audit 2>&1 | tee "$TEXT_REPORT"
fi

if [[ "$FORMAT" == json || "$FORMAT" == both ]]; then
  {
    echo '{'
    echo '  "tool": "vps-guard-audit",'
    echo "  \"version\": \"$(json_escape "$VERSION")\","
    echo "  \"language\": \"$(json_escape "$LANGUAGE")\","
    echo "  \"host\": \"$(json_escape "$HOST")\","
    echo "  \"time\": \"$(json_escape "$(date -Is)")\","
    echo '  "read_only": true,'
    echo "  \"summary\": {\"pass\": $PASS, \"warn\": $WARN, \"fail\": $FAIL, \"info\": $INFO, \"skip\": $SKIP},"
    echo '  "findings": ['
    for i in "${!RESULTS[@]}"; do
      printf '    %s' "${RESULTS[$i]}"
      [[ "$i" -lt $((${#RESULTS[@]}-1)) ]] && printf ','
      printf '\n'
    done
    echo '  ]'
    echo '}'
  } >"$JSON_REPORT"
fi

[[ "$FORMAT" == json ]] && rm -f "$TEXT_REPORT"
[[ "$FORMAT" == text ]] && rm -f "$JSON_REPORT"

echo
echo "============================================================"
echo "$(t done)"
echo "$(t reports):"
[[ -f "$TEXT_REPORT" ]] && echo "  TXT : $TEXT_REPORT"
[[ -f "$JSON_REPORT" ]] && echo "  JSON: $JSON_REPORT"
echo "============================================================"

if ((FAIL > 0)); then exit 2
elif ((WARN > 0)); then exit 1
else exit 0
fi
