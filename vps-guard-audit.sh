#!/usr/bin/env bash
# VPS Guard Audit
# Interactive bilingual, read-only security audit.
# Supported: Ubuntu 26.04/24.04/22.04 LTS and Debian 13/12/11.
# Version: 4.4.0

set -uo pipefail
IFS=$'\n\t'
export LC_ALL=C LANG=C

VERSION="4.4.0"
LANGUAGE=""
OUTPUT_DIR="${PWD}"
FORMAT="both"
QUIET=0
LOGIN_LINES=30
CONFIG_FILE=""
CHECK_UPDATES=1
CHECK_ROOTKITS=0
REFRESH_PACKAGE_INDEX=0
PROFILE="auto"
POLICY="baseline"
FULL_IDENTIFIERS=0
MAX_LIST_ITEMS=20
HISTORY_ENABLED=1

PASS=0
WARN=0
FAIL=0
INFO=0
SKIP=0

declare -a RESULTS=()
declare -a WARNINGS=()
declare -a FAILURES=()
declare -a RECOMMENDATIONS=()
declare -a FINDING_IDS=()
declare -a FINDING_LEVELS=()
declare -a FINDING_TITLES=()
declare -a FINDING_DETAILS=()
declare -a FINDING_RECOMMENDATIONS=()

usage() {
  cat <<'EOF_USAGE'
Usage:
  sudo ./vps-guard-audit.sh

Options:
  --lang zh|en
  --output-dir DIR
  --format text|json|both
  --config FILE
  --login-lines N
  --no-update-check
  --refresh-package-index
  --profile auto|vps|server|desktop|container
  --policy baseline|strict
  --full-identifiers
  --rootkit-check
  --no-history
  --quiet
  -h, --help
  -v, --version
EOF_USAGE
}

while (($#)); do
  case "$1" in
    --lang) LANGUAGE="${2:?missing language}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:?missing directory}"; shift 2 ;;
    --format) FORMAT="${2:?missing format}"; shift 2 ;;
    --config) CONFIG_FILE="${2:?missing config file}"; shift 2 ;;
    --login-lines) LOGIN_LINES="${2:?missing number}"; shift 2 ;;
    --no-update-check) CHECK_UPDATES=0; shift ;;
    --refresh-package-index) REFRESH_PACKAGE_INDEX=1; shift ;;
    --profile) PROFILE="${2:?missing profile}"; shift 2 ;;
    --policy) POLICY="${2:?missing policy}"; shift 2 ;;
    --full-identifiers) FULL_IDENTIFIERS=1; shift ;;
    --rootkit-check) CHECK_ROOTKITS=1; shift ;;
    --no-history) HISTORY_ENABLED=0; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "$VERSION"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$FORMAT" in text|json|both) ;; *) echo "Invalid format: $FORMAT" >&2; exit 64 ;; esac
case "$PROFILE" in auto|vps|server|desktop|container) ;; *) echo "Invalid profile: $PROFILE" >&2; exit 64 ;; esac
case "$POLICY" in baseline|strict) ;; *) echo "Invalid policy: $POLICY" >&2; exit 64 ;; esac
[[ "$LOGIN_LINES" =~ ^[0-9]+$ ]] || { echo "--login-lines must be an integer" >&2; exit 64; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "请使用 root 权限运行 / Run as root:"
  echo "sudo ./vps-guard-audit.sh"
  exit 77
fi

choose_language() {
  local choice
  if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    echo "Interactive terminal is unavailable. Run with --lang zh or --lang en." >&2
    exit 65
  fi

  cat >/dev/tty <<'EOF_LANGUAGE'
============================================================
                      VPS Guard Audit
============================================================

Please select a language / 请选择语言：

  1) 中文
  2) English

EOF_LANGUAGE
  while true; do
    printf "请输入选项 / Enter choice [1-2]: " >/dev/tty
    if ! IFS= read -r choice </dev/tty; then
      echo >&2
      echo "Unable to read from the interactive terminal." >&2
      exit 65
    fi
    case "$choice" in
      1|zh|ZH|cn|CN|中文) LANGUAGE="zh"; break ;;
      2|en|EN|English|english) LANGUAGE="en"; break ;;
      *) echo "无效选项，请输入 1 或 2。 / Invalid choice. Enter 1 or 2." >/dev/tty ;;
    esac
  done
}
[[ -z "$LANGUAGE" ]] && choose_language
case "$LANGUAGE" in zh|en) ;; *) echo "Invalid language: $LANGUAGE" >&2; exit 64 ;; esac

declare -A ZH EN
ZH[title]="VPS Guard Audit 完整报告"
EN[title]="VPS Guard Audit Full Report"
ZH[readonly]="默认只读：不会修改防火墙、SSH、用户或系统配置；仅在使用 --refresh-package-index 时刷新 APT 索引"
EN[readonly]="Read-only by default: no firewall, SSH, user or system settings are changed; APT indexes refresh only with --refresh-package-index"
ZH[start]="即将开始全面安全检测"
EN[start]="The full security audit is about to begin"
ZH[system]="1. 操作系统支持状态与基础防护"
EN[system]="1. OS support status and baseline protection"
ZH[ports]="2. 全部接口监听端口与网络暴露"
EN[ports]="2. All-interface listeners and network exposure"
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
ZH[summary]="16. 检测总结与下一步建议"
EN[summary]="16. Summary and next steps"
ZH[reports]="报告保存位置"
EN[reports]="Report location"
ZH[done]="检测完成"
EN[done]="Audit completed"
ZH[low]="总体情况良好：没有发现明确的高危问题"
EN[low]="Overall status looks good: no clear high-risk issue was found"
ZH[medium]="没有发现明确的高危问题，但有一些项目建议确认或改进"
EN[medium]="No clear high-risk issue was found, but some items should be reviewed or improved"
ZH[high]="发现需要尽快处理的问题"
EN[high]="Issues requiring prompt attention were found"

t() {
  local key="$1"
  [[ "$LANGUAGE" == "zh" ]] && printf '%s' "${ZH[$key]}" || printf '%s' "${EN[$key]}"
}

echo
echo "$(t readonly)"
echo "$(t start)"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d-%H%M%S)"
FULL_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}-full.txt"
AI_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}-ai.txt"
JSON_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}.json"
TMP_DIR="$(mktemp -d)"
MODULE_TMP_DIR=""
trap 'rm -rf "$TMP_DIR"; [[ -n "$MODULE_TMP_DIR" ]] && rm -rf "$MODULE_TMP_DIR"' EXIT

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
  FINDING_IDS+=("$id")
  FINDING_LEVELS+=("$level")
  FINDING_TITLES+=("$title")
  FINDING_DETAILS+=("$detail")
  FINDING_RECOMMENDATIONS+=("$rec")
  printf '[%s] %s' "$level" "$title"
  [[ -n "$detail" ]] && printf ' — %s' "$detail"
  printf '\n'
  RESULTS+=("{\"id\":\"$(json_escape "$id")\",\"level\":\"$level\",\"title\":\"$(json_escape "$title")\",\"detail\":\"$(json_escape "$detail")\",\"recommendation\":\"$(json_escape "$rec")\"}")
}

section() { printf '\n==============================================================================\n%s\n==============================================================================\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
safe() { "$@" 2>&1 || true; }
contains_word() { [[ " $1 " == *" $2 "* ]]; }

redact_stream() {
  if [[ "$FULL_IDENTIFIERS" -eq 1 ]]; then
    cat
  else
    sed -E 's/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)[0-9]{1,3}\b/\1x/g'
  fi
}

trim_lines() {
  local limit="${1:-$MAX_LIST_ITEMS}"
  head -n "$limit"
}

detect_host_profile() {
  if [[ "$PROFILE" != auto ]]; then
    HOST_PROFILE="$PROFILE"
    return
  fi
  if systemd-detect-virt --container >/dev/null 2>&1; then
    HOST_PROFILE="container"
    return
  fi
  local chassis virt
  chassis="$(hostnamectl chassis 2>/dev/null || true)"
  virt="$(systemd-detect-virt 2>/dev/null || true)"
  case "$chassis" in
    desktop|laptop|convertible|tablet) HOST_PROFILE="desktop" ;;
    server) HOST_PROFILE="server" ;;
    *)
      if [[ -n "$virt" && "$virt" != none ]]; then HOST_PROFILE="vps"; else HOST_PROFILE="server"; fi
      ;;
  esac
}

detect_host_profile
SELF_PATH="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"

supported_os_check() {
  OS_ID="unknown"; OS_VERSION="unknown"; OS_CODENAME=""
  if [[ -r /etc/os-release ]]; then
    OS_ID="$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '"')"
    OS_VERSION="$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n1 | tr -d '"')"
    OS_CODENAME="$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release | head -n1 | tr -d '"')"
    OS_ID="${OS_ID:-unknown}"
    OS_VERSION="${OS_VERSION:-unknown}"
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

load_audit_modules() {
  local script_dir lib_dir tmp_lib base_url module
  script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
  if [[ -d "$script_dir/lib" ]]; then
    lib_dir="$script_dir/lib"
  elif [[ -d /usr/local/lib/vps-guard-audit/current/lib ]]; then
    lib_dir="/usr/local/lib/vps-guard-audit/current/lib"
  else
    have curl || { echo "curl is required to download audit modules" >&2; exit 69; }
    tmp_lib="$(mktemp -d)"
    MODULE_TMP_DIR="$tmp_lib"
    base_url="${VPS_GUARD_BASE_URL:-https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/lib}"
    for module in audit-platform.sh audit-access.sh audit-system.sh audit-containers.sh report-guidance-zh.sh report-guidance-en.sh report-guidance.sh report-output.sh audit-summary.sh; do
      curl -fsSL "$base_url/$module" -o "$tmp_lib/$module" || {
        echo "Failed to download module: $module" >&2
        exit 69
      }
    done
    lib_dir="$tmp_lib"
  fi
  for module in audit-platform.sh audit-access.sh audit-system.sh audit-containers.sh report-guidance-zh.sh report-guidance-en.sh report-guidance.sh report-output.sh audit-summary.sh; do
    # shellcheck disable=SC1090
    source "$lib_dir/$module"
  done
}

load_audit_modules

run_audit() {
  echo "$(t title)"
  echo "Version: $VERSION"
  echo "Host: $HOST"
  echo "Time: $(date -Is)"
  echo "$(t readonly)"

  audit_platform
  audit_access
  audit_system
  audit_containers
  audit_summary
}

if [[ "$QUIET" -eq 1 ]]; then
  run_audit >"$FULL_REPORT" 2>&1
else
  AUDIT_PIPE="$TMP_DIR/audit.pipe"
  mkfifo "$AUDIT_PIPE"
  tee "$FULL_REPORT" <"$AUDIT_PIPE" &
  TEE_PID=$!
  run_audit >"$AUDIT_PIPE" 2>&1
  wait "$TEE_PID"
fi
chmod 0600 "$FULL_REPORT" 2>/dev/null || true

if [[ "$FORMAT" == json || "$FORMAT" == both ]]; then
  {
    echo '{'
    echo '  "tool": "vps-guard-audit",'
    echo "  \"version\": \"$(json_escape "$VERSION")\","
    echo "  \"language\": \"$(json_escape "$LANGUAGE")\","
    echo "  \"host\": \"$(json_escape "$HOST")\","
    echo "  \"time\": \"$(json_escape "$(date -Is)")\","
    if [[ "$REFRESH_PACKAGE_INDEX" -eq 0 ]]; then read_only_json=true; else read_only_json=false; fi
    echo "  \"read_only\": $read_only_json,"
    echo "  \"profile\": \"$(json_escape "$HOST_PROFILE")\","
    echo "  \"policy\": \"$(json_escape "$POLICY")\","
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
  chmod 0600 "$JSON_REPORT" 2>/dev/null || true
fi

if [[ "$FORMAT" == text || "$FORMAT" == both ]]; then
  generate_ai_report
fi
save_history_state

if [[ "$FORMAT" == json ]]; then
  rm -f "$FULL_REPORT" "$AI_REPORT"
elif [[ "$FORMAT" == text ]]; then
  rm -f "$JSON_REPORT"
fi

echo
echo "============================================================"
echo "$(t done)"
echo "$(t reports):"
[[ -f "$FULL_REPORT" ]] && echo "  FULL: $FULL_REPORT"
[[ -f "$AI_REPORT" ]] && echo "  AI  : $AI_REPORT"
[[ -f "$JSON_REPORT" ]] && echo "  JSON: $JSON_REPORT"
echo "============================================================"

if ((FAIL > 0)); then exit 2
elif ((WARN > 0)); then exit 1
else exit 0
fi
