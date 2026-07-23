#!/usr/bin/env bash
# VPS Guard Audit
# 面向中文用户的 Ubuntu / Debian VPS 安全审计与可控加固工具。
# Supported: Ubuntu 26.04/24.04/22.04 LTS and Debian 13/12/11.
# Version: 6.0.0-dev.9

set -uo pipefail
IFS=$'\n\t'
export LC_ALL=C LANG=C
umask 077

VERSION="6.0.0-dev.9"
SCHEMA_VERSION="2.0"
COMMAND="audit"
AFTER_AUDIT="auto"
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
DEPTH="standard"
FULL_IDENTIFIERS=0
MAX_LIST_ITEMS=20
HISTORY_ENABLED=1
IS_CONTAINER=0

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
declare -a FINDING_LEGACY_IDS=()
declare -a FINDING_CONFIDENCE=()
declare -a FINDING_APPLICABILITY=()
declare -a FINDING_HISTORY_KEYS=()

usage() {
  cat <<'EOF_USAGE'
用法：
  vpsga [options]
  vpsga plan [options]         检测后生成中文加固计划（只读）

首次安装：
  curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash

选项：
  --output-dir DIR             报告保存目录
  --format text|json|both
  --config FILE                配置文件
  --login-lines N              登录记录最大行数
  --no-update-check            跳过软件更新检查
  --refresh-package-index      刷新 APT 索引（会写入系统）
  --profile auto|general|web|docker|proxy|home|desktop
  --depth quick|standard|deep  快速、标准或深度检查
  --policy baseline|strict
  --full-identifiers           完整显示标识符
  --rootkit-check              运行已安装的 Rootkit 扫描器
  --no-history                 不保存本次比较状态
  --after-audit auto|none|plan|menu
                               检测后的操作；auto 仅在交互终端显示菜单
  --quiet                      不在终端显示检测过程
  -h, --help                   显示帮助
  -v, --version                显示版本
EOF_USAGE
}

if [[ "${1-}" == audit || "${1-}" == plan ]]; then
  COMMAND="$1"
  shift
fi

while (($#)); do
  case "$1" in
    --output-dir) OUTPUT_DIR="${2:?缺少目录}"; shift 2 ;;
    --format) FORMAT="${2:?缺少格式}"; shift 2 ;;
    --config) CONFIG_FILE="${2:?缺少配置文件}"; shift 2 ;;
    --login-lines) LOGIN_LINES="${2:?缺少数字}"; shift 2 ;;
    --no-update-check) CHECK_UPDATES=0; shift ;;
    --refresh-package-index) REFRESH_PACKAGE_INDEX=1; shift ;;
    --profile) PROFILE="${2:?缺少配置档案}"; shift 2 ;;
    --depth) DEPTH="${2:?缺少检测深度}"; shift 2 ;;
    --policy) POLICY="${2:?缺少安全策略}"; shift 2 ;;
    --full-identifiers) FULL_IDENTIFIERS=1; shift ;;
    --rootkit-check) CHECK_ROOTKITS=1; shift ;;
    --no-history) HISTORY_ENABLED=0; shift ;;
    --after-audit) AFTER_AUDIT="${2:?缺少检测后操作}"; shift 2 ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "$VERSION"; exit 0 ;;
    *) echo "未知选项：$1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$FORMAT" in text|json|both) ;; *) echo "无效报告格式：$FORMAT" >&2; exit 64 ;; esac
case "$PROFILE" in auto|general|web|docker|proxy|home|desktop|vps|server|container) ;; *) echo "无效配置档案：$PROFILE" >&2; exit 64 ;; esac
case "$DEPTH" in quick|standard|deep) ;; *) echo "无效检测深度：$DEPTH" >&2; exit 64 ;; esac
case "$POLICY" in baseline|strict) ;; *) echo "无效安全策略：$POLICY" >&2; exit 64 ;; esac
case "$AFTER_AUDIT" in auto|none|plan|menu) ;; *) echo "无效检测后操作：$AFTER_AUDIT" >&2; exit 64 ;; esac
[[ "$LOGIN_LINES" =~ ^[0-9]+$ ]] || { echo "--login-lines 必须是整数" >&2; exit 64; }
case "$PROFILE" in vps|server|container) PROFILE="general" ;; esac
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  if command -v vpsga >/dev/null 2>&1; then
    echo "请直接运行 vpsga，它会自动请求 sudo 权限。" >&2
  else
    echo "请先运行官方一键安装命令：" >&2
    echo "curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash" >&2
  fi
  exit 77
fi

# Generic defaults. Optional config can extend or override these. Configuration
# must be fully validated before any output directory, report, lock or runtime
# temporary file is created.
TRUSTED_LOGIN_IPS=""
EXPECTED_UID0_USERS="root"
CUSTOM_ALLOWED_TCP_PORTS=""
CUSTOM_ALLOWED_UDP_PORTS=""

load_config() {
  local file="$1" line key value
  local double_quoted_re='^([A-Z0-9_]+)="([^"]*)"$'
  local single_quoted_re="^([A-Z0-9_]+)='([^']*)'$"
  local unquoted_re='^([A-Z0-9_]+)=([A-Za-z0-9_.,:/ -]*)$'
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" =~ $double_quoted_re ]]; then
      key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ $single_quoted_re ]]; then
      key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ $unquoted_re ]]; then
      key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
    else
      echo "配置文件包含不受支持或不安全的语法：$line" >&2
      exit 76
    fi
    case "$key" in
      TRUSTED_LOGIN_IPS|EXPECTED_UID0_USERS|CUSTOM_ALLOWED_TCP_PORTS|CUSTOM_ALLOWED_UDP_PORTS|PROFILE|POLICY|DEPTH|MAX_LIST_ITEMS)
        printf -v "$key" '%s' "$value"
        ;;
      *)
        echo "配置文件包含未知字段：$key" >&2
        exit 64
        ;;
    esac
  done <"$file"
}

if [[ -n "$CONFIG_FILE" ]]; then
  [[ ! -L "$CONFIG_FILE" ]] || { echo "拒绝加载符号链接配置文件：$CONFIG_FILE" >&2; exit 76; }
  [[ -r "$CONFIG_FILE" ]] || { echo "无法读取配置文件：$CONFIG_FILE" >&2; exit 66; }
  config_owner="$(stat -c %u "$CONFIG_FILE" 2>/dev/null || true)"
  if find "$CONFIG_FILE" -maxdepth 0 -perm /022 -print -quit 2>/dev/null | grep -q .; then
    echo "配置文件可被组用户或其他用户修改，拒绝以 root 权限加载：$CONFIG_FILE" >&2
    exit 76
  fi
  if [[ "$config_owner" != 0 && "$config_owner" != "${SUDO_UID:-}" ]]; then
    echo "配置文件所有者不是 root 或当前调用用户，拒绝加载：$CONFIG_FILE" >&2
    exit 76
  fi
  load_config "$CONFIG_FILE"
fi
case "$PROFILE" in auto|general|web|docker|proxy|home|desktop|vps|server|container) ;; *) echo "配置文件中的 PROFILE 无效：$PROFILE" >&2; exit 64 ;; esac
case "$PROFILE" in vps|server|container) PROFILE="general" ;; esac
case "$POLICY" in baseline|strict) ;; *) echo "配置文件中的 POLICY 无效：$POLICY" >&2; exit 64 ;; esac
case "$DEPTH" in quick|standard|deep) ;; *) echo "配置文件中的 DEPTH 无效：$DEPTH" >&2; exit 64 ;; esac
[[ "$MAX_LIST_ITEMS" =~ ^[1-9][0-9]*$ ]] || { echo "MAX_LIST_ITEMS 必须是正整数" >&2; exit 64; }
case "$DEPTH" in
  quick) CHECK_UPDATES=0; CHECK_ROOTKITS=0; MAX_LIST_ITEMS=10 ;;
  deep) CHECK_ROOTKITS=1 ;;
esac

prepare_output_directory() {
  local requested="$OUTPUT_DIR"

  if [[ -e "$requested" || -L "$requested" ]]; then
    [[ -d "$requested" ]] || {
      echo "报告输出路径不是目录：$requested" >&2
      exit 73
    }
  elif [[ "${SUDO_UID:-}" =~ ^[0-9]+$ && "${SUDO_GID:-}" =~ ^[0-9]+$ && "$SUDO_UID" -ne 0 ]]; then
    install -d -m 0700 -o "$SUDO_UID" -g "$SUDO_GID" -- "$requested" || {
      echo "无法为当前调用用户创建报告目录：$requested" >&2
      exit 73
    }
  else
    mkdir -p -- "$requested" || {
      echo "无法创建报告目录：$requested" >&2
      exit 73
    }
  fi

  OUTPUT_DIR="$(cd -- "$requested" 2>/dev/null && pwd -P)" || {
    echo "无法进入报告目录：$requested" >&2
    exit 73
  }
}

prepare_output_directory

declare -A ZH
ZH[title]="VPS Guard Audit 完整报告"
ZH[readonly]="检测过程只读：只有明确输入 APPLY 执行已开放加固项，或使用 --refresh-package-index 时才会修改系统"
ZH[start]="即将开始全面安全检测"
ZH[system]="1. 操作系统支持状态与基础防护"
ZH[ports]="2. 全部接口监听端口与网络暴露"
ZH[firewall]="3. 防火墙与默认入站策略"
ZH[ssh]="4. SSH 登录安全"
ZH[f2b]="5. 暴力破解防护"
ZH[accounts]="6. 用户、sudo、密码与 SSH 密钥"
ZH[logins]="7. 登录记录与可疑来源"
ZH[persistence]="8. 开机服务、Cron 与持久化项目"
ZH[packages]="9. 软件包、漏洞修复与自动更新"
ZH[sysctl]="10. 内核与网络安全参数"
ZH[files]="11. 敏感文件权限与全局可写文件"
ZH[docker]="12. Docker 与容器风险"
ZH[malware]="13. 可疑进程、临时目录与下载执行痕迹"
ZH[proxy]="14. 代理、VPN 与高风险辅助脚本"
ZH[rootkit]="15. Rootkit 扫描器状态"
ZH[summary]="16. 检测总结与下一步建议"
ZH[reports]="报告保存位置"
ZH[done]="检测完成"
ZH[low]="总体情况良好：没有发现明确的高危问题"
ZH[medium]="没有发现明确的高危问题，但有一些项目建议确认或改进"
ZH[high]="发现需要尽快处理的问题"

t() {
  local key="$1"
  printf '%s' "${ZH[$key]}"
}

echo
echo "$(t readonly)"
echo "$(t start)"

HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d-%H%M%S)"
FULL_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}-full.txt"
AI_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}-ai.txt"
JSON_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}.json"
for report_path in "$FULL_REPORT" "$AI_REPORT" "$JSON_REPORT"; do
  if [[ -e "$report_path" || -L "$report_path" ]]; then
    echo "拒绝覆盖已经存在的报告路径：$report_path" >&2
    exit 73
  fi
done

LOCK_DIR="${VPSGA_LOCK_DIR:-/run/vps-guard-audit.lock}"
if ! mkdir -- "$LOCK_DIR" 2>/dev/null; then
  lock_pid="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
  if [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
    echo "已有另一个 vpsga 检测正在运行（PID $lock_pid）。" >&2
    exit 75
  fi
  if [[ -d "$LOCK_DIR" && ! -L "$LOCK_DIR" && "$(stat -c %u "$LOCK_DIR" 2>/dev/null || true)" == 0 ]]; then
    rm -f -- "$LOCK_DIR/pid" 2>/dev/null || true
    rmdir -- "$LOCK_DIR" 2>/dev/null || true
  fi
  mkdir -- "$LOCK_DIR" 2>/dev/null || {
    echo "无法取得运行锁；请确认没有检测正在运行，并检查：$LOCK_DIR" >&2
    exit 75
  }
fi
printf '%s\n' "$$" >"$LOCK_DIR/pid"
set -o noclobber
exec 3>"$FULL_REPORT" || { echo "无法安全创建完整报告：$FULL_REPORT" >&2; rm -f -- "$LOCK_DIR/pid"; rmdir -- "$LOCK_DIR" 2>/dev/null || true; exit 73; }
exec 4>"$JSON_REPORT" || { echo "无法安全创建 JSON 报告：$JSON_REPORT" >&2; exec 3>&-; rm -f -- "$FULL_REPORT" "$LOCK_DIR/pid"; rmdir -- "$LOCK_DIR" 2>/dev/null || true; exit 73; }
exec 5>"$AI_REPORT" || { echo "无法安全创建 AI 报告：$AI_REPORT" >&2; exec 3>&- 4>&-; rm -f -- "$FULL_REPORT" "$JSON_REPORT" "$LOCK_DIR/pid"; rmdir -- "$LOCK_DIR" 2>/dev/null || true; exit 73; }
set +o noclobber
TMP_DIR="$(mktemp -d)" || { echo "无法创建临时目录" >&2; exec 3>&- 4>&- 5>&-; rm -f -- "$FULL_REPORT" "$JSON_REPORT" "$AI_REPORT" "$LOCK_DIR/pid"; rmdir -- "$LOCK_DIR" 2>/dev/null || true; exit 69; }
MODULE_TMP_DIR=""
cleanup_runtime() {
  if [[ -n "${HARDENING_TX_DIR:-}" && -f "${HARDENING_TX_DIR}/status" ]] \
    && grep -q '^status=running$' "${HARDENING_TX_DIR}/status" 2>/dev/null \
    && declare -F hardening_tx_rollback >/dev/null 2>&1; then
    interrupted_action="${HARDENING_TX_ACTION:-}"
    if hardening_tx_rollback "程序中断，退出时自动回滚" >/dev/null 2>&1; then
      [[ -z "$interrupted_action" ]] || ! declare -F hardening_after_rollback >/dev/null 2>&1 \
        || hardening_after_rollback "$interrupted_action" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf -- "$TMP_DIR"
  [[ -n "$MODULE_TMP_DIR" ]] && rm -rf -- "$MODULE_TMP_DIR"
  if [[ -d "$LOCK_DIR" && ! -L "$LOCK_DIR" && "$(cat "$LOCK_DIR/pid" 2>/dev/null || true)" == "$$" ]]; then
    rm -f -- "$LOCK_DIR/pid" 2>/dev/null || true
    rmdir -- "$LOCK_DIR" 2>/dev/null || true
  fi
}
trap cleanup_runtime EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

json_escape() {
  local s=${1-}
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

level_label() {
  case "$1" in
    PASS) printf '正常' ;;
    WARN) printf '提醒' ;;
    FAIL) printf '问题' ;;
    INFO) printf '信息' ;;
    SKIP) printf '跳过' ;;
    *) printf '未知' ;;
  esac
}

record() {
  local level="$1" id="$2" zh_title="$3" en_title="$4" detail="${5-}" zh_rec="${6-}" en_rec="${7-}"
  local title="$zh_title" rec="$zh_rec" status confidence applicability evidence_json commands_json label
  registry_lookup "$id"
  case "$level" in
    PASS) PASS=$((PASS+1)) ;;
    WARN) WARN=$((WARN+1)); WARNINGS+=("$title${detail:+ — $detail}") ;;
    FAIL) FAIL=$((FAIL+1)); FAILURES+=("$title${detail:+ — $detail}") ;;
    INFO) INFO=$((INFO+1)) ;;
    SKIP) SKIP=$((SKIP+1)) ;;
  esac
  case "$level" in
    PASS) status="pass"; confidence="confirmed" ;;
    WARN) status="warn"; confidence="needs_review" ;;
    FAIL) status="fail"; confidence="confirmed" ;;
    INFO) status="info"; confidence="informational" ;;
    SKIP) status="skip"; confidence="unconfirmed" ;;
  esac
  applicability="applicable"
  if [[ "$level" == SKIP ]]; then
    if [[ "$zh_title" == *未安装* || "$zh_title" == *缺少* || "$zh_title" == *无法读取* ]]; then
      applicability="missing_requirement"
    elif [[ "$zh_title" == *容器内无法* || "$zh_title" == *不适用* ]]; then
      applicability="not_applicable"
    else
      applicability="not_checked"
    fi
  fi
  [[ -n "$rec" ]] && RECOMMENDATIONS+=("$rec")
  FINDING_IDS+=("$CHECK_ID")
  FINDING_LEGACY_IDS+=("$id")
  FINDING_HISTORY_KEYS+=("$CHECK_ID|$id")
  FINDING_LEVELS+=("$level")
  FINDING_TITLES+=("$title")
  FINDING_DETAILS+=("$detail")
  FINDING_RECOMMENDATIONS+=("$rec")
  FINDING_CONFIDENCE+=("$confidence")
  FINDING_APPLICABILITY+=("$applicability")
  label="$(level_label "$level")"
  printf '[%s] %s %s' "$label" "$CHECK_ID" "$title"
  [[ -n "$detail" ]] && printf ' — %s' "$detail"
  printf '\n'
  if [[ -n "$detail" ]]; then evidence_json="[\"$(json_escape "$detail")\"]"; else evidence_json="[]"; fi
  if [[ -n "$CHECK_REQUIRED_COMMANDS" ]]; then commands_json="[\"${CHECK_REQUIRED_COMMANDS//,/\",\"}\"]"; else commands_json="[]"; fi
  RESULTS+=("{\"test_id\":\"$CHECK_ID\",\"instance_key\":\"$(json_escape "$id")\",\"registered_name\":\"$(json_escape "$CHECK_NAME")\",\"status\":\"$status\",\"confidence\":\"$confidence\",\"applicability\":\"$applicability\",\"title\":\"$(json_escape "$title")\",\"category\":\"$(json_escape "$CHECK_CATEGORY")\",\"applicable_systems\":[\"Ubuntu\",\"Debian\"],\"risk\":\"$CHECK_RISK\",\"check_depth\":\"$CHECK_DEPTH\",\"required_commands\":$commands_json,\"requires_root\":true,\"prerequisite\":\"$(json_escape "$CHECK_PREREQUISITE")\",\"source\":\"$(json_escape "$CHECK_SOURCE")\",\"evidence\":$evidence_json,\"recommendation\":\"$(json_escape "$rec")\",\"references\":[]}")
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
  if systemd-detect-virt --container >/dev/null 2>&1; then
    IS_CONTAINER=1
  fi
  if [[ "$PROFILE" != auto ]]; then
    HOST_PROFILE="$PROFILE"
    return
  fi
  if [[ "$IS_CONTAINER" -eq 1 ]]; then
    HOST_PROFILE="general"
    return
  fi
  local chassis
  chassis="$(hostnamectl chassis 2>/dev/null || true)"
  case "$chassis" in
    desktop|laptop|convertible|tablet) HOST_PROFILE="desktop" ;;
    server) HOST_PROFILE="general" ;;
    *)
      HOST_PROFILE="general"
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
  # 使用物理路径解析 current 符号链接，确保权限与所有者检查真正遍历版本目录。
  script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd -P)"
  if [[ -d "$script_dir/lib" ]]; then
    lib_dir="$script_dir/lib"
  elif [[ -d /usr/local/lib/vps-guard-audit/current/lib ]]; then
    lib_dir="/usr/local/lib/vps-guard-audit/current/lib"
  else
    have curl || { echo "下载检测模块需要 curl" >&2; exit 69; }
    tmp_lib="$(mktemp -d)"
    MODULE_TMP_DIR="$tmp_lib"
    base_url="${VPS_GUARD_BASE_URL:-https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/lib}"
    for module in check-registry.sh hardening-registry.sh hardening-transaction.sh hardening-actions.sh connection-safety.sh hardening-plan.sh audit-platform.sh audit-access.sh audit-system.sh audit-containers.sh report-guidance-zh.sh report-guidance.sh report-output.sh audit-summary.sh; do
      curl -fsSL "$base_url/$module" -o "$tmp_lib/$module" || {
        echo "下载模块失败：$module" >&2
        exit 69
      }
    done
    lib_dir="$tmp_lib"
  fi
  if [[ -f "$script_dir/MANIFEST.sha256" ]]; then
    if [[ "$(stat -c %u "$script_dir" 2>/dev/null || true)" != 0 ]]; then
      echo "安装目录不属于 root，拒绝以 root 权限加载：$script_dir" >&2
      exit 76
    fi
    if find "$script_dir" -xdev -type f -perm /022 -print -quit 2>/dev/null | grep -q .; then
      echo "安装目录中存在可被组用户或其他用户修改的文件，拒绝继续。" >&2
      exit 76
    fi
    if find "$script_dir" -xdev -type f ! -user root -print -quit 2>/dev/null | grep -q .; then
      echo "安装目录中存在不属于 root 的程序文件，拒绝继续。" >&2
      exit 76
    fi
    if ! (cd "$script_dir" && sha256sum -c MANIFEST.sha256 >/dev/null 2>&1); then
      echo "程序模块完整性校验失败，请运行 vpsga update 重新安装。" >&2
      exit 76
    fi
  fi
  for module in check-registry.sh hardening-registry.sh hardening-transaction.sh hardening-actions.sh connection-safety.sh hardening-plan.sh audit-platform.sh audit-access.sh audit-system.sh audit-containers.sh report-guidance-zh.sh report-guidance.sh report-output.sh audit-summary.sh; do
    [[ -f "$lib_dir/$module" && ! -L "$lib_dir/$module" ]] || {
      echo "检测模块缺失或是符号链接：$lib_dir/$module" >&2
      exit 76
    }
    # shellcheck disable=SC1090
    source "$lib_dir/$module"
  done
}

load_audit_modules

run_audit() {
  echo "$(t title)"
  echo "版本：$VERSION"
  echo "主机：$HOST"
  echo "时间：$(date -Is)"
  echo "配置档案：$HOST_PROFILE"
  echo "检测深度：$DEPTH"
  echo "$(t readonly)"

  audit_platform
  audit_access
  audit_system
  audit_containers
  audit_summary
}

if [[ "$QUIET" -eq 1 ]]; then
  run_audit >&3 2>&1
else
  AUDIT_PIPE="$TMP_DIR/audit.pipe"
  mkfifo "$AUDIT_PIPE"
  tee /dev/fd/3 <"$AUDIT_PIPE" &
  TEE_PID=$!
  run_audit >"$AUDIT_PIPE" 2>&1
  wait "$TEE_PID"
fi
chmod 0600 "$FULL_REPORT" 2>/dev/null || true

if [[ "$FORMAT" == json || "$FORMAT" == both ]]; then
  {
    echo '{'
    echo '  "tool": "vps-guard-audit",'
    echo "  \"schema_version\": \"$SCHEMA_VERSION\","
    echo "  \"version\": \"$(json_escape "$VERSION")\","
    echo '  "language": "zh-CN",'
    echo "  \"host\": \"$(json_escape "$HOST")\","
    echo "  \"time\": \"$(json_escape "$(date -Is)")\","
    if [[ "$REFRESH_PACKAGE_INDEX" -eq 0 ]]; then read_only_json=true; else read_only_json=false; fi
    echo "  \"read_only\": $read_only_json,"
    echo "  \"profile\": \"$(json_escape "$HOST_PROFILE")\","
    echo "  \"policy\": \"$(json_escape "$POLICY")\","
    echo "  \"depth\": \"$(json_escape "$DEPTH")\","
    echo "  \"summary\": {\"pass\": $PASS, \"warn\": $WARN, \"fail\": $FAIL, \"info\": $INFO, \"skip\": $SKIP},"
    echo '  "findings": ['
    for i in "${!RESULTS[@]}"; do
      printf '    %s' "${RESULTS[$i]}"
      [[ "$i" -lt $((${#RESULTS[@]}-1)) ]] && printf ','
      printf '\n'
    done
    echo '  ]'
    echo '}'
  } >&4
  chmod 0600 "$JSON_REPORT" 2>/dev/null || true
fi

if [[ "$FORMAT" == text || "$FORMAT" == both ]]; then
  generate_ai_report
fi
exec 3>&- 4>&- 5>&-
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
[[ -f "$FULL_REPORT" ]] && echo "  完整报告：$FULL_REPORT"
[[ -f "$AI_REPORT" ]] && echo "  AI 脱敏报告：$AI_REPORT"
[[ -f "$JSON_REPORT" ]] && echo "  JSON: $JSON_REPORT"
echo "============================================================"

if [[ "$COMMAND" == plan || "$AFTER_AUDIT" == plan ]]; then
  print_hardening_plan
elif [[ "$AFTER_AUDIT" == menu ]]; then
  if [[ -t 0 && -t 1 ]]; then
    show_post_audit_menu
  else
    echo "--after-audit menu 需要交互式终端；已改为输出只读加固计划。" >&2
    print_hardening_plan
  fi
elif [[ "$AFTER_AUDIT" == auto && -t 0 && -t 1 ]]; then
  show_post_audit_menu
fi

if ((FAIL > 0)); then exit 2
elif ((WARN > 0)); then exit 1
else exit 0
fi
