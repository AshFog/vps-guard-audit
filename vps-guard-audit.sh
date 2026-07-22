#!/usr/bin/env bash
# VPS Guard Audit
# 中文原生、默认只读的 Ubuntu / Debian VPS 安全审计工具。
# Version: 5.0.0

set -uo pipefail
IFS=$'\n\t'
export LC_ALL=C LANG=C
umask 077

VERSION="5.0.0"
SCHEMA_VERSION="2.0"
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
MODE="standard"
FULL_IDENTIFIERS=0
MAX_LIST_ITEMS=20
HISTORY_ENABLED=1

PASS=0
WARN=0
FAIL=0
INFO=0
SKIP=0

TMP_DIR=""
MODULE_TMP_DIR=""
LOCK_PID_FILE=""

declare -a RESULTS=()
declare -a WARNINGS=()
declare -a FAILURES=()
declare -a RECOMMENDATIONS=()
declare -a FINDING_IDS=()
declare -a FINDING_CODES=()
declare -a FINDING_LEVELS=()
declare -a FINDING_TITLES=()
declare -a FINDING_DETAILS=()
declare -a FINDING_RECOMMENDATIONS=()
declare -a FINDING_CATEGORIES=()
declare -a FINDING_CONFIDENCES=()
declare -a FINDING_APPLICABILITIES=()

usage() {
  cat <<'EOF_USAGE'
VPS Guard Audit 5.0

用法：
  vpsga [参数]

第一次安装：
  curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash

常用参数：
  --mode quick|standard|deep       检测深度：快速、标准、深度
  --output-dir 目录                报告保存目录
  --format text|json|both          报告格式
  --config 文件                    读取自定义配置
  --login-lines 数量               登录记录最大行数
  --no-update-check                不读取待更新软件包
  --refresh-package-index          先刷新 APT 索引（会写入系统）
  --profile auto|vps|server|desktop|container
  --policy baseline|strict         SSH 等项目的基线或严格策略
  --full-identifiers               在完整报告中保留更多标识符
  --rootkit-check                  运行系统中已经安装的 Rootkit 扫描器
  --no-history                     本次不读取或保存历史比较
  --quiet                          终端不显示检测过程
  -h, --help                       显示帮助
  -v, --version                    显示版本

兼容说明：
  --lang zh 仍可使用但会被忽略；5.0 起不再生成英文报告。
EOF_USAGE
}

while (($#)); do
  case "$1" in
    --mode) MODE="${2:?缺少检测模式}"; shift 2 ;;
    --mode=*) MODE="${1#*=}"; shift ;;
    --output-dir) OUTPUT_DIR="${2:?缺少目录}"; shift 2 ;;
    --output-dir=*) OUTPUT_DIR="${1#*=}"; shift ;;
    --format) FORMAT="${2:?缺少格式}"; shift 2 ;;
    --format=*) FORMAT="${1#*=}"; shift ;;
    --config) CONFIG_FILE="${2:?缺少配置文件}"; shift 2 ;;
    --config=*) CONFIG_FILE="${1#*=}"; shift ;;
    --login-lines) LOGIN_LINES="${2:?缺少数量}"; shift 2 ;;
    --login-lines=*) LOGIN_LINES="${1#*=}"; shift ;;
    --no-update-check) CHECK_UPDATES=0; shift ;;
    --refresh-package-index) REFRESH_PACKAGE_INDEX=1; shift ;;
    --profile) PROFILE="${2:?缺少主机类型}"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    --policy) POLICY="${2:?缺少策略}"; shift 2 ;;
    --policy=*) POLICY="${1#*=}"; shift ;;
    --full-identifiers) FULL_IDENTIFIERS=1; shift ;;
    --rootkit-check) CHECK_ROOTKITS=1; shift ;;
    --no-history) HISTORY_ENABLED=0; shift ;;
    --quiet) QUIET=1; shift ;;
    --lang)
      legacy_lang="${2:?缺少语言}"; shift 2
      [[ "$legacy_lang" == zh || "$legacy_lang" == zh-CN ]] || {
        echo "VPS Guard Audit 5.0 起只生成中文报告，不再支持英文报告。" >&2
        exit 64
      }
      ;;
    --lang=*)
      legacy_lang="${1#*=}"; shift
      [[ "$legacy_lang" == zh || "$legacy_lang" == zh-CN ]] || {
        echo "VPS Guard Audit 5.0 起只生成中文报告，不再支持英文报告。" >&2
        exit 64
      }
      ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "$VERSION"; exit 0 ;;
    *) echo "未知参数：$1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$FORMAT" in text|json|both) ;; *) echo "报告格式无效：$FORMAT" >&2; exit 64 ;; esac
case "$PROFILE" in auto|vps|server|desktop|container) ;; *) echo "主机类型无效：$PROFILE" >&2; exit 64 ;; esac
case "$POLICY" in baseline|strict) ;; *) echo "安全策略无效：$POLICY" >&2; exit 64 ;; esac
case "$MODE" in quick|standard|deep) ;; *) echo "检测模式无效：$MODE" >&2; exit 64 ;; esac
[[ "$LOGIN_LINES" =~ ^[0-9]+$ ]] || { echo "--login-lines 必须是整数" >&2; exit 64; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  if command -v vpsga >/dev/null 2>&1; then
    echo "请直接运行 vpsga，它会自动请求 sudo 权限。" >&2
  else
    echo "请先运行官方一键安装命令：" >&2
    echo "curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash" >&2
  fi
  exit 77
fi

cleanup() {
  [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf -- "$TMP_DIR"
  [[ -n "$MODULE_TMP_DIR" && -d "$MODULE_TMP_DIR" ]] && rm -rf -- "$MODULE_TMP_DIR"
  [[ -n "$LOCK_PID_FILE" && -f "$LOCK_PID_FILE" ]] && rm -f -- "$LOCK_PID_FILE"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

acquire_lock() {
  local lock_file lock_dir old_pid
  lock_file="${VPSGA_LOCK_FILE:-/run/lock/vpsga.lock}"
  lock_dir="$(dirname "$lock_file")"
  mkdir -p -- "$lock_dir" 2>/dev/null || true

  if command -v flock >/dev/null 2>&1; then
    exec 9>"$lock_file" || { echo "无法创建运行锁：$lock_file" >&2; exit 75; }
    if ! flock -n 9; then
      echo "已有一个 VPS Guard Audit 正在运行，本次已停止。" >&2
      exit 75
    fi
    printf '%s\n' "$$" 1>&9
    return
  fi

  LOCK_PID_FILE="${VPSGA_PID_FILE:-/run/vpsga.pid}"
  if (set -o noclobber; printf '%s\n' "$$" >"$LOCK_PID_FILE") 2>/dev/null; then
    return
  fi
  old_pid="$(cat "$LOCK_PID_FILE" 2>/dev/null || true)"
  if [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
    echo "已有一个 VPS Guard Audit 正在运行（PID $old_pid），本次已停止。" >&2
    exit 75
  fi
  rm -f -- "$LOCK_PID_FILE"
  (set -o noclobber; printf '%s\n' "$$" >"$LOCK_PID_FILE") 2>/dev/null || {
    echo "无法取得运行锁，本次已停止。" >&2
    exit 75
  }
}

acquire_lock

if [[ -n "$CONFIG_FILE" ]]; then
  [[ -r "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || {
    echo "配置文件不可读或是符号链接：$CONFIG_FILE" >&2
    exit 66
  }
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

case "$PROFILE" in auto|vps|server|desktop|container) ;; *) echo "配置中的 PROFILE 无效：$PROFILE" >&2; exit 64 ;; esac
case "$POLICY" in baseline|strict) ;; *) echo "配置中的 POLICY 无效：$POLICY" >&2; exit 64 ;; esac
case "$MODE" in quick|standard|deep) ;; *) echo "配置中的 MODE 无效：$MODE" >&2; exit 64 ;; esac
[[ "$MAX_LIST_ITEMS" =~ ^[0-9]+$ && "$MAX_LIST_ITEMS" -gt 0 ]] || { echo "MAX_LIST_ITEMS 必须是正整数" >&2; exit 64; }

mkdir -p -- "$OUTPUT_DIR" || { echo "无法创建报告目录：$OUTPUT_DIR" >&2; exit 73; }
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
[[ -w "$OUTPUT_DIR" ]] || { echo "报告目录不可写：$OUTPUT_DIR" >&2; exit 73; }

HOST="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_TIME="$(date -Is)"
FULL_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}-full.txt"
AI_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}-ai.txt"
JSON_REPORT="${OUTPUT_DIR}/vpsga-${STAMP}.json"
TMP_DIR="$(mktemp -d)"

for report_path in "$FULL_REPORT" "$AI_REPORT" "$JSON_REPORT"; do
  if [[ -e "$report_path" || -L "$report_path" ]]; then
    echo "为避免覆盖或符号链接风险，报告文件已存在：$report_path" >&2
    exit 73
  fi
done

TRUSTED_LOGIN_IPS="${TRUSTED_LOGIN_IPS:-}"
EXPECTED_UID0_USERS="${EXPECTED_UID0_USERS:-root}"
CUSTOM_ALLOWED_TCP_PORTS="${CUSTOM_ALLOWED_TCP_PORTS:-}"
CUSTOM_ALLOWED_UDP_PORTS="${CUSTOM_ALLOWED_UDP_PORTS:-}"

json_escape() {
  local s=${1-}
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

status_label() {
  case "$1" in
    PASS) printf '正常' ;;
    WARN) printf '提醒' ;;
    FAIL) printf '问题' ;;
    INFO) printf '信息' ;;
    SKIP) printf '跳过' ;;
    *) printf '%s' "$1" ;;
  esac
}

status_json() {
  case "$1" in
    PASS) printf 'pass' ;;
    WARN) printf 'warn' ;;
    FAIL) printf 'fail' ;;
    INFO) printf 'info' ;;
    SKIP) printf 'skip' ;;
    *) printf 'unknown' ;;
  esac
}

record() {
  local level="$1" id="$2" zh_title="$3" _unused_en_title="${4-}" detail="${5-}" zh_rec="${6-}" _unused_en_rec="${7-}"
  local label json_status
  registry_lookup "$id"
  label="$(status_label "$level")"
  json_status="$(status_json "$level")"

  case "$level" in
    PASS) PASS=$((PASS+1)) ;;
    WARN) WARN=$((WARN+1)); WARNINGS+=("$zh_title${detail:+ — $detail}") ;;
    FAIL) FAIL=$((FAIL+1)); FAILURES+=("$zh_title${detail:+ — $detail}") ;;
    INFO) INFO=$((INFO+1)) ;;
    SKIP) SKIP=$((SKIP+1)) ;;
  esac

  [[ -n "$zh_rec" ]] && RECOMMENDATIONS+=("$zh_rec")
  FINDING_IDS+=("$id")
  FINDING_CODES+=("$TEST_CODE")
  FINDING_LEVELS+=("$level")
  FINDING_TITLES+=("$zh_title")
  FINDING_DETAILS+=("$detail")
  FINDING_RECOMMENDATIONS+=("$zh_rec")
  FINDING_CATEGORIES+=("$TEST_CATEGORY")
  FINDING_CONFIDENCES+=("$TEST_CONFIDENCE")
  FINDING_APPLICABILITIES+=("$TEST_APPLICABILITY")

  printf '[%s] [%s] %s' "$label" "$TEST_CODE" "$zh_title"
  [[ -n "$detail" ]] && printf ' — %s' "$detail"
  printf '\n'

  RESULTS+=("{\"id\":\"$(json_escape "$id")\",\"test_code\":\"$(json_escape "$TEST_CODE")\",\"status\":\"$json_status\",\"level\":\"$level\",\"category\":\"$(json_escape "$TEST_CATEGORY")\",\"required_mode\":\"$(json_escape "$TEST_REQUIRED_MODE")\",\"confidence\":\"$(json_escape "$TEST_CONFIDENCE")\",\"applicability\":\"$(json_escape "$TEST_APPLICABILITY")\",\"title\":\"$(json_escape "$zh_title")\",\"detail\":\"$(json_escape "$detail")\",\"recommendation\":\"$(json_escape "$zh_rec")\"}")
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
      record PASS os.supported "当前 Ubuntu 版本在项目支持范围内" "" "${OS_ID} ${OS_VERSION} ${OS_CODENAME}" ;;
    debian:13|debian:12|debian:11)
      record PASS os.supported "当前 Debian 版本在项目支持范围内" "" "${OS_ID} ${OS_VERSION} ${OS_CODENAME}" ;;
    ubuntu:*|debian:*)
      record WARN os.unsupported_version "当前系统版本不在已验证的六个版本中" "" "${OS_ID} ${OS_VERSION}" \
        "建议使用 Ubuntu 26.04/24.04/22.04 LTS 或 Debian 13/12/11。" ;;
    *)
      record FAIL os.unsupported_family "当前系统不是受支持的 Ubuntu 或 Debian" "" "${OS_ID} ${OS_VERSION}" \
        "请不要在未测试的系统上依赖本报告。" ;;
  esac
}

verify_installed_integrity() {
  local script_dir manifest
  script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd -P)"
  manifest="$script_dir/manifest.sha256"
  case "$script_dir" in
    /usr/local/lib/vps-guard-audit/*)
      have sha256sum || { echo "缺少 sha256sum，无法验证已安装程序完整性。" >&2; exit 69; }
      [[ -r "$manifest" && ! -L "$manifest" ]] || { echo "已安装程序缺少完整性清单：$manifest" >&2; exit 69; }
      if ! (cd "$script_dir" && sha256sum -c --quiet manifest.sha256); then
        echo "VPS Guard Audit 安装文件完整性校验失败。请运行官方一键命令重新安装。" >&2
        exit 69
      fi
      ;;
  esac
}

load_audit_modules() {
  local script_dir lib_dir tmp_lib base_url module
  local -a modules=(
    test-registry.sh
    audit-platform.sh
    audit-access.sh
    audit-system.sh
    audit-containers.sh
    audit-deep.sh
    report-guidance-zh.sh
    report-guidance.sh
    report-output.sh
    audit-summary.sh
  )

  script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd -P)"
  if [[ -d "$script_dir/lib" ]]; then
    lib_dir="$script_dir/lib"
  elif [[ -d /usr/local/lib/vps-guard-audit/current/lib ]]; then
    lib_dir="/usr/local/lib/vps-guard-audit/current/lib"
  else
    have curl || { echo "缺少 curl，无法下载审计模块。" >&2; exit 69; }
    tmp_lib="$(mktemp -d)"
    MODULE_TMP_DIR="$tmp_lib"
    base_url="${VPS_GUARD_BASE_URL:-https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/lib}"
    for module in "${modules[@]}"; do
      curl -fsSL "$base_url/$module" -o "$tmp_lib/$module" || {
        echo "模块下载失败：$module" >&2
        exit 69
      }
    done
    lib_dir="$tmp_lib"
  fi

  for module in "${modules[@]}"; do
    [[ -r "$lib_dir/$module" && ! -L "$lib_dir/$module" ]] || {
      echo "审计模块缺失、不可读或是符号链接：$lib_dir/$module" >&2
      exit 69
    }
    # shellcheck disable=SC1090
    source "$lib_dir/$module"
  done
}

verify_installed_integrity
load_audit_modules
detect_host_profile
SELF_PATH="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"

run_audit() {
  echo "VPS Guard Audit 完整报告"
  echo "版本：$VERSION"
  echo "报告格式版本：$SCHEMA_VERSION"
  echo "主机：$HOST"
  echo "时间：$RUN_TIME"
  echo "检测模式：$MODE"
  echo "主机类型：$HOST_PROFILE"
  echo "安全策略：$POLICY"
  echo "默认只读：不会修改防火墙、SSH、用户或系统配置；仅在使用 --refresh-package-index 时刷新 APT 索引"

  audit_platform
  audit_access

  if [[ "$MODE" == quick ]]; then
    section "8-16. 快速检查跳过的项目"
    record SKIP mode.quick.system "快速检查未运行系统维护、文件权限和内核参数检查" "" "使用 --mode standard 或 --mode deep 运行"
    record SKIP mode.quick.containers "快速检查未运行容器、可疑进程和 Rootkit 检查" "" "使用 --mode standard 或 --mode deep 运行"
  else
    audit_system
    audit_containers
  fi

  if [[ "$MODE" == deep ]]; then
    audit_deep
  fi

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
    echo "  \"schema_version\": \"$(json_escape "$SCHEMA_VERSION")\","
    echo '  "language": "zh-CN",'
    echo "  \"host\": \"$(json_escape "$HOST")\","
    echo "  \"time\": \"$(json_escape "$RUN_TIME")\","
    if [[ "$REFRESH_PACKAGE_INDEX" -eq 0 ]]; then read_only_json=true; else read_only_json=false; fi
    echo "  \"read_only\": $read_only_json,"
    echo "  \"mode\": \"$(json_escape "$MODE")\","
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
  rm -f -- "$FULL_REPORT" "$AI_REPORT"
elif [[ "$FORMAT" == text ]]; then
  rm -f -- "$JSON_REPORT"
fi

echo
echo "============================================================"
echo "检测完成"
echo "报告保存位置："
[[ -f "$FULL_REPORT" ]] && echo "  完整报告：$FULL_REPORT"
[[ -f "$AI_REPORT" ]] && echo "  AI 脱敏报告：$AI_REPORT"
[[ -f "$JSON_REPORT" ]] && echo "  JSON：$JSON_REPORT"
echo "============================================================"

if ((FAIL > 0)); then exit 2
elif ((WARN > 0)); then exit 1
else exit 0
fi
