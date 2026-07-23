#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

# This helper never performs a hardening action. It verifies and records the
# evidence produced by actions that a human runs on an explicitly disposable
# Ubuntu/Debian VM with a provider console and snapshot.

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATE_ROOT="${VPSGA_VM_ACCEPTANCE_ROOT:-/var/lib/vps-guard-audit/vm-acceptance}"
HARDENING_STATE_ROOT="${VPSGA_HARDENING_STATE_ROOT:-/var/lib/vps-guard-audit/hardening}"
GUARD_ROOT="${VPSGA_CONNECTION_GUARD_ROOT:-/run/vps-guard-audit/connection-guards}"
OS_RELEASE="${VPSGA_VM_ACCEPTANCE_OS_RELEASE:-/etc/os-release}"
VPSGA_BIN="${VPSGA_VM_ACCEPTANCE_BIN:-vpsga}"
SYSTEMCTL_BIN="${VPSGA_VM_ACCEPTANCE_SYSTEMCTL:-systemctl}"
INSTALLED_ROOT="${VPSGA_VM_ACCEPTANCE_INSTALLED_ROOT:-/usr/local/lib/vps-guard-audit/current}"
TEST_MODE="${VPSGA_VM_ACCEPTANCE_TEST_MODE:-0}"

ACTIONS=(
  HARD-2001 HARD-2002 HARD-2003 HARD-2004
  HARD-2005 HARD-2006 HARD-2007 HARD-2008
)
PATHS=(confirm timeout)

die() {
  local rc="$1"
  shift
  printf 'VM 验收失败：%s\n' "$*" >&2
  exit "$rc"
}

usage() {
  cat <<'EOF'
用法：
  sudo -E bash tests/manual-vm-acceptance.sh start ADMIN SNAPSHOT_REF
  sudo -E bash tests/manual-vm-acceptance.sh record RUN_ID HARD-2001 confirm TX_ID
  sudo -E bash tests/manual-vm-acceptance.sh record RUN_ID HARD-2001 timeout TX_ID
  sudo bash tests/manual-vm-acceptance.sh status RUN_ID
  sudo -E bash tests/manual-vm-acceptance.sh finish RUN_ID

安全门槛：
  start/record/finish 均需显式设置 VPSGA_VM_ACCEPTANCE_DISPOSABLE=YES。
  start 还需设置 VPSGA_VM_ACCEPTANCE_CONSOLE=READY，并提供快照标识。
  record 必须由备用管理员从一次全新的 SSH 会话通过 sudo 运行。
EOF
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die 77 "需要 root 权限。"
}

require_disposable_ack() {
  [[ "${VPSGA_VM_ACCEPTANCE_DISPOSABLE:-}" == YES ]] || {
    die 65 "仅可在一次性 VM 上设置 VPSGA_VM_ACCEPTANCE_DISPOSABLE=YES 后运行。"
  }
}

is_action() {
  local wanted="$1" action
  for action in "${ACTIONS[@]}"; do
    [[ "$wanted" == "$action" ]] && return 0
  done
  return 1
}

parse_ssh_context() {
  local value="$1" remote_ip remote_port local_ip local_port extra
  IFS=' ' read -r remote_ip remote_port local_ip local_port extra <<<"$value"
  [[ -n "$remote_ip" && -n "$local_ip" && -z "${extra:-}" ]] || return 65
  [[ "$remote_ip" != *[[:space:]]* && "$local_ip" != *[[:space:]]* ]] || return 65
  [[ "$remote_port" =~ ^[0-9]+$ && "$local_port" =~ ^[0-9]+$ ]] || return 65
  ((remote_port >= 1 && remote_port <= 65535 && local_port >= 1 && local_port <= 65535)) || return 65
  printf '%s\t%s\t%s\t%s\n' "$remote_ip" "$remote_port" "$local_ip" "$local_port"
}

current_ssh_context() {
  [[ -n "${SSH_CONNECTION:-}" ]] || die 65 "当前不是可验证的 SSH 会话。"
  parse_ssh_context "$SSH_CONNECTION" || die 65 "SSH_CONNECTION 格式无效。"
}

read_os_value() {
  local key="$1" value
  [[ -f "$OS_RELEASE" && ! -L "$OS_RELEASE" ]] || die 66 "无法读取安全的 os-release：$OS_RELEASE"
  value="$(sed -n "s/^${key}=//p" "$OS_RELEASE" | head -n 1)"
  value="${value#\"}"
  value="${value%\"}"
  [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]] || die 66 "os-release 中的 $key 无效。"
  printf '%s\n' "$value"
}

require_supported_vm() {
  local os_id="$1" os_version="$2"
  case "$os_id:$os_version" in
    ubuntu:26.04|ubuntu:24.04|ubuntu:22.04|debian:13|debian:12|debian:11) ;;
    *) die 69 "不支持的真实 VM 系统：$os_id $os_version" ;;
  esac

  if [[ "$TEST_MODE" != 1 ]]; then
    [[ -d /run/systemd/system ]] || die 69 "当前不是可用的 systemd 主机。"
    command -v systemd-detect-virt >/dev/null 2>&1 || die 69 "缺少 systemd-detect-virt。"
    if systemd-detect-virt --container >/dev/null 2>&1; then
      die 65 "容器不能替代真实 VM 连接验收。"
    fi
    command -v systemd-run >/dev/null 2>&1 || die 69 "缺少 systemd-run。"
    command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1 || die 69 "缺少 systemctl。"
  else
    [[ "$STATE_ROOT" != /var/lib/vps-guard-audit/vm-acceptance ]] || {
      die 76 "测试模式不得写入正式验收目录。"
    }
  fi
}

prepare_state_root() {
  [[ ! -L "$STATE_ROOT" ]] || die 76 "拒绝使用符号链接验收目录。"
  mkdir -p -- "$STATE_ROOT"
  [[ "$(stat -c %u "$STATE_ROOT")" == 0 ]] || die 76 "验收目录不属于 root。"
  chmod 0700 -- "$STATE_ROOT"
}

read_meta() {
  local run_dir="$1" key="$2"
  sed -n "s/^${key}=//p" "$run_dir/meta" | head -n 1
}

load_run() {
  local run_id="$1" run_dir
  [[ "$run_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9]+$ ]] || die 64 "RUN_ID 格式无效。"
  run_dir="$STATE_ROOT/$run_id"
  [[ -d "$run_dir" && ! -L "$run_dir" && -f "$run_dir/meta" && -f "$run_dir/cases.tsv" ]] \
    || die 66 "找不到完整验收记录：$run_id"
  [[ "$(stat -c %u "$run_dir")" == 0 ]] || die 76 "验收记录不属于 root。"
  if find "$run_dir" -xdev -perm /077 -print -quit 2>/dev/null | grep -q .; then
    die 76 "验收记录可被其他用户读取或修改。"
  fi
  printf '%s\n' "$run_dir"
}

candidate_version() {
  bash "$PROJECT_ROOT/vps-guard-audit.sh" --version
}

installed_version() {
  "$VPSGA_BIN" --version
}

candidate_commit() {
  local commit
  if [[ "$TEST_MODE" == 1 ]]; then
    git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || printf 'test-mode\n'
    return 0
  fi
  command -v git >/dev/null 2>&1 || die 69 "真实 VM 验收需要 Git 候选分支工作区。"
  git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree 2>/dev/null | grep -qx true \
    || die 69 "验收助手不在 Git 候选分支中。"
  [[ -z "$(git -C "$PROJECT_ROOT" status --porcelain --untracked-files=no)" ]] \
    || die 65 "候选分支存在未提交的受跟踪文件改动，拒绝建立发布证据。"
  commit="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
  [[ "$commit" =~ ^[a-f0-9]{40}$ ]] || die 69 "无法确定候选提交。"
  printf '%s\n' "$commit"
}

assert_source_matches_install() {
  local manifest file checksum
  if [[ "$TEST_MODE" == 1 && "${VPSGA_VM_ACCEPTANCE_TEST_VERIFY_INSTALL:-0}" != 1 ]]; then
    return 0
  fi
  [[ -d "$INSTALLED_ROOT" ]] || die 66 "找不到已安装候选目录：$INSTALLED_ROOT"
  manifest="$INSTALLED_ROOT/MANIFEST.sha256"
  [[ -f "$manifest" && ! -L "$manifest" ]] || die 66 "已安装候选缺少完整性清单。"
  while IFS=' ' read -r checksum file; do
    [[ "$checksum" =~ ^[a-f0-9]{64}$ && "$file" =~ ^[A-Za-z0-9._/-]+$ ]] \
      || die 76 "安装完整性清单包含无效条目。"
    [[ "$file" != /* && "$file" != *..* ]] || die 76 "安装完整性清单包含不安全路径。"
    [[ -f "$PROJECT_ROOT/$file" && ! -L "$PROJECT_ROOT/$file" ]] \
      || die 66 "候选分支缺少安装文件：$file"
    cmp -s -- "$PROJECT_ROOT/$file" "$INSTALLED_ROOT/$file" \
      || die 65 "已安装内容与候选提交不一致：$file"
  done <"$manifest"
}

assert_candidate_installed() {
  local expected="$1" recorded_commit="${2:-}" actual current_commit
  actual="$(installed_version 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]] || {
    die 69 "已安装版本 ${actual:-未知} 与候选版本 $expected 不一致。"
  }
  current_commit="$(candidate_commit)"
  if [[ -n "$recorded_commit" && "$recorded_commit" != "$current_commit" ]]; then
    die 65 "候选提交已在验收过程中变化。"
  fi
  assert_source_matches_install
}

capture_command() {
  local output="$1"
  shift
  if "$@" >"$output" 2>&1; then
    chmod 0600 -- "$output"
    return 0
  fi
  chmod 0600 -- "$output" 2>/dev/null || true
  return 1
}

cmd_start() {
  local admin="${1:-}" snapshot_ref="${2:-}" os_id os_version expected actual
  local context run_id run_dir snapshot_hash commit connection_log
  require_root
  require_disposable_ack
  [[ "${VPSGA_VM_ACCEPTANCE_CONSOLE:-}" == READY ]] || {
    die 65 "必须先验证网页控制台/VNC/救援模式，再设置 VPSGA_VM_ACCEPTANCE_CONSOLE=READY。"
  }
  [[ "$admin" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || die 64 "备用管理员用户名无效。"
  [[ "$snapshot_ref" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || die 64 "快照标识格式无效。"
  context="$(current_ssh_context)"
  os_id="$(read_os_value ID)"
  os_version="$(read_os_value VERSION_ID)"
  require_supported_vm "$os_id" "$os_version"
  prepare_state_root

  expected="$(candidate_version)"
  actual="$(installed_version 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]] || die 69 "请先从当前候选分支安装 $expected；当前为 ${actual:-未知}。"
  commit="$(candidate_commit)"
  assert_source_matches_install

  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM:-0}"
  run_dir="$STATE_ROOT/$run_id"
  mkdir -- "$run_dir" "$run_dir/preflight" "$run_dir/cases"
  chmod 0700 -- "$run_dir" "$run_dir/preflight" "$run_dir/cases"

  capture_command "$run_dir/preflight/doctor.txt" "$VPSGA_BIN" doctor \
    || die 69 "vpsga doctor 未通过；原始结果保存在 $run_dir/preflight/doctor.txt"
  connection_log="$run_dir/preflight/connection-check.txt"
  capture_command "$connection_log" "$VPSGA_BIN" connection-check \
    || die 69 "连接前置检查未通过；结果保存在 $connection_log"
  grep -Fqx "  - $admin" "$connection_log" \
    || die 65 "备用管理员 $admin 未通过 sudo 与 authorized_keys 检查。"
  capture_command "$run_dir/preflight/firewall-plan.txt" "$VPSGA_BIN" firewall-plan \
    || die 69 "防火墙端口计划生成失败。"
  capture_command "$run_dir/preflight/workload-plan.txt" "$VPSGA_BIN" workload-plan \
    || die 69 "业务用途检查生成失败。"

  snapshot_hash="$(printf '%s' "$snapshot_ref" | sha256sum | awk '{print $1}')"
  cat >"$run_dir/meta" <<EOF
run_id=$run_id
candidate_version=$expected
candidate_commit=$commit
os_id=$os_id
os_version=$os_version
started_at=$(date -Is)
started_epoch=$(date +%s)
admin=$admin
snapshot_ref_sha256=$snapshot_hash
console=confirmed
initial_session_sha256=$(printf '%s' "$context" | sha256sum | awk '{print $1}')
test_mode=$TEST_MODE
EOF
  : >"$run_dir/cases.tsv"
  chmod 0600 -- "$run_dir/meta" "$run_dir/cases.tsv"

  echo "真实 VM 验收已建立。"
  echo "不要删除快照，不要关闭当前 SSH 会话。"
  echo "RUN_ID=$run_id"
}

find_guard_dir() {
  local tx_id="$1" dir found=""
  [[ -d "$GUARD_ROOT" && ! -L "$GUARD_ROOT" ]] || return 66
  for dir in "$GUARD_ROOT"/*; do
    [[ -d "$dir" && ! -L "$dir" && "${dir##*/}" =~ ^[a-f0-9]{32}$ ]] || continue
    [[ -f "$dir/status" && ! -L "$dir/status" ]] || continue
    if grep -Fqx "transaction=$tx_id" "$dir/status"; then
      [[ -z "$found" ]] || return 75
      found="$dir"
    fi
  done
  [[ -n "$found" ]] || return 66
  printf '%s\n' "$found"
}

context_same_endpoint() {
  local first="$1" second="$2"
  [[ "$(cut -f3,4 <<<"$first")" == "$(cut -f3,4 <<<"$second")" ]]
}

assert_new_admin_session() {
  local admin="$1" initial="$2" confirmed="${3:-}" current confirming_user
  current="$(current_ssh_context)"
  confirming_user="${SUDO_USER:-${USER:-}}"
  [[ "$confirming_user" == "$admin" ]] || {
    die 65 "必须由备用管理员 $admin 从新 SSH 会话通过 sudo 记录结果。"
  }
  [[ "$current" != "$initial" ]] || die 65 "当前仍是动作开始时的原 SSH 会话。"
  context_same_endpoint "$initial" "$current" || die 65 "当前 SSH 到达的服务器地址或端口不同。"
  if [[ -n "$confirmed" ]]; then
    [[ "$current" != "$confirmed" ]] || {
      die 65 "确认路径还需在提交后再打开一个全新的第三 SSH 会话。"
    }
    context_same_endpoint "$initial" "$confirmed" || die 76 "第二会话证据的服务器入口不一致。"
  fi
  printf '%s\n' "$current"
}

assert_timer_inactive() {
  local unit="$1"
  if "$SYSTEMCTL_BIN" is-active --quiet "$unit.timer" >/dev/null 2>&1; then
    die 75 "自动回滚 timer 仍在运行：$unit.timer"
  fi
}

cmd_record() {
  local run_id="${1:-}" action="${2:-}" path="${3:-}" tx_id="${4:-}"
  local run_dir expected tx_dir tx_action tx_status guard_dir guard_status guard_admin
  local initial confirmed="" current unit result started finished elapsed evidence
  require_root
  require_disposable_ack
  is_action "$action" || die 64 "仅支持 HARD-2001 至 HARD-2008。"
  [[ "$path" == confirm || "$path" == timeout ]] || die 64 "路径必须为 confirm 或 timeout。"
  [[ "$tx_id" =~ ^[0-9]{8}T[0-9]{6}Z-${action}-[0-9]+-[0-9]+$ ]] \
    || die 64 "事务编号与动作不匹配。"

  run_dir="$(load_run "$run_id")"
  [[ ! -f "$run_dir/finished" ]] || die 65 "该验收已经结束。"
  expected="$(read_meta "$run_dir" candidate_version)"
  assert_candidate_installed "$expected" "$(read_meta "$run_dir" candidate_commit)"
  if awk -F'\t' -v action="$action" -v path="$path" \
    '$1 == action && $2 == path && $3 == "PASS" { found=1 } END { exit(found ? 0 : 1) }' \
    "$run_dir/cases.tsv"; then
    die 65 "$action/$path 已经记录通过，拒绝覆盖。"
  fi

  tx_dir="$HARDENING_STATE_ROOT/$tx_id"
  [[ -d "$tx_dir" && ! -L "$tx_dir" && -f "$tx_dir/status" && -f "$tx_dir/rollback-unit" ]] \
    || die 66 "找不到完整加固事务：$tx_id"
  [[ "$(stat -c %u "$tx_dir")" == 0 ]] || die 76 "加固事务不属于 root。"
  if find "$tx_dir" -xdev -type f -perm /077 -print -quit 2>/dev/null | grep -q .; then
    die 76 "加固事务文件权限不安全。"
  fi
  tx_action="$(sed -n 's/^action=//p' "$tx_dir/status")"
  tx_status="$(sed -n 's/^status=//p' "$tx_dir/status")"
  [[ "$tx_action" == "$action" ]] || die 76 "事务动作与记录动作不一致。"

  guard_dir="$(find_guard_dir "$tx_id")" || die 66 "找不到该事务的第二会话证据。"
  [[ "$(stat -c %u "$guard_dir")" == 0 ]] || die 76 "第二会话证据不属于 root。"
  if find "$guard_dir" -xdev -type f -perm /077 -print -quit 2>/dev/null | grep -q .; then
    die 76 "第二会话证据权限不安全。"
  fi
  initial="$(cat "$guard_dir/initial-context.tsv")"
  guard_status="$(sed -n 's/^status=//p' "$guard_dir/status")"
  guard_admin="$(sed -n 's/^admin=//p' "$guard_dir/status")"
  [[ "$guard_admin" == "$(read_meta "$run_dir" admin)" ]] \
    || die 65 "动作使用的备用管理员与本次 VM 验收不一致。"
  parse_ssh_context "$(tr '\t' ' ' <<<"$initial")" >/dev/null \
    || die 76 "原 SSH 会话证据无效。"
  unit="$(cat "$tx_dir/rollback-unit")"
  [[ "$unit" == "vpsga-rollback-${tx_id,,}" ]] || die 76 "回滚 unit 与事务不匹配。"

  case "$path" in
    confirm)
      [[ "$tx_status" == committed ]] || die 65 "确认路径事务状态不是 committed：$tx_status"
      [[ "$guard_status" == confirmed && -f "$guard_dir/confirmed-context.tsv" ]] \
        || die 65 "缺少已确认的第二 SSH 会话证据。"
      confirmed="$(cat "$guard_dir/confirmed-context.tsv")"
      parse_ssh_context "$(tr '\t' ' ' <<<"$confirmed")" >/dev/null \
        || die 76 "第二 SSH 会话证据无效。"
      [[ "$confirmed" != "$initial" ]] || die 76 "第二 SSH 会话与原会话相同。"
      current="$(assert_new_admin_session "$(read_meta "$run_dir" admin)" "$initial" "$confirmed")"
      assert_timer_inactive "$unit"
      ;;
    timeout)
      [[ "$tx_status" == rolled_back ]] || die 65 "超时路径事务状态不是 rolled_back：$tx_status"
      grep -Fqx 'reason=第二终端确认超时，延时自动回滚' "$tx_dir/status" \
        || die 65 "事务不是由五分钟确认超时自动回滚。"
      [[ "$guard_status" == awaiting_second_connection && ! -e "$guard_dir/confirmed-context.tsv" ]] \
        || die 65 "超时路径不应存在成功的第二会话确认。"
      current="$(assert_new_admin_session "$(read_meta "$run_dir" admin)" "$initial")"
      assert_timer_inactive "$unit"
      result="$("$SYSTEMCTL_BIN" show "$unit.service" --property=Result --value 2>/dev/null || true)"
      [[ "$result" == success ]] || die 74 "自动回滚 systemd service 未成功：${result:-未知}"
      started="$(sed -n 's/^started_at=//p' "$tx_dir/status")"
      finished="$(sed -n 's/^finished_at=//p' "$tx_dir/status")"
      started="$(date -d "$started" +%s 2>/dev/null || true)"
      finished="$(date -d "$finished" +%s 2>/dev/null || true)"
      [[ "$started" =~ ^[0-9]+$ && "$finished" =~ ^[0-9]+$ ]] || die 76 "事务时间证据无效。"
      elapsed=$((finished - started))
      ((elapsed >= 270)) || die 65 "回滚发生得过早（${elapsed}s），不能证明五分钟 timer。"
      ;;
  esac

  evidence="$run_dir/cases/${action}-${path}.txt"
  cat >"$evidence" <<EOF
action=$action
path=$path
result=PASS
recorded_at=$(date -Is)
transaction=$tx_id
transaction_status=$tx_status
guard_status=$guard_status
session_sha256=$(printf '%s' "$current" | sha256sum | awk '{print $1}')
EOF
  chmod 0600 -- "$evidence"
  printf '%s\t%s\tPASS\t%s\t%s\n' "$action" "$path" "$(date -Is)" "$tx_id" \
    >>"$run_dir/cases.tsv"
  echo "已记录通过：$action / $path"
}

case_result() {
  local run_dir="$1" action="$2" path="$3"
  if awk -F'\t' -v action="$action" -v path="$path" \
    '$1 == action && $2 == path && $3 == "PASS" { found=1 } END { exit(found ? 0 : 1) }' \
    "$run_dir/cases.tsv"; then
    printf 'PASS'
  else
    printf 'PENDING'
  fi
}

print_status() {
  local run_dir="$1" action path passed=0 total=0 result
  printf '真实 VM 验收：%s %s，候选版本 %s\n' \
    "$(read_meta "$run_dir" os_id)" "$(read_meta "$run_dir" os_version)" \
    "$(read_meta "$run_dir" candidate_version)"
  for action in "${ACTIONS[@]}"; do
    for path in "${PATHS[@]}"; do
      result="$(case_result "$run_dir" "$action" "$path")"
      printf '  %-9s %-7s %s\n' "$action" "$path" "$result"
      total=$((total + 1))
      [[ "$result" == PASS ]] && passed=$((passed + 1))
    done
  done
  printf '进度：%d/%d\n' "$passed" "$total"
  [[ "$passed" -eq "$total" ]]
}

cmd_status() {
  local run_dir
  require_root
  run_dir="$(load_run "${1:-}")"
  print_status "$run_dir" || true
}

cmd_finish() {
  local run_id="${1:-}" run_dir expected summary archive action path
  require_root
  require_disposable_ack
  run_dir="$(load_run "$run_id")"
  [[ ! -f "$run_dir/finished" ]] || die 65 "该验收已经结束。"
  expected="$(read_meta "$run_dir" candidate_version)"
  assert_candidate_installed "$expected" "$(read_meta "$run_dir" candidate_commit)"
  print_status "$run_dir" >/dev/null || die 65 "16 条真实连接路径尚未全部通过。"
  capture_command "$run_dir/final-doctor.txt" "$VPSGA_BIN" doctor \
    || die 69 "最终 vpsga doctor 未通过。"

  printf 'finished_at=%s\n' "$(date -Is)" >"$run_dir/finished"
  chmod 0600 -- "$run_dir/finished"
  summary="$run_dir/summary.md"
  {
    echo "# VPS Guard Audit v6 真实 VM 验收摘要"
    echo
    printf -- '- 系统：%s %s\n' "$(read_meta "$run_dir" os_id)" "$(read_meta "$run_dir" os_version)"
    printf -- '- 候选版本：%s\n' "$expected"
    printf -- '- 候选提交：%s\n' "$(read_meta "$run_dir" candidate_commit)"
    printf -- '- 开始时间：%s\n' "$(read_meta "$run_dir" started_at)"
    printf -- '- 完成时间：%s\n' "$(sed -n 's/^finished_at=//p' "$run_dir/finished")"
    echo '- 控制台：已人工确认'
    echo '- 快照：已记录（标识仅保存为 SHA-256）'
    echo
    echo "| 动作 | 第二终端确认 | 五分钟超时回滚 |"
    echo "|---|---:|---:|"
    for action in "${ACTIONS[@]}"; do
      printf '| %s | %s | %s |\n' "$action" \
        "$(case_result "$run_dir" "$action" confirm)" "$(case_result "$run_dir" "$action" timeout)"
    done
    echo
    echo "摘要不包含 IP、端口、用户名、主机名或快照名称；原始证据应仅私下保存。"
  } >"$summary"
  chmod 0600 -- "$summary"

  (
    cd "$run_dir"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
    chmod 0600 SHA256SUMS
  )
  archive="$STATE_ROOT/${run_id}-evidence.tar.gz"
  tar -C "$STATE_ROOT" -czf "$archive" "$run_id"
  chmod 0600 -- "$archive"
  echo "真实 VM 验收完成。"
  echo "脱敏摘要：$summary"
  echo "私有证据包：$archive"
}

case "${1:-}" in
  start) shift; cmd_start "$@" ;;
  record) shift; cmd_record "$@" ;;
  status) shift; cmd_status "$@" ;;
  finish) shift; cmd_finish "$@" ;;
  -h|--help|help|"") usage ;;
  *) die 64 "未知命令：$1" ;;
esac
