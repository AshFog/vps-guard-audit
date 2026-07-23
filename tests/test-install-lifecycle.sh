#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
expected_version="$(bash "$project_dir/vps-guard-audit.sh" --version)"
legacy_archive="${VPSGA_V5_ARCHIVE:-}"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo '安装生命周期验收必须以 root 身份在一次性系统中运行。' >&2
  exit 77
}
[[ "${VPSGA_E2E_DISPOSABLE:-}" == YES ]] || {
  echo '拒绝修改系统：仅可在一次性 VM/容器中设置 VPSGA_E2E_DISPOSABLE=YES。' >&2
  exit 65
}
[[ -z "${SSH_CONNECTION:-}" && -z "${SSH_CLIENT:-}" ]] || {
  echo '拒绝在 SSH 会话中运行破坏性安装生命周期验收。' >&2
  exit 65
}
[[ -r /etc/os-release ]] || { echo '无法识别测试系统。' >&2; exit 69; }
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || {
  echo "只接受一次性 Ubuntu/Debian 测试系统；当前：${ID:-unknown}" >&2
  exit 69
}
[[ -f "$legacy_archive" && ! -L "$legacy_archive" ]] || {
  echo '缺少由 git archive v5.0.0 生成的 VPSGA_V5_ARCHIVE。' >&2
  exit 66
}
if [[ -n "${VPSGA_EXPECTED_VERSION:-}" && "$expected_version" != "$VPSGA_EXPECTED_VERSION" ]]; then
  echo "源码版本不符合预期：$expected_version != $VPSGA_EXPECTED_VERSION" >&2
  exit 65
fi

clean_program() {
  rm -rf -- /usr/local/lib/vps-guard-audit
  rm -f -- /usr/local/bin/vpsga /usr/local/sbin/vps-guard-audit
}

run_quick_audit() {
  local label="$1" output="$work/reports-$1" report rc
  mkdir -p "$output"
  set +e
  env VPSGA_LOCK_DIR="$work/lock-$label" /usr/local/bin/vpsga \
    --depth quick --profile general --no-history --no-update-check \
    --format json --output-dir "$output" --quiet
  rc=$?
  set -e
  ((rc >= 0 && rc <= 2))
  report="$(find "$output" -maxdepth 1 -type f -name 'vpsga-*.json' -print -quit)"
  [[ -n "$report" ]]
  grep -Fq "  \"version\": \"$expected_version\"," "$report"
  grep -Fq '  "schema_version": "2.0",' "$report"
}

echo "Testing $expected_version on ${PRETTY_NAME:-$ID}"
clean_program
rm -rf -- /var/lib/vps-guard-audit

# Fresh installation of the candidate.
bash "$project_dir/install.sh"
[[ "$(/usr/local/bin/vpsga --version)" == "$expected_version" ]]
[[ "$(readlink -f /usr/local/lib/vps-guard-audit/current)" == \
  "/usr/local/lib/vps-guard-audit/releases/$expected_version" ]]
/usr/local/bin/vpsga doctor >/dev/null
run_quick_audit fresh

set +e
env VPSGA_LOCK_DIR="$work/lock-plan" /usr/local/bin/vpsga plan \
  --depth quick --profile general --no-history --no-update-check \
  --format json --output-dir "$work" --quiet >"$work/plan.txt"
plan_rc=$?
set -e
((plan_rc >= 0 && plan_rc <= 2))
grep -q '中文加固计划（只读预览）' "$work/plan.txt"

# Install the real v5.0.0 tag, create persistent state, then upgrade through the
# same local installer path used by `vpsga update` after it downloads a release.
clean_program
mkdir -p "$work/v5"
tar -xf "$legacy_archive" -C "$work/v5"
bash "$work/v5/install.sh" >/dev/null
[[ "$(/usr/local/bin/vpsga --version)" == 5.0.0 ]]
mkdir -p /var/lib/vps-guard-audit
printf 'preserve-across-upgrade\n' >/var/lib/vps-guard-audit/e2e-state-sentinel
chmod 0600 /var/lib/vps-guard-audit/e2e-state-sentinel

bash "$project_dir/install.sh"
[[ "$(/usr/local/bin/vpsga --version)" == "$expected_version" ]]
[[ -d /usr/local/lib/vps-guard-audit/releases/5.0.0 ]]
[[ "$(cat /var/lib/vps-guard-audit/e2e-state-sentinel)" == preserve-across-upgrade ]]
/usr/local/bin/vpsga doctor >/dev/null
run_quick_audit upgraded

[[ "$(stat -c %U /usr/local/lib/vps-guard-audit/current/vps-guard-audit.sh)" == root ]]
[[ "$(stat -c %a /usr/local/lib/vps-guard-audit/current/MANIFEST.sha256)" == 644 ]]
(cd /usr/local/lib/vps-guard-audit/current && sha256sum -c --quiet MANIFEST.sha256)

echo "Install and v5-to-$expected_version upgrade lifecycle passed on ${ID} ${VERSION_ID:-unknown}."
