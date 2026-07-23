#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
audit="$project_dir/vps-guard-audit.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo '配置安全回归测试必须以 root 身份运行。' >&2
  exit 77
}

safe_config="$work/safe.conf"
cat >"$safe_config" <<'EOF'
TRUSTED_LOGIN_IPS=""
CUSTOM_ALLOWED_TCP_PORTS="80 443"
CUSTOM_ALLOWED_UDP_PORTS="443"
EXPECTED_UID0_USERS="root"
PROFILE="web"
POLICY="strict"
DEPTH="quick"
MAX_LIST_ITEMS=7
EOF
chmod 0600 "$safe_config"

valid_output="$work/valid-output"
set +e
env VPSGA_LOCK_DIR="$work/valid-lock" bash "$audit" \
  --config "$safe_config" \
  --format json \
  --output-dir "$valid_output" \
  --no-history \
  --no-update-check \
  --quiet >"$work/valid.log" 2>&1
valid_rc=$?
set -e
((valid_rc >= 0 && valid_rc <= 2))

[[ -d "$valid_output" ]]
valid_report="$(find "$valid_output" -maxdepth 1 -type f -name 'vpsga-*.json' -print -quit)"
[[ -n "$valid_report" ]]
[[ "$(find "$valid_output" -maxdepth 1 -type f | wc -l)" -eq 1 ]]
grep -Fq '  "profile": "web",' "$valid_report"
grep -Fq '  "policy": "strict",' "$valid_report"
grep -Fq '  "depth": "quick",' "$valid_report"
if [[ "${SUDO_UID:-}" =~ ^[0-9]+$ && "${SUDO_GID:-}" =~ ^[0-9]+$ && "$SUDO_UID" -ne 0 ]]; then
  [[ "$(stat -c %u "$valid_output")" == "$SUDO_UID" ]]
  [[ "$(stat -c %g "$valid_output")" == "$SUDO_GID" ]]
  [[ "$(stat -c %u "$valid_report")" == "$SUDO_UID" ]]
  [[ "$(stat -c %g "$valid_report")" == "$SUDO_GID" ]]
fi

assert_config_rejected() {
  local label="$1" config="$2" expected_rc="$3" expected_message="$4"
  local output_dir="$work/$label-output" log="$work/$label.log" rc
  mkdir -p "$output_dir"

  set +e
  env VPSGA_LOCK_DIR="$work/$label-lock" bash "$audit" \
    --config "$config" \
    --format both \
    --output-dir "$output_dir" \
    --no-history \
    --no-update-check \
    --quiet >"$log" 2>&1
  rc=$?
  set -e

  [[ "$rc" -eq "$expected_rc" ]]
  grep -Fq "$expected_message" "$log"
  ! grep -Fq '即将开始全面安全检测' "$log"
  [[ "$(find "$output_dir" -maxdepth 1 -type f | wc -l)" -eq 0 ]]
  [[ ! -e "$work/$label-lock" ]]
}

unsafe_config="$work/unsafe.conf"
cp "$safe_config" "$unsafe_config"
chmod 0666 "$unsafe_config"
assert_config_rejected \
  unsafe "$unsafe_config" 76 \
  '配置文件可被组用户或其他用户修改'

symlink_config="$work/config-link.conf"
ln -s "$safe_config" "$symlink_config"
assert_config_rejected \
  symlink "$symlink_config" 76 \
  '拒绝加载符号链接配置文件'

invalid_policy="$work/invalid-policy.conf"
printf 'POLICY="maximum"\n' >"$invalid_policy"
chmod 0600 "$invalid_policy"
assert_config_rejected \
  invalid-policy "$invalid_policy" 64 \
  '配置文件中的 POLICY 无效'

invalid_limit="$work/invalid-limit.conf"
printf 'MAX_LIST_ITEMS=0\n' >"$invalid_limit"
chmod 0600 "$invalid_limit"
assert_config_rejected \
  invalid-limit "$invalid_limit" 64 \
  'MAX_LIST_ITEMS 必须是正整数'

echo 'Configuration validation runs before report initialization.'
