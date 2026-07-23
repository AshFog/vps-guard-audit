#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo 'VM acceptance tests require root or sudo.' >&2
    exit 77
  }
  exec sudo bash "$0"
fi

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin" "$work/state" "$work/hardening" "$work/guards" "$work/installed"
cp "$project_dir/vps-guard-audit.sh" "$work/installed/vps-guard-audit.sh"
(
  cd "$work/installed"
  sha256sum vps-guard-audit.sh >MANIFEST.sha256
)

cat >"$work/os-release" <<'EOF'
ID=ubuntu
VERSION_ID="24.04"
EOF

cat >"$work/bin/vpsga" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in
  --version) bash "$project_dir/vps-guard-audit.sh" --version ;;
  doctor) echo '安装状态正常。' ;;
  connection-check)
    echo '连接敏感加固前置检查'
    echo '  - milo'
    ;;
  firewall-plan) echo '防火墙端口计划' ;;
  workload-plan) echo '业务用途检查（只读）' ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$work/bin/vpsga"

cat >"$work/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  is-active) exit 3 ;;
  show) echo success ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$work/bin/systemctl"

helper="$project_dir/tests/manual-vm-acceptance.sh"
common_env=(
  "PATH=$work/bin:$PATH"
  "VPSGA_VM_ACCEPTANCE_ROOT=$work/state"
  "VPSGA_HARDENING_STATE_ROOT=$work/hardening"
  "VPSGA_CONNECTION_GUARD_ROOT=$work/guards"
  "VPSGA_VM_ACCEPTANCE_OS_RELEASE=$work/os-release"
  "VPSGA_VM_ACCEPTANCE_BIN=$work/bin/vpsga"
  "VPSGA_VM_ACCEPTANCE_SYSTEMCTL=$work/bin/systemctl"
  "VPSGA_VM_ACCEPTANCE_INSTALLED_ROOT=$work/installed"
  "VPSGA_VM_ACCEPTANCE_TEST_MODE=1"
  "VPSGA_VM_ACCEPTANCE_TEST_VERIFY_INSTALL=1"
  "VPSGA_VM_ACCEPTANCE_DISPOSABLE=YES"
)

if env "${common_env[@]}" SSH_CONNECTION='198.51.100.20 50000 203.0.113.10 2222' \
  bash "$helper" start milo snap-before-test >/dev/null 2>&1; then
  echo 'start must require an explicit console acknowledgement' >&2
  exit 1
fi

start_output="$(env "${common_env[@]}" VPSGA_VM_ACCEPTANCE_CONSOLE=READY \
  SSH_CONNECTION='198.51.100.20 50000 203.0.113.10 2222' \
  bash "$helper" start milo snap-before-test)"
run_id="$(sed -n 's/^RUN_ID=//p' <<<"$start_output")"
[[ "$run_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+-[0-9]+$ ]]

index=0
for action in HARD-2001 HARD-2002 HARD-2003 HARD-2004 HARD-2005 HARD-2006 HARD-2007 HARD-2008; do
  for path in confirm timeout; do
    index=$((index + 1))
    tx_id="20260723T000000Z-${action}-123-${index}"
    tx_dir="$work/hardening/$tx_id"
    token="$(printf '%032x' "$index")"
    guard_dir="$work/guards/$token"
    mkdir -p "$tx_dir" "$guard_dir"
    printf '%s\n' "vpsga-rollback-${tx_id,,}" >"$tx_dir/rollback-unit"
    : >"$tx_dir/manifest.tsv"
    : >"$tx_dir/after.tsv"
    printf '198.51.100.20\t50000\t203.0.113.10\t2222\n' >"$guard_dir/initial-context.tsv"
    if [[ "$path" == confirm ]]; then
      cat >"$tx_dir/status" <<EOF
action=$action
started_at=2026-07-23T00:00:00+00:00
status=committed
finished_at=2026-07-23T00:01:00+00:00
EOF
      cat >"$guard_dir/status" <<EOF
admin=milo
transaction=$tx_id
status=confirmed
EOF
      printf '198.51.100.20\t50001\t203.0.113.10\t2222\n' >"$guard_dir/confirmed-context.tsv"
    else
      cat >"$tx_dir/status" <<EOF
action=$action
started_at=2026-07-23T00:00:00+00:00
status=rolled_back
finished_at=2026-07-23T00:05:01+00:00
reason=第二终端确认超时，延时自动回滚
EOF
      cat >"$guard_dir/status" <<EOF
admin=milo
transaction=$tx_id
status=awaiting_second_connection
EOF
    fi
    chmod 0700 "$tx_dir" "$guard_dir"
    chmod 0600 "$tx_dir"/* "$guard_dir"/*

    if [[ "$index" -eq 1 ]]; then
      printf '\n# changed after installation\n' >>"$work/installed/vps-guard-audit.sh"
      if env "${common_env[@]}" SUDO_USER=milo \
        SSH_CONNECTION='198.51.100.20 50002 203.0.113.10 2222' \
        bash "$helper" record "$run_id" "$action" "$path" "$tx_id" >/dev/null 2>&1; then
        echo 'candidate and installed content mismatch must be rejected' >&2
        exit 1
      fi
      cp "$project_dir/vps-guard-audit.sh" "$work/installed/vps-guard-audit.sh"
      if env "${common_env[@]}" SUDO_USER=milo \
        SSH_CONNECTION='198.51.100.20 50000 203.0.113.10 2222' \
        bash "$helper" record "$run_id" "$action" "$path" "$tx_id" >/dev/null 2>&1; then
        echo 'the original SSH session must not record a passing case' >&2
        exit 1
      fi
      if env "${common_env[@]}" SUDO_USER=root \
        SSH_CONNECTION='198.51.100.20 50002 203.0.113.10 2222' \
        bash "$helper" record "$run_id" "$action" "$path" "$tx_id" >/dev/null 2>&1; then
        echo 'the wrong administrator must not record a passing case' >&2
        exit 1
      fi
    fi

    env "${common_env[@]}" SUDO_USER=milo \
      SSH_CONNECTION='198.51.100.20 50002 203.0.113.10 2222' \
      bash "$helper" record "$run_id" "$action" "$path" "$tx_id" >/dev/null
  done
done

status_output="$(env "${common_env[@]}" bash "$helper" status "$run_id")"
grep -q '进度：16/16' <<<"$status_output"

finish_output="$(env "${common_env[@]}" \
  SSH_CONNECTION='198.51.100.20 50003 203.0.113.10 2222' \
  bash "$helper" finish "$run_id")"
summary="$(sed -n 's/^脱敏摘要：//p' <<<"$finish_output")"
archive="$(sed -n 's/^私有证据包：//p' <<<"$finish_output")"
[[ -f "$summary" && "$(stat -c %a "$summary")" == 600 ]]
[[ -f "$archive" && "$(stat -c %a "$archive")" == 600 ]]
[[ "$(grep -c '| HARD-200[1-8] | PASS | PASS |' "$summary")" -eq 8 ]]
if grep -Eq '198\.51\.100|203\.0\.113|milo|2222|snap-before-test' "$summary"; then
  echo 'the public summary contains sensitive test context' >&2
  exit 1
fi

echo 'Manual VM acceptance helper tests passed.'
