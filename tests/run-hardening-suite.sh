#!/usr/bin/env bash
set -euo pipefail

# Sensitive rollback tests intentionally require root-owned transaction state.
# The suite only uses temporary system roots and fake service/network commands,
# so non-root CI runners can safely execute the whole isolated suite via sudo.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || {
    echo 'The isolated hardening suite requires root or sudo.' >&2
    exit 77
  }
  exec sudo bash "$0"
fi

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

expected_actions=(
  HARD-1001 HARD-1002 HARD-1003 HARD-1004 HARD-1005
  HARD-1006 HARD-1007 HARD-1008 HARD-1009 HARD-1010
  HARD-2001 HARD-2002 HARD-2003 HARD-2004 HARD-2005
  HARD-2006 HARD-2007 HARD-2008
)

[[ "$(grep -c 'register_hardening_action "HARD-' lib/hardening-registry.sh)" -eq 18 ]]
for action in "${expected_actions[@]}"; do
  grep -Fq "register_hardening_action \"$action\"" lib/hardening-registry.sh || {
    echo "加固注册表缺少 $action" >&2
    exit 1
  }
  grep -Eqs "(execute_hardening_action|stage_sensitive_hardening_action)[[:space:]]+$action([[:space:]]|$)" \
    tests/test-hardening-*.sh || {
      echo "动作测试未实际调用 $action" >&2
      exit 1
    }
done

tests=(
  tests/test-hardening-filesystem.sh
  tests/test-hardening-ssh.sh
  tests/test-hardening-system.sh
  tests/test-connection-safety.sh
  tests/test-hardening-sensitive-ssh.sh
  tests/test-hardening-network.sh
  tests/test-hardening-workloads.sh
)

for test_script in "${tests[@]}"; do
  bash "$test_script"
done

echo 'All 18 hardening actions have executable test coverage.'
