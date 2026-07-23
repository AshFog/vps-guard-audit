#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == unattended-upgrades ]]
[[ -f "$VPSGA_SYSTEM_ROOT/unattended-upgrades.installed" ]]
echo 'install ok installed'
