#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'install -y unattended-upgrades' ]]
: >"$VPSGA_SYSTEM_ROOT/unattended-upgrades.installed"
