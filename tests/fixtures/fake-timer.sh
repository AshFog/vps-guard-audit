#!/usr/bin/env bash
set -euo pipefail
printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}" >>"${VPSGA_TEST_TIMER_LOG:?}"
