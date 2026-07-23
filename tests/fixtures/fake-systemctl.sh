#!/usr/bin/env bash
set -euo pipefail
state="${VPSGA_TEST_SERVICE_STATE:?}"
touch "$state"
case "${1:-}" in
  is-active)
    grep -q '^active=1$' "$state"
    ;;
  is-enabled)
    grep -q '^enabled=1$' "$state"
    ;;
  enable)
    sed -i 's/^enabled=.*/enabled=1/' "$state"
    [[ " $* " == *' --now '* ]] && sed -i 's/^active=.*/active=1/' "$state"
    ;;
  disable) sed -i 's/^enabled=.*/enabled=0/' "$state" ;;
  restart)
    [[ ! -e "${VPSGA_SYSTEM_ROOT:?}/fail-service" ]] || exit 1
    sed -i 's/^active=.*/active=1/' "$state"
    ;;
  stop) sed -i 's/^active=.*/active=0/' "$state" ;;
  *) echo "unsupported fake systemctl command: $*" >&2; exit 64 ;;
esac
