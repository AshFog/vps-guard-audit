#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  test) exit 0 ;;
  status) echo 'Jail list: sshd' ;;
  *) exit 64 ;;
esac
