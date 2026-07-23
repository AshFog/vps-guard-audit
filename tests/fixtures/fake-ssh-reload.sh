#!/usr/bin/env bash
set -u
main="${1:?}"
root="${main%/etc/ssh/sshd_config}"
if [[ -e "$root/fail-next-reload" ]]; then
  rm -f -- "$root/fail-next-reload"
  exit 1
fi
exit 0
