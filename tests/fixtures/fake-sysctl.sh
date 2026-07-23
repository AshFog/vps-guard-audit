#!/usr/bin/env bash
set -euo pipefail
state="$VPSGA_SYSTEM_ROOT/sysctl-runtime.tsv"

get_value() {
  awk -F= -v key="$1" '$1 == key { value=$2; found=1 } END { if (found) print value; else exit 1 }' "$state"
}

set_value() {
  local key="${1%%=*}" value="${1#*=}" tmp="$state.tmp"
  awk -F= -v key="$key" -v value="$value" 'BEGIN { done=0 } $1 == key { print key "=" value; done=1; next } { print } END { if (!done) print key "=" value }' "$state" >"$tmp"
  mv "$tmp" "$state"
}

case "${1:-}" in
  -n)
    get_value "$2"
    ;;
  -w)
    set_value "$2"
    echo "$2"
    ;;
  -p)
    while IFS= read -r line; do
      [[ "$line" =~ ^[[:space:]]*# || -z "${line//[[:space:]]/}" ]] && continue
      line="${line//[[:space:]]/}"
      set_value "$line"
      if [[ -f "$VPSGA_SYSTEM_ROOT/fail-sysctl-apply" ]]; then
        rm -f "$VPSGA_SYSTEM_ROOT/fail-sysctl-apply"
        exit 1
      fi
    done <"$2"
    ;;
  *) exit 64 ;;
esac
