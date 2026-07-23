#!/usr/bin/env bash
set -euo pipefail

state="${VPSGA_TEST_SERVICE_UNITS_STATE:?}"
fail_file="${VPSGA_SYSTEM_ROOT:?}/fail-service-command"
[[ ! -f "$fail_file" || "$(cat "$fail_file")" != "$*" ]] || exit 1

unit_record() {
  awk -F '\t' -v unit="$1" '$1 == unit { print; found=1; exit } END { if (!found) exit 1 }' "$state"
}

set_field() {
  local unit="$1" field="$2" value="$3" tmp="$state.tmp"
  awk -F '\t' -v OFS='\t' -v unit="$unit" -v field="$field" -v value="$value" '
    $1 == unit { $field=value; found=1 }
    { print }
    END { if (!found) exit 1 }
  ' "$state" >"$tmp" || { rm -f -- "$tmp"; return 1; }
  mv -- "$tmp" "$state"
}

command_name="${1:-}"; shift || true
case "$command_name" in
  show)
    unit="${1:?}"; record="$(unit_record "$unit")"
    if [[ "$*" == *'LoadState'* ]]; then cut -f4 <<<"$record"; else printf '%s\n' "$record"; fi
    ;;
  is-active)
    quiet=0
    [[ "${1:-}" == --quiet ]] && { quiet=1; shift; }
    record="$(unit_record "${1:?}")"
    if [[ "$(cut -f2 <<<"$record")" == 1 ]]; then
      [[ "$quiet" -eq 1 ]] || printf 'active\n'
      exit 0
    fi
    [[ "$quiet" -eq 1 ]] || printf 'inactive\n'
    exit 3
    ;;
  is-enabled)
    [[ "${1:-}" == --quiet ]] && shift
    record="$(unit_record "${1:?}")"
    enabled="$(cut -f3 <<<"$record")"
    printf '%s\n' "$enabled"
    [[ "$enabled" == enabled || "$enabled" == enabled-runtime ]]
    ;;
  enable|disable)
    runtime=0
    [[ "${1:-}" == --runtime ]] && { runtime=1; shift; }
    unit="${1:?}"
    if [[ "$command_name" == enable ]]; then
      [[ "$runtime" -eq 1 ]] && enabled=enabled-runtime || enabled=enabled
    else
      enabled=disabled
    fi
    set_field "$unit" 3 "$enabled"
    ;;
  stop) set_field "${1:?}" 2 0 ;;
  start) set_field "${1:?}" 2 1 ;;
  *) echo "unsupported fake service systemctl command: $command_name $*" >&2; exit 64 ;;
esac
