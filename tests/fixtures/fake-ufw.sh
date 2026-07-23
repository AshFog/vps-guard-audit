#!/usr/bin/env bash
set -euo pipefail
root="${VPSGA_SYSTEM_ROOT:?}"
state="$root/ufw-state"
rules="$root/etc/ufw/user.rules"
mkdir -p "$root/etc/ufw"
[[ -f "$state" ]] || printf 'inactive\n' >"$state"
[[ -f "$rules" ]] || : >"$rules"

if [[ "${1:-}" == status ]]; then
  current="$(cat "$state")"
  echo "Status: $current"
  if [[ "${2:-}" == verbose ]]; then
    echo "Default: deny (incoming), allow (outgoing), disabled (routed)"
    while IFS= read -r spec; do [[ -z "$spec" ]] || printf '%s ALLOW IN Anywhere\n' "$spec"; done <"$rules"
  elif [[ "${2:-}" == numbered ]]; then
    n=1
    while IFS= read -r spec; do
      [[ -z "$spec" ]] || { printf '[ %d] %s ALLOW IN Anywhere\n' "$n" "$spec"; n=$((n+1)); }
    done <"$rules"
  fi
  exit 0
fi
case "$*" in
  'default deny incoming'|'default allow outgoing'|'reload') exit 0 ;;
  '--force enable') printf 'active\n' >"$state" ;;
  '--force disable') printf 'inactive\n' >"$state" ;;
  allow\ *)
    spec="${2:?}"
    grep -Fqx "$spec" "$rules" 2>/dev/null || printf '%s\n' "$spec" >>"$rules"
    ;;
  --force\ delete\ *)
    number="${3:?}"
    awk -v wanted="$number" 'NF { n++; if (n != wanted) print }' "$rules" >"$rules.tmp"
    mv "$rules.tmp" "$rules"
    ;;
  *) echo "unsupported fake ufw command: $*" >&2; exit 64 ;;
esac
