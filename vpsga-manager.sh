#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="/usr/local/lib/vps-guard-audit"
CURRENT="$INSTALL_ROOT/current"
ARCHIVE_URL="https://github.com/AshFog/vps-guard-audit/archive/refs/heads/main.tar.gz"

need_root() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    return 0
  fi
  command -v sudo >/dev/null 2>&1 || {
    echo "Root privileges are required and sudo is not available." >&2
    exit 77
  }
  exec sudo "$0" "$@"
}

cmd_doctor() {
  local failed=0 target version
  echo "VPS Guard Audit installation check"
  if [[ -L "$CURRENT" && -d "$CURRENT" ]]; then
    echo "[OK] Current release: $(readlink -f "$CURRENT")"
  else
    echo "[FAIL] Missing or invalid current release link: $CURRENT"
    failed=1
  fi
  target="$CURRENT/vps-guard-audit.sh"
  if [[ -x "$target" ]]; then
    version="$("$target" --version 2>/dev/null || true)"
    echo "[OK] Audit executable: $target"
    echo "[OK] Version: ${version:-unknown}"
  else
    echo "[FAIL] Audit executable is missing: $target"
    failed=1
  fi
  for module in audit-platform.sh audit-access.sh audit-system.sh audit-containers.sh report-guidance-zh.sh report-guidance-en.sh report-guidance.sh report-output.sh audit-summary.sh; do
    if [[ -r "$CURRENT/lib/$module" ]]; then
      echo "[OK] Module: $module"
    else
      echo "[FAIL] Missing module: $module"
      failed=1
    fi
  done
  command -v vpsga >/dev/null 2>&1 && echo "[OK] Command in PATH: $(command -v vpsga)" || { echo "[FAIL] vpsga is not in PATH"; failed=1; }
  ((failed == 0)) || exit 1
}

cmd_update() {
  need_root update
  local tmp archive root installer
  command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 69; }
  command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 69; }
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  archive="$tmp/vpsga.tar.gz"
  echo "Downloading the current VPS Guard Audit source..."
  curl --fail --show-error --location --connect-timeout 15 --max-time 120 --retry 2 --retry-delay 1 "$ARCHIVE_URL" -o "$archive"
  tar -xzf "$archive" -C "$tmp"
  root="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d -name 'vps-guard-audit-*' -print -quit)"
  installer="$root/install.sh"
  [[ -f "$installer" ]] || { echo "Downloaded package is incomplete" >&2; exit 69; }
  bash "$installer"
  echo "Update completed. Current version: $(/usr/local/bin/vpsga --version)"
}

cmd_uninstall() {
  need_root uninstall
  local answer keep_history="yes" history_tmp=""
  if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    echo "An interactive terminal is required for uninstall." >&2
    exit 65
  fi
  echo "This removes the installed VPS Guard Audit program and vpsga command." >/dev/tty
  printf "Type UNINSTALL to continue: " >/dev/tty
  IFS= read -r answer </dev/tty
  [[ "$answer" == UNINSTALL ]] || { echo "Cancelled."; exit 0; }

  if [[ -d /var/lib/vps-guard-audit/history ]]; then
    printf "Keep audit history? [Y/n]: " >/dev/tty
    IFS= read -r answer </dev/tty
    case "$answer" in n|N|no|NO) keep_history="no" ;; esac
    if [[ "$keep_history" == yes ]]; then
      history_tmp="$(mktemp -d)"
      cp -a /var/lib/vps-guard-audit/history "$history_tmp/"
    fi
  fi

  rm -f /usr/local/bin/vpsga /usr/local/sbin/vps-guard-audit
  rm -rf "$INSTALL_ROOT"
  if [[ "$keep_history" == yes && -n "$history_tmp" && -d "$history_tmp/history" ]]; then
    install -d -m 0700 /var/lib/vps-guard-audit
    rm -rf /var/lib/vps-guard-audit/history
    cp -a "$history_tmp/history" /var/lib/vps-guard-audit/history
    echo "Program removed. History kept at /var/lib/vps-guard-audit/history"
  else
    rm -rf /var/lib/vps-guard-audit
    echo "VPS Guard Audit has been removed."
  fi
}

usage() {
  cat <<'EOF_USAGE'
VPS Guard Audit management commands:
  vpsga doctor                 Check the installed program
  vpsga update                 Install the current upstream version
  vpsga uninstall              Remove the installed program
EOF_USAGE
}

case "${1:-}" in
  doctor) shift; cmd_doctor "$@" ;;
  update) shift; cmd_update "$@" ;;
  uninstall) shift; cmd_uninstall "$@" ;;
  -h|--help|help|"") usage ;;
  *) echo "Unknown management command: $1" >&2; usage >&2; exit 64 ;;
esac
