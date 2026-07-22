#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="/usr/local/lib/vps-guard-audit"
CURRENT="$INSTALL_ROOT/current"
ARCHIVE_URL="https://github.com/AshFog/vps-guard-audit/archive/refs/heads/main.tar.gz"

latest_html() {
  local path="${1:-$PWD}"
  if [[ -f "$path" && "$path" == *.html ]]; then
    readlink -f "$path" 2>/dev/null || printf '%s\n' "$path"
    return 0
  fi
  [[ -d "$path" ]] || { echo "Directory not found: $path" >&2; return 66; }
  find "$path" -maxdepth 1 -type f -name 'vpsga-*.html' -printf '%T@\t%p\n' 2>/dev/null \
    | sort -nr | head -n1 | cut -f2-
}

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

cmd_open() {
  local report
  report="$(latest_html "${1:-$PWD}")"
  [[ -n "$report" && -f "$report" ]] || { echo "No vpsga HTML report was found." >&2; exit 66; }
  if command -v xdg-open >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    xdg-open "$report" >/dev/null 2>&1 &
    echo "Opened: file://$report"
  elif command -v gio >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    gio open "$report" >/dev/null 2>&1 &
    echo "Opened: file://$report"
  else
    echo "HTML report: file://$report"
    echo "No local graphical browser was detected. For an SSH session, use:"
    echo "  vpsga serve \"$(dirname "$report")\""
  fi
}

cmd_serve() {
  local path="${1:-$PWD}" port="${2:-8765}" report dir name python_bin
  [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1024 && port <= 65535)) || {
    echo "Port must be an integer between 1024 and 65535." >&2
    exit 64
  }
  report="$(latest_html "$path")"
  [[ -n "$report" && -f "$report" ]] || { echo "No vpsga HTML report was found." >&2; exit 66; }
  dir="$(dirname "$report")"
  name="$(basename "$report")"
  if command -v python3 >/dev/null 2>&1; then python_bin=python3; elif command -v python >/dev/null 2>&1; then python_bin=python; else
    echo "Python is required for the local report server." >&2
    exit 69
  fi

  echo "Serving reports from: $dir"
  echo "Open: http://127.0.0.1:$port/$name"
  echo "The server listens on 127.0.0.1 only and is not exposed publicly."
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    echo
    echo "This is an SSH session. On your own computer, create a tunnel first:"
    echo "  ssh -L $port:127.0.0.1:$port USER@SERVER"
    echo "Then open the URL above in your local browser."
  fi
  echo "Press Ctrl+C to stop."
  cd "$dir"
  exec "$python_bin" -m http.server "$port" --bind 127.0.0.1
}

usage() {
  cat <<'EOF_USAGE'
VPS Guard Audit management commands:
  vpsga doctor                 Check the installed program
  vpsga update                 Install the current upstream version
  vpsga open [FILE|DIR]        Open the latest HTML report on a local desktop
  vpsga serve [FILE|DIR] [PORT]
                               Serve the latest HTML report on 127.0.0.1
  vpsga uninstall              Remove the installed program
EOF_USAGE
}

case "${1:-}" in
  doctor) shift; cmd_doctor "$@" ;;
  update) shift; cmd_update "$@" ;;
  open) shift; cmd_open "$@" ;;
  serve) shift; cmd_serve "$@" ;;
  uninstall) shift; cmd_uninstall "$@" ;;
  -h|--help|help|"") usage ;;
  *) echo "Unknown management command: $1" >&2; usage >&2; exit 64 ;;
esac
