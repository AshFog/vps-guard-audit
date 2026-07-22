#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="/usr/local/lib/vps-guard-audit"
CURRENT="$INSTALL_ROOT/current"
ARCHIVE_URL="https://github.com/AshFog/vps-guard-audit/archive/refs/heads/main.tar.gz"
VPSGA_BIN="/usr/local/bin/vpsga"

REQUIRED_MODULES=(
  audit-platform.sh
  audit-access.sh
  audit-system.sh
  audit-containers.sh
  report-guidance-zh.sh
  report-guidance-en.sh
  report-guidance.sh
  report-output.sh
  audit-summary.sh
)

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
  local failed=0 target manager version resolved wrapper_version bad module
  echo "VPS Guard Audit installation check"

  if [[ -L "$CURRENT" ]]; then
    resolved="$(readlink -f "$CURRENT" 2>/dev/null || true)"
    if [[ -n "$resolved" && -d "$resolved" ]]; then
      echo "[OK] Current release: $resolved"
    else
      echo "[FAIL] Current release link is broken: $CURRENT"
      failed=1
    fi
  elif [[ -e "$CURRENT" ]]; then
    echo "[FAIL] Current path is a directory or regular file instead of a symlink: $CURRENT"
    echo "       Run the official one-command installer to migrate it safely."
    failed=1
    resolved=""
  else
    echo "[FAIL] Missing current release link: $CURRENT"
    failed=1
    resolved=""
  fi

  target="$CURRENT/vps-guard-audit.sh"
  manager="$CURRENT/vpsga-manager.sh"
  if [[ -x "$target" ]]; then
    version="$("$target" --version 2>/dev/null || true)"
    echo "[OK] Audit executable: $target"
    echo "[OK] Version: ${version:-unknown}"
  else
    echo "[FAIL] Audit executable is missing: $target"
    failed=1
    version=""
  fi

  if [[ -x "$manager" ]]; then
    echo "[OK] Manager executable: $manager"
  else
    echo "[FAIL] Manager executable is missing: $manager"
    failed=1
  fi

  for module in "${REQUIRED_MODULES[@]}"; do
    if [[ -r "$CURRENT/lib/$module" ]]; then
      echo "[OK] Module: $module"
    else
      echo "[FAIL] Missing module: $module"
      failed=1
    fi
  done

  if [[ -x "$target" && -x "$manager" ]]; then
    if bash -n "$target" "$manager" "$CURRENT/lib"/*.sh 2>/dev/null; then
      echo "[OK] Bash syntax"
    else
      echo "[FAIL] Bash syntax validation failed"
      failed=1
    fi
  fi

  if [[ -x "$VPSGA_BIN" ]]; then
    wrapper_version="$("$VPSGA_BIN" --version 2>/dev/null || true)"
    echo "[OK] Global command: $VPSGA_BIN"
    if [[ -n "$version" && "$wrapper_version" == "$version" ]]; then
      echo "[OK] Global command version: $wrapper_version"
    else
      echo "[FAIL] Global command version mismatch: ${wrapper_version:-unknown}"
      failed=1
    fi
  else
    echo "[FAIL] Global command is missing: $VPSGA_BIN"
    failed=1
  fi

  if command -v vpsga >/dev/null 2>&1; then
    echo "[OK] Command in PATH: $(command -v vpsga)"
  else
    echo "[FAIL] vpsga is not in PATH"
    failed=1
  fi

  if [[ -n "$resolved" && "$resolved" == "$INSTALL_ROOT/releases/"* ]]; then
    echo "[OK] Release path is inside the managed releases directory"
  elif [[ -n "$resolved" ]]; then
    echo "[FAIL] Current release points outside the managed releases directory: $resolved"
    failed=1
  fi

  if [[ -n "$resolved" && -d "$resolved" ]]; then
    bad="$(find "$resolved" -xdev -type f -perm /022 -print 2>/dev/null || true)"
    if [[ -z "$bad" ]]; then
      echo "[OK] Installed files are not group/world writable"
    else
      echo "[FAIL] Group/world-writable installed files detected:"
      printf '%s\n' "$bad"
      failed=1
    fi
  fi

  if ((failed == 0)); then
    echo "Installation is healthy."
  else
    echo "Installation problems were found." >&2
    exit 1
  fi
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
  [[ -n "$root" ]] || { echo "Downloaded package has no project directory" >&2; exit 69; }
  installer="$root/install.sh"
  [[ -f "$installer" ]] || { echo "Downloaded package is incomplete" >&2; exit 69; }
  bash "$installer"
  "$CURRENT/vpsga-manager.sh" doctor
  echo "Update completed. Current version: $("$VPSGA_BIN" --version)"
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
    cp -a "$history_tmp/history" /var/lib/vps-guard-audit/history
    rm -rf "$history_tmp"
    echo "Program removed. History kept at /var/lib/vps-guard-audit/history"
  else
    rm -rf /var/lib/vps-guard-audit
    [[ -n "$history_tmp" ]] && rm -rf "$history_tmp"
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
