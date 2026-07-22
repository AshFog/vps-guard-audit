#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/vps-guard-audit.sh"
MANAGER_SRC="$ROOT/vpsga-manager.sh"
LIB_SRC="$ROOT/lib"
INSTALL_ROOT="/usr/local/lib/vps-guard-audit"
RELEASES_DIR="$INSTALL_ROOT/releases"
CURRENT_LINK="$INSTALL_ROOT/current"
VPSGA_BIN="/usr/local/bin/vpsga"
COMPAT_BIN="/usr/local/sbin/vps-guard-audit"
STAGE=""
WRAPPER_TMP=""
RELEASE_BACKUP=""
CURRENT_BACKUP=""
PREVIOUS_LINK_TARGET=""

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

cleanup() {
  [[ -n "$STAGE" && -d "$STAGE" ]] && rm -rf -- "$STAGE"
  [[ -n "$WRAPPER_TMP" && -f "$WRAPPER_TMP" ]] && rm -f -- "$WRAPPER_TMP"
}
trap cleanup EXIT

fail() {
  echo "Installation failed: $*" >&2
  exit 69
}

rollback_install() {
  rm -rf -- "$CURRENT_LINK" 2>/dev/null || true
  rm -rf -- "$RELEASE_DIR" 2>/dev/null || true
  if [[ -n "$RELEASE_BACKUP" && -e "$RELEASE_BACKUP" ]]; then
    mv "$RELEASE_BACKUP" "$RELEASE_DIR" 2>/dev/null || true
  fi
  if [[ -n "$CURRENT_BACKUP" && -e "$CURRENT_BACKUP" ]]; then
    mv "$CURRENT_BACKUP" "$CURRENT_LINK" 2>/dev/null || true
  elif [[ -n "$PREVIOUS_LINK_TARGET" ]]; then
    ln -s "$PREVIOUS_LINK_TARGET" "$CURRENT_LINK" 2>/dev/null || true
  fi
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo "Run the installer as root: sudo ./install.sh" >&2
  exit 77
}
[[ -f "$SRC" ]] || { echo "Missing: $SRC" >&2; exit 66; }
[[ -f "$MANAGER_SRC" ]] || { echo "Missing: $MANAGER_SRC" >&2; exit 66; }
[[ -d "$LIB_SRC" ]] || { echo "Missing: $LIB_SRC" >&2; exit 66; }
for module in "${REQUIRED_MODULES[@]}"; do
  [[ -f "$LIB_SRC/$module" ]] || { echo "Missing module: $LIB_SRC/$module" >&2; exit 66; }
done

bash -n "$SRC" "$MANAGER_SRC" "$LIB_SRC"/*.sh
VERSION="$(bash "$SRC" --version)"
[[ "$VERSION" =~ ^[0-9A-Za-z._-]+$ ]] || {
  echo "Invalid version returned by the audit: $VERSION" >&2
  exit 66
}

install -d -m 0755 "$INSTALL_ROOT" "$RELEASES_DIR" /usr/local/bin /usr/local/sbin
STAGE="$(mktemp -d "$INSTALL_ROOT/.install-${VERSION}.XXXXXX")"
install -m 0755 "$SRC" "$STAGE/vps-guard-audit.sh"
install -m 0755 "$MANAGER_SRC" "$STAGE/vpsga-manager.sh"
install -d -m 0755 "$STAGE/lib"
for module in "${REQUIRED_MODULES[@]}"; do
  install -m 0644 "$LIB_SRC/$module" "$STAGE/lib/$module"
done
bash -n "$STAGE/vps-guard-audit.sh" "$STAGE/vpsga-manager.sh" "$STAGE/lib"/*.sh
[[ "$(bash "$STAGE/vps-guard-audit.sh" --version)" == "$VERSION" ]] || fail "staged version check failed"

RELEASE_DIR="$RELEASES_DIR/$VERSION"
if [[ -e "$RELEASE_DIR" || -L "$RELEASE_DIR" ]]; then
  RELEASE_BACKUP="$INSTALL_ROOT/.release-${VERSION}.backup.$$"
  rm -rf -- "$RELEASE_BACKUP"
  mv "$RELEASE_DIR" "$RELEASE_BACKUP"
fi
mv "$STAGE" "$RELEASE_DIR"
STAGE=""

# Older development builds could leave `current` as a real directory. Move it
# aside before creating the release symlink; otherwise `ln` creates a nested
# current/VERSION link and the global command cannot find the executable.
if [[ -L "$CURRENT_LINK" ]]; then
  PREVIOUS_LINK_TARGET="$(readlink "$CURRENT_LINK")"
  rm -f -- "$CURRENT_LINK"
elif [[ -e "$CURRENT_LINK" ]]; then
  CURRENT_BACKUP="$INSTALL_ROOT/.current.backup.$$"
  rm -rf -- "$CURRENT_BACKUP"
  mv "$CURRENT_LINK" "$CURRENT_BACKUP"
fi
ln -s "$RELEASE_DIR" "$CURRENT_LINK"

if [[ ! -x "$CURRENT_LINK/vps-guard-audit.sh" || ! -x "$CURRENT_LINK/vpsga-manager.sh" ]]; then
  rollback_install
  fail "current release link does not expose the installed executables"
fi
for module in "${REQUIRED_MODULES[@]}"; do
  if [[ ! -r "$CURRENT_LINK/lib/$module" ]]; then
    rollback_install
    fail "installed module is missing: $module"
  fi
done

WRAPPER_TMP="$(mktemp)"
cat >"$WRAPPER_TMP" <<'EOF_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

CURRENT="/usr/local/lib/vps-guard-audit/current"
TARGET="$CURRENT/vps-guard-audit.sh"
MANAGER="$CURRENT/vpsga-manager.sh"
[[ -x "$TARGET" && -x "$MANAGER" ]] || {
  echo "VPS Guard Audit installation is incomplete." >&2
  echo "Repair it with:" >&2
  echo "curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash" >&2
  exit 69
}

case "${1-}" in
  doctor|update|uninstall)
    exec "$MANAGER" "$@"
    ;;
  -h|--help|-v|--version)
    exec "$TARGET" "$@"
    ;;
esac

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  exec "$TARGET" "$@"
fi

command -v sudo >/dev/null 2>&1 || {
  echo "Root privileges are required and sudo is not available." >&2
  exit 77
}
exec sudo "$TARGET" "$@"
EOF_WRAPPER

install -m 0755 "$WRAPPER_TMP" "$VPSGA_BIN"
install -m 0755 "$WRAPPER_TMP" "$COMPAT_BIN"

installed_version="$(PATH="/usr/local/bin:/usr/local/sbin:$PATH" "$VPSGA_BIN" --version 2>/dev/null || true)"
if [[ "$installed_version" != "$VERSION" ]]; then
  rollback_install
  fail "vpsga post-install version check failed"
fi

rm -rf -- "$RELEASE_BACKUP" "$CURRENT_BACKUP" 2>/dev/null || true
RELEASE_BACKUP=""
CURRENT_BACKUP=""
find "$INSTALL_ROOT" -maxdepth 1 -type f -name '*.sh' -delete 2>/dev/null || true

echo "Installed VPS Guard Audit $VERSION"
echo "Command: vpsga"
echo "Location: $RELEASE_DIR"
echo "Reports are saved in the directory where vpsga is run."
