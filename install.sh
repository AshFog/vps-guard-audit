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

cleanup() {
  [[ -n "$STAGE" && -d "$STAGE" ]] && rm -rf "$STAGE"
  [[ -n "$WRAPPER_TMP" && -f "$WRAPPER_TMP" ]] && rm -f "$WRAPPER_TMP"
}
trap cleanup EXIT

[[ ${EUID:-$(id -u)} -eq 0 ]] || {
  echo "Run the installer as root: sudo ./install.sh" >&2
  exit 77
}
[[ -f "$SRC" ]] || { echo "Missing: $SRC" >&2; exit 66; }
[[ -f "$MANAGER_SRC" ]] || { echo "Missing: $MANAGER_SRC" >&2; exit 66; }
[[ -d "$LIB_SRC" ]] || { echo "Missing: $LIB_SRC" >&2; exit 66; }

VERSION="$(bash "$SRC" --version)"
[[ "$VERSION" =~ ^[0-9A-Za-z._-]+$ ]] || {
  echo "Invalid version returned by the audit: $VERSION" >&2
  exit 66
}

install -d -m 0755 "$RELEASES_DIR" /usr/local/bin /usr/local/sbin
STAGE="$(mktemp -d "$RELEASES_DIR/.install-${VERSION}.XXXXXX")"
install -m 0755 "$SRC" "$STAGE/vps-guard-audit.sh"
install -m 0755 "$MANAGER_SRC" "$STAGE/vpsga-manager.sh"
install -d -m 0755 "$STAGE/lib"
install -m 0644 "$LIB_SRC"/*.sh "$STAGE/lib/"

RELEASE_DIR="$RELEASES_DIR/$VERSION"
rm -rf "$RELEASE_DIR"
mv "$STAGE" "$RELEASE_DIR"
STAGE=""
ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"

WRAPPER_TMP="$(mktemp)"
cat >"$WRAPPER_TMP" <<'EOF_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

CURRENT="/usr/local/lib/vps-guard-audit/current"
TARGET="$CURRENT/vps-guard-audit.sh"
MANAGER="$CURRENT/vpsga-manager.sh"
[[ -x "$TARGET" && -x "$MANAGER" ]] || {
  echo "VPS Guard Audit is not installed correctly. Run the official one-command installer again." >&2
  exit 69
}

case "${1-}" in
  doctor|update|open|serve|uninstall)
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

find "$INSTALL_ROOT" -maxdepth 1 -type f -name '*.sh' -delete 2>/dev/null || true

echo "Installed VPS Guard Audit $VERSION"
echo "Command: vpsga"
echo "Location: $RELEASE_DIR"
echo "Reports are saved in the directory where vpsga is run."
