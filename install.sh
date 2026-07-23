#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/vps-guard-audit.sh"
MANAGER_SRC="$ROOT/vpsga-manager.sh"
LIB_SRC="$ROOT/lib"
CONFIG_SRC="$ROOT/config"
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
  check-registry.sh
  hardening-registry.sh
  hardening-transaction.sh
  hardening-actions.sh
  connection-safety.sh
  hardening-plan.sh
  audit-platform.sh
  audit-access.sh
  audit-system.sh
  audit-containers.sh
  report-guidance-zh.sh
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
  echo "安装失败：$*" >&2
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
  echo "请使用 root 权限运行安装程序：sudo bash ./install.sh" >&2
  exit 77
}
command -v sha256sum >/dev/null 2>&1 || { echo "缺少命令：sha256sum" >&2; exit 69; }
[[ -f "$SRC" && ! -L "$SRC" ]] || { echo "主脚本缺失或是符号链接：$SRC" >&2; exit 66; }
[[ -f "$MANAGER_SRC" && ! -L "$MANAGER_SRC" ]] || { echo "管理脚本缺失或是符号链接：$MANAGER_SRC" >&2; exit 66; }
[[ -d "$LIB_SRC" && ! -L "$LIB_SRC" ]] || { echo "模块目录缺失或是符号链接：$LIB_SRC" >&2; exit 66; }
[[ -f "$CONFIG_SRC/audit.conf.example" && -d "$CONFIG_SRC/profiles" ]] || { echo "缺少中文配置模板：$CONFIG_SRC" >&2; exit 66; }
for module in "${REQUIRED_MODULES[@]}"; do
  [[ -f "$LIB_SRC/$module" && ! -L "$LIB_SRC/$module" ]] || { echo "模块缺失或是符号链接：$LIB_SRC/$module" >&2; exit 66; }
done

bash -n "$SRC" "$MANAGER_SRC" "$LIB_SRC"/*.sh
VERSION="$(bash "$SRC" --version)"
[[ "$VERSION" =~ ^[0-9A-Za-z._-]+$ ]] || {
  echo "检测程序返回了无效版本：$VERSION" >&2
  exit 66
}

install -d -m 0755 "$INSTALL_ROOT" "$RELEASES_DIR" /usr/local/bin /usr/local/sbin
STAGE="$(mktemp -d "$INSTALL_ROOT/.install-${VERSION}.XXXXXX")"
# mktemp creates directories with mode 0700. The installed program must be
# traversable by a non-root user before the wrapper can invoke sudo, so the
# release root is intentionally 0755 while report/history data stays private.
chmod 0755 "$STAGE"
install -m 0755 "$SRC" "$STAGE/vps-guard-audit.sh"
install -m 0755 "$MANAGER_SRC" "$STAGE/vpsga-manager.sh"
install -d -m 0755 "$STAGE/lib"
for module in "${REQUIRED_MODULES[@]}"; do
  install -m 0644 "$LIB_SRC/$module" "$STAGE/lib/$module"
done
install -d -m 0755 "$STAGE/config/profiles"
install -m 0644 "$CONFIG_SRC/audit.conf.example" "$STAGE/config/audit.conf.example"
install -m 0644 "$CONFIG_SRC/profiles"/*.conf "$STAGE/config/profiles/"
bash -n "$STAGE/vps-guard-audit.sh" "$STAGE/vpsga-manager.sh" "$STAGE/lib"/*.sh
[[ "$(bash "$STAGE/vps-guard-audit.sh" --version)" == "$VERSION" ]] || fail "暂存版本校验失败"
(
  cd "$STAGE"
  sha256sum vps-guard-audit.sh vpsga-manager.sh lib/*.sh config/audit.conf.example config/profiles/*.conf > MANIFEST.sha256
  sha256sum -c --quiet MANIFEST.sha256
)
chmod 0644 "$STAGE/MANIFEST.sha256"

RELEASE_DIR="$RELEASES_DIR/$VERSION"
if [[ -e "$RELEASE_DIR" || -L "$RELEASE_DIR" ]]; then
  RELEASE_BACKUP="$INSTALL_ROOT/.release-${VERSION}.backup.$$"
  rm -rf -- "$RELEASE_BACKUP"
  mv "$RELEASE_DIR" "$RELEASE_BACKUP"
fi
mv "$STAGE" "$RELEASE_DIR"
STAGE=""
chmod 0755 "$RELEASE_DIR" "$RELEASE_DIR/lib"

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
  fail "current 链接无法访问已安装的可执行文件"
fi
for module in "${REQUIRED_MODULES[@]}"; do
  if [[ ! -r "$CURRENT_LINK/lib/$module" ]]; then
    rollback_install
    fail "已安装模块缺失：$module"
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
  echo "VPS Guard Audit 安装不完整。" >&2
  echo "请使用以下命令修复：" >&2
  echo "curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash" >&2
  exit 69
}

case "${1-}" in
  doctor|update|rollback|uninstall)
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
  echo "需要 root 权限，但系统中没有 sudo。" >&2
  exit 77
}
exec sudo "$TARGET" "$@"
EOF_WRAPPER

install -m 0755 "$WRAPPER_TMP" "$VPSGA_BIN"
install -m 0755 "$WRAPPER_TMP" "$COMPAT_BIN"

installed_version="$(PATH="/usr/local/bin:/usr/local/sbin:$PATH" "$VPSGA_BIN" --version 2>/dev/null || true)"
if [[ "$installed_version" != "$VERSION" ]]; then
  rollback_install
  fail "vpsga 安装后版本校验失败"
fi

rm -rf -- "$RELEASE_BACKUP" "$CURRENT_BACKUP" 2>/dev/null || true
RELEASE_BACKUP=""
CURRENT_BACKUP=""
find "$INSTALL_ROOT" -maxdepth 1 -type f -name '*.sh' -delete 2>/dev/null || true

echo "VPS Guard Audit $VERSION 安装完成"
echo "命令：vpsga"
echo "位置：$RELEASE_DIR"
echo "报告将保存到运行 vpsga 时所在的目录。"
