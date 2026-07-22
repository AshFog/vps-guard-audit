#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_URL="https://github.com/AshFog/vps-guard-audit/archive/refs/heads/main.tar.gz"
ORIGINAL_DIR="$(pwd -P)"
TMP_DIR="$(mktemp -d)"
ARCHIVE="$TMP_DIR/vps-guard-audit.tar.gz"
trap 'rm -rf "$TMP_DIR"' EXIT

command -v curl >/dev/null 2>&1 || { echo "缺少必要命令：curl" >&2; exit 69; }
command -v tar >/dev/null 2>&1 || { echo "缺少必要命令：tar" >&2; exit 69; }

ARGS=("$@")
HAS_OUTPUT_DIR=0
for arg in "${ARGS[@]}"; do
  case "$arg" in
    --output-dir|--output-dir=*) HAS_OUTPUT_DIR=1 ;;
  esac
done

if [[ "$HAS_OUTPUT_DIR" -eq 0 ]]; then
  ARGS+=(--output-dir "$ORIGINAL_DIR")
fi

echo "[1/4] 正在下载 VPS Guard Audit……"
curl --fail --show-error --location \
  --connect-timeout 15 --max-time 120 --retry 2 --retry-delay 1 \
  "$ARCHIVE_URL" -o "$ARCHIVE"

echo "[2/4] 正在解压安装包……"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
ROOT_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'vps-guard-audit-*' -print -quit)"
SCRIPT="$ROOT_DIR/vps-guard-audit.sh"
INSTALLER="$ROOT_DIR/install.sh"
MANAGER="$ROOT_DIR/vpsga-manager.sh"
[[ -f "$SCRIPT" && -f "$INSTALLER" && -f "$MANAGER" && -d "$ROOT_DIR/lib" ]] || {
  echo "下载的安装包不完整" >&2
  exit 69
}
chmod 0700 "$SCRIPT" "$INSTALLER" "$MANAGER"
EXPECTED_VERSION="$(bash "$SCRIPT" --version)"

echo "[3/4] 正在安装或更新 vpsga 命令……"
if [[ "$(id -u)" -eq 0 ]]; then
  bash "$INSTALLER"
else
  command -v sudo >/dev/null 2>&1 || {
    echo "需要 root 权限，但系统中没有 sudo。" >&2
    exit 77
  }
  sudo bash "$INSTALLER"
fi

[[ -x /usr/local/bin/vpsga ]] || {
  echo "安装完成，但未生成 /usr/local/bin/vpsga" >&2
  exit 69
}
INSTALLED_VERSION="$(/usr/local/bin/vpsga --version 2>/dev/null || true)"
[[ "$INSTALLED_VERSION" == "$EXPECTED_VERSION" ]] || {
  echo "安装校验失败：预期 $EXPECTED_VERSION，实际 ${INSTALLED_VERSION:-未知}" >&2
  exit 69
}
/usr/local/bin/vpsga doctor >/dev/null || {
  echo "安装校验失败，请运行：vpsga doctor" >&2
  exit 69
}

echo "[4/4] 正在开始安全检测……"
echo "以后直接运行：vpsga"
echo "报告保存位置：$ORIGINAL_DIR"
set +e
(cd "$ORIGINAL_DIR" && /usr/local/bin/vpsga "${ARGS[@]}")
rc=$?
set -e
exit "$rc"
