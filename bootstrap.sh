#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_URL="https://github.com/AshFog/vps-guard-audit/archive/refs/heads/main.tar.gz"
ORIGINAL_DIR="$(pwd -P)"
TMP_DIR="$(mktemp -d)"
ARCHIVE="$TMP_DIR/vps-guard-audit.tar.gz"
trap 'rm -rf "$TMP_DIR"' EXIT

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 69; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 69; }

ARGS=("$@")
HAS_OUTPUT_DIR=0
for arg in "${ARGS[@]}"; do
  case "$arg" in
    --output-dir|--output-dir=*) HAS_OUTPUT_DIR=1; break ;;
  esac
done
if [[ "$HAS_OUTPUT_DIR" -eq 0 ]]; then
  ARGS+=(--output-dir "$ORIGINAL_DIR")
fi

echo "[1/3] Downloading VPS Guard Audit..."
curl --fail --show-error --location \
  --connect-timeout 15 --max-time 120 --retry 2 --retry-delay 1 \
  "$ARCHIVE_URL" -o "$ARCHIVE"

echo "[2/3] Extracting package..."
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
ROOT_DIR="$(find "$TMP_DIR" -mindepth 1 -maxdepth 1 -type d -name 'vps-guard-audit-*' -print -quit)"
SCRIPT="$ROOT_DIR/vps-guard-audit.sh"
[[ -f "$SCRIPT" && -d "$ROOT_DIR/lib" ]] || {
  echo "Downloaded package is incomplete" >&2
  exit 69
}
chmod 0700 "$SCRIPT"

echo "[3/3] Starting audit..."
echo "Reports will be saved in: $ORIGINAL_DIR"
set +e
if [[ "$(id -u)" -eq 0 ]]; then
  (cd "$ROOT_DIR" && bash "$SCRIPT" "${ARGS[@]}" </dev/tty)
else
  (cd "$ROOT_DIR" && sudo bash "$SCRIPT" "${ARGS[@]}" </dev/tty)
fi
rc=$?
set -e
exit "$rc"
