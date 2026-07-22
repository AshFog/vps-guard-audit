#!/usr/bin/env bash
set -euo pipefail

URL="https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/vps-guard-audit.sh"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP"
chmod 0700 "$TMP"

if [[ "$(id -u)" -eq 0 ]]; then
  bash "$TMP" </dev/tty
else
  sudo bash "$TMP" </dev/tty
fi
