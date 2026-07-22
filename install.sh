#!/usr/bin/env bash
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)/vps-guard-audit.sh"
DEST="/usr/local/sbin/vps-guard-audit"
install -m 0755 "$SRC" "$DEST"
echo "Installed: $DEST"
echo "Run: sudo vps-guard-audit"
