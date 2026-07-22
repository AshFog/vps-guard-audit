#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/vps-guard-audit.sh"
LIB_SRC="$ROOT/lib"
DEST="/usr/local/sbin/vps-guard-audit"
LIB_DEST="/usr/local/lib/vps-guard-audit"

[[ -f "$SRC" ]] || { echo "Missing: $SRC" >&2; exit 66; }
[[ -d "$LIB_SRC" ]] || { echo "Missing: $LIB_SRC" >&2; exit 66; }

install -d -m 0755 "$LIB_DEST"
install -m 0644 "$LIB_SRC"/*.sh "$LIB_DEST"/
install -m 0755 "$SRC" "$DEST"

echo "Installed: $DEST"
echo "Modules: $LIB_DEST"
echo "Run: sudo vps-guard-audit"
