#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

HOME="${HOME:-/data/data/com.termux/files/home}"
APP_DIR="$HOME/nexus-ai-android"

if [ ! -f "$APP_DIR/nexus_bridge_start.sh" ]; then
  printf '%s\n' "NEXUS: falta $APP_DIR/nexus_bridge_start.sh" >&2
  exit 2
fi

exec /data/data/com.termux/files/usr/bin/bash "$APP_DIR/nexus_bridge_start.sh"
