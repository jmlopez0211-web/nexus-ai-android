#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
HOME="${HOME:-/data/data/com.termux/files/home}"
APP_DIR="$HOME/nexus-ai-android"
DATA_DIR="$HOME/.cache/nexus-ai"
mkdir -p "$DATA_DIR"
rm -f "$DATA_DIR/STOP_BRIDGE"
if [ -x "$APP_DIR/nexus_bridge_supervisor.sh" ]; then
  nohup "$APP_DIR/nexus_bridge_supervisor.sh" >/dev/null 2>&1 </dev/null &
  echo "NEXUS supervisor iniciado."
else
  echo "ERROR: falta nexus_bridge_supervisor.sh"
  exit 1
fi
