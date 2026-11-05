#!/data/data/com.termux/files/usr/bin/bash
set -u
HOME="${HOME:-/data/data/com.termux/files/home}"
DATA_DIR="$HOME/.cache/nexus-ai"
mkdir -p "$DATA_DIR"
touch "$DATA_DIR/STOP_BRIDGE"
if [ -s "$DATA_DIR/bridge-child.pid" ]; then
  PID="$(cat "$DATA_DIR/bridge-child.pid" 2>/dev/null || true)"
  case "$PID" in ''|*[!0-9]*) ;; *) kill -TERM "$PID" 2>/dev/null || true ;; esac
fi
if [ -s "$DATA_DIR/bridge-supervisor.pid" ]; then
  PID="$(cat "$DATA_DIR/bridge-supervisor.pid" 2>/dev/null || true)"
  case "$PID" in ''|*[!0-9]*) ;; *) kill -TERM "$PID" 2>/dev/null || true ;; esac
fi
echo "NEXUS bridge detenido. El arranque automático queda desactivado hasta el próximo reinicio del dispositivo o nueva instalación."
