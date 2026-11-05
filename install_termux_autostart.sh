#!/data/data/com.termux/files/usr/bin/bash
# One-time installation of NEXUS Android boot autostart.
set -euo pipefail
umask 077
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
PYTHON="$PREFIX/bin/python"
HOME="${HOME:-/data/data/com.termux/files/home}"
APP_DIR="$HOME/nexus-ai-android"
BOOT_DIR="$HOME/.termux/boot"
CONFIG_DIR="$HOME/.config/nexus-ai"
DATA_DIR="$HOME/.cache/nexus-ai"
if [ ! -f "$APP_DIR/nexus_bridge_termux.py" ] || [ ! -f "$APP_DIR/nexus_bridge_supervisor.sh" ]; then
  echo "ERROR: No encuentro el repositorio actualizado en $APP_DIR"
  exit 1
fi
if [ ! -s "$HOME/.nexus_bridge_token" ]; then
  echo "ERROR: No existe ~/.nexus_bridge_token. No se generará otro token."
  exit 1
fi
mkdir -p "$BOOT_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$HOME/.termux" "$BOOT_DIR" "$CONFIG_DIR" "$DATA_DIR"
chmod 700 "$APP_DIR/nexus_bridge_supervisor.sh"
cp "$APP_DIR/termux-boot/00-nexus-bridge" "$BOOT_DIR/00-nexus-bridge"
chmod 700 "$BOOT_DIR/00-nexus-bridge"
if [ -s "$DATA_DIR/bridge-supervisor.pid" ]; then
  EXISTING_PID="$(cat "$DATA_DIR/bridge-supervisor.pid" 2>/dev/null || true)"
  case "$EXISTING_PID" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo "NEXUS: el supervisor ya está activo (PID $EXISTING_PID). No se inicia una segunda instancia."
        exit 0
      fi
      ;;
  esac
fi
if [ ! -f "$CONFIG_DIR/bridge.conf" ]; then
  printf 'KEEP_CPU_AWAKE=0\n' > "$CONFIG_DIR/bridge.conf"
  chmod 600 "$CONFIG_DIR/bridge.conf"
fi
rm -f "$DATA_DIR/STOP_BRIDGE"

# Stop only an existing NEXUS bridge launched from this exact project folder.
# This avoids the common "Address already in use" failure during first migration.
"$PYTHON" - "$APP_DIR" <<'PY'
import os
import signal
import sys
import time
root = os.path.realpath(sys.argv[1])
me = {os.getpid(), os.getppid()}
stopped = []
try:
    entries = os.listdir("/proc")
except OSError:
    entries = []
for entry in entries:
    if not entry.isdigit() or int(entry) in me:
        continue
    proc = "/proc/" + entry
    try:
        args = open(proc + "/cmdline", "rb").read().split(b"\\0")
        cwd = os.path.realpath(proc + "/cwd")
        names = [os.fsdecode(arg) for arg in args if arg]
        bridge_args = any(os.path.basename(arg) == "nexus_bridge_termux.py" for arg in names)
        exact_script = any(os.path.realpath(arg) == os.path.join(root, "nexus_bridge_termux.py") for arg in names)
        if bridge_args and (cwd == root or exact_script):
            os.kill(int(entry), signal.SIGTERM)
            stopped.append(int(entry))
    except (OSError, ProcessLookupError, PermissionError):
        pass
if stopped:
    time.sleep(1)
    print("Instancias anteriores de NEXUS detenidas:", len(stopped))
PY

echo "NEXUS: arranque automático instalado."
echo "El ahorro de batería sigue activo. Puedes activar el wakelock editando bridge.conf a KEEP_CPU_AWAKE=1."
echo "Abre Termux:Boot una vez y configura Android para no suspender Termux/Termux:Boot."
if ! cmd package path com.termux.boot >/dev/null 2>&1; then echo "AVISO: instala Termux:Boot desde la misma fuente que Termux y ábrelo una vez."; fi
echo "Iniciando supervisor ahora…"
nohup "$APP_DIR/nexus_bridge_supervisor.sh" >/dev/null 2>&1 </dev/null &
