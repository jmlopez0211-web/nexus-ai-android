#!/data/data/com.termux/files/usr/bin/bash
# One-time installation of NEXUS Android boot autostart.
set -euo pipefail
umask 077
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
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
if [ ! -f "$CONFIG_DIR/bridge.conf" ]; then
  printf 'KEEP_CPU_AWAKE=0\n' > "$CONFIG_DIR/bridge.conf"
  chmod 600 "$CONFIG_DIR/bridge.conf"
fi
rm -f "$DATA_DIR/STOP_BRIDGE"
echo "NEXUS: arranque automático instalado."
echo "El ahorro de batería sigue activo. Puedes activar el wakelock editando bridge.conf a KEEP_CPU_AWAKE=1."
echo "Abre Termux:Boot una vez y configura Android para no suspender Termux/Termux:Boot."
echo "Iniciando supervisor ahora…"
nohup "$APP_DIR/nexus_bridge_supervisor.sh" >/dev/null 2>&1 </dev/null &
