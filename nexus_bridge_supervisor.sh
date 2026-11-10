#!/data/data/com.termux/files/usr/bin/bash
# NEXUS bridge supervisor. Runs only the local loopback bridge.
set -u
umask 077
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
HOME="${HOME:-/data/data/com.termux/files/home}"
APP_DIR="$HOME/nexus-ai-android"
DATA_DIR="$HOME/.cache/nexus-ai"
LOG_FILE="$DATA_DIR/bridge-supervisor.log"
PID_FILE="$DATA_DIR/bridge-supervisor.pid"
LOCK_DIR="$DATA_DIR/bridge-supervisor.lock"
CHILD_PID_FILE="$DATA_DIR/bridge-child.pid"
STOP_FILE="$DATA_DIR/STOP_BRIDGE"
TOKEN_FILE="$HOME/.nexus_bridge_token"
PYTHON="$PREFIX/bin/python"
PORT="${NEXUS_BRIDGE_PORT:-8766}"
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*" >> "$LOG_FILE"; }
rotate_log() {
  if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE")" -gt 1048576 ]; then
    mv -f "$LOG_FILE" "$LOG_FILE.1"
    : > "$LOG_FILE"
    chmod 600 "$LOG_FILE"
  fi
}
write_pid() { printf '%s\n' "$$" > "$PID_FILE"; chmod 600 "$PID_FILE"; }
cleanup() {
  if [ -n "${BRIDGE_PID:-}" ] && kill -0 "$BRIDGE_PID" 2>/dev/null; then
    kill -TERM "$BRIDGE_PID" 2>/dev/null || true
    wait "$BRIDGE_PID" 2>/dev/null || true
  fi
  rm -f "$PID_FILE" "$CHILD_PID_FILE"
  if [ -f "$LOCK_DIR/pid" ] && [ "$(cat "$LOCK_DIR/pid" 2>/dev/null || true)" = "$$" ]; then
    rm -rf "$LOCK_DIR"
  fi
}

# Atomic singleton guard: duplicate start requests exit without touching the live bridge.
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  sleep 1
  EXISTING_PID="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
  if [[ "$EXISTING_PID" =~ ^[0-9]+$ ]] && kill -0 "$EXISTING_PID" 2>/dev/null; then
    if tr '\0' ' ' < "/proc/$EXISTING_PID/cmdline" 2>/dev/null | grep -Fq "$APP_DIR/nexus_bridge_supervisor.sh"; then
      log "Ya existe un supervisor activo (PID $EXISTING_PID); se omite el duplicado."
      exit 0
    fi
  fi
  rm -rf "$LOCK_DIR"
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "No se pudo adquirir el bloqueo del supervisor; se omite esta instancia."
    exit 0
  fi
fi
printf '%s\n' "$$" > "$LOCK_DIR/pid"
chmod 600 "$LOCK_DIR/pid"
trap cleanup EXIT INT TERM

if [ ! -f "$APP_DIR/nexus_bridge_termux.py" ] || [ ! -f "$APP_DIR/nexus_runtime_inventory.py" ]; then
  log "ERROR: no se encuentra la versión actual del puente en $APP_DIR"
  exit 1
fi
if [ ! -x "$PYTHON" ]; then
  log "ERROR: Python no está disponible en $PYTHON"
  exit 1
fi
if [ ! -s "$TOKEN_FILE" ]; then
  log "ERROR: falta el token persistente $TOKEN_FILE; no se crea otro para evitar invalidar el token del navegador."
  exit 1
fi

write_pid
BACKOFF=3
while :; do
  if [ -f "$STOP_FILE" ]; then
    log "Parada solicitada; no se reiniciará el puente."
    break
  fi
  rotate_log
  log "Iniciando NEXUS bridge en 127.0.0.1:$PORT"
  cd "$APP_DIR" || exit 1
  "$PYTHON" -u "$APP_DIR/nexus_bridge_termux.py" >> "$LOG_FILE" 2>&1 &
  BRIDGE_PID=$!
  printf '%s\n' "$BRIDGE_PID" > "$CHILD_PID_FILE"
  chmod 600 "$CHILD_PID_FILE"
  FAILURES=0
  # Supervisor de salud: detecta tanto la salida del proceso como un API bloqueado.
  while kill -0 "$BRIDGE_PID" 2>/dev/null; do
    sleep 25
    if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then break; fi
    if [ -s "$TOKEN_FILE" ]; then
      TOKEN="$(cat "$TOKEN_FILE")"
      if NEXUS_HEALTH_TOKEN="$TOKEN" NEXUS_HEALTH_PORT="$PORT" "$PYTHON" -c 'import os,urllib.request; r=urllib.request.Request("http://127.0.0.1:"+os.environ.get("NEXUS_HEALTH_PORT","8766")+"/api/status",headers={"Authorization":"Bearer "+os.environ["NEXUS_HEALTH_TOKEN"]}); x=urllib.request.urlopen(r,timeout=5); raise SystemExit(0 if x.status==200 else 1)' >/dev/null 2>&1; then
        FAILURES=0
        BACKOFF=3
      else
        FAILURES=$((FAILURES + 1))
        log "Health check fallido ($FAILURES/3)."
        if [ "$FAILURES" -ge 3 ]; then
          log "El API no responde; reinicio controlado del proceso."
          kill -TERM "$BRIDGE_PID" 2>/dev/null || true
          break
        fi
      fi
    fi
  done
  wait "$BRIDGE_PID"
  EXIT_CODE=$?
  BRIDGE_PID=""
  rm -f "$CHILD_PID_FILE"
  log "El puente terminó (código $EXIT_CODE)."
  if [ -f "$STOP_FILE" ]; then
    log "Parada solicitada; supervisor finalizado."
    break
  fi
  sleep "$BACKOFF"
  if [ "$BACKOFF" -lt 60 ]; then BACKOFF=$((BACKOFF * 2)); [ "$BACKOFF" -gt 60 ] && BACKOFF=60; fi
done
