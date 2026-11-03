#!/usr/bin/env python3
"""Puente Wi-Fi local para NEXUS IA y Termux:API.

Escucha exclusivamente en 127.0.0.1. No obtiene, almacena ni prueba claves Wi-Fi.
"""
import json
import os
import secrets
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = int(os.environ.get("NEXUS_WIFI_PORT", "8765"))
TOKEN = os.environ.get("NEXUS_WIFI_TOKEN", "")
DEFAULT_ORIGINS = {
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://127.0.0.1:8081",
    "http://localhost:8081",
    "https://nexus-ai-android-3.onrender.com",
}
extra_origins = {
    item.strip() for item in os.environ.get("NEXUS_WIFI_ALLOWED_ORIGINS", "").split(",")
    if item.strip()
}
ALLOWED_ORIGINS = DEFAULT_ORIGINS | extra_origins


class Handler(BaseHTTPRequestHandler):
    server_version = "NEXUS-WiFi-Bridge/1.0"

    def log_message(self, fmt, *args):
        print("[NEXUS WiFi] " + (fmt % args))

    def reply(self, status, data, origin=""):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def check_origin(self):
        origin = self.headers.get("Origin", "")
        if origin and origin not in ALLOWED_ORIGINS:
            self.reply(403, {"ok": False, "error": "Origen no permitido"})
            return False
        return True

    def check_token(self, origin):
        if TOKEN and not secrets.compare_digest(
            self.headers.get("Authorization", ""), "Bearer " + TOKEN
        ):
            self.reply(401, {"ok": False, "error": "Token incorrecto"}, origin)
            return False
        return True

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        if origin and origin not in ALLOWED_ORIGINS:
            return self.reply(403, {"ok": False, "error": "Origen no permitido"})
        self.send_response(204)
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Max-Age", "300")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):
        origin = self.headers.get("Origin", "")
        if not self.check_origin():
            return
        if not self.check_token(origin):
            return

        path = urlparse(self.path).path
        command = shutil.which("termux-wifi-scaninfo")
        if path == "/api/status":
            return self.reply(200, {
                "ok": True,
                "wifi_api": bool(command),
                "host": HOST,
                "port": PORT,
                "token_required": bool(TOKEN),
            }, origin)
        if path != "/api/wifi":
            return self.reply(404, {"ok": False, "error": "Ruta no encontrada"}, origin)
        if not command:
            return self.reply(503, {
                "ok": False,
                "error": "No se encuentra termux-wifi-scaninfo. Instala el paquete termux-api y la app Termux:API compatible."
            }, origin)

        try:
            result = subprocess.run(
                [command], capture_output=True, text=True, timeout=25, check=False
            )
            if result.returncode:
                detail = (result.stderr or result.stdout or "Error de Termux:API")[:800]
                return self.reply(502, {"ok": False, "error": detail}, origin)
            raw = json.loads(result.stdout or "[]")
            if not isinstance(raw, list):
                raise ValueError("La respuesta de Termux:API no es una lista JSON")
            networks = []
            for item in raw:
                if not isinstance(item, dict):
                    continue
                networks.append({
                    "ssid": str(item.get("ssid") or ""),
                    "bssid": str(item.get("bssid") or ""),
                    "rssi": item.get("rssi", item.get("level")),
                    "frequency_mhz": item.get("frequency_mhz", item.get("frequency")),
                    "channel_bandwidth_mhz": item.get("channel_bandwidth_mhz"),
                    "capabilities": str(item.get("capabilities") or ""),
                })
            return self.reply(200, {
                "ok": True,
                "mode": "live",
                "count": len(networks),
                "networks": networks,
            }, origin)
        except subprocess.TimeoutExpired:
            return self.reply(504, {"ok": False, "error": "Termux:API superó el límite de 25 segundos"}, origin)
        except (json.JSONDecodeError, ValueError) as error:
            return self.reply(502, {"ok": False, "error": str(error)}, origin)
        except Exception as error:
            self.log_error(error)
            return self.reply(500, {"ok": False, "error": "Error interno del puente"}, origin)

    def log_error(self, error):
        print("[NEXUS WiFi] Error interno: " + type(error).__name__)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"NEXUS WiFi Bridge activo en http://{HOST}:{PORT} (solo loopback)")
    print("No expongas este puerto a Internet ni a redes externas.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando puente…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
