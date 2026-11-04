#!/usr/bin/env python3
"""NEXUS IA local Android bridge. Binds to loopback only; never expose this port."""
import concurrent.futures
import ipaddress
import json
import os
import secrets
import shutil
import socket
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from nexus_wireless_engine import inventory_tools, run_tool_module
from nexus_plugin_manager import list_plugins, launch_plugin

HOST = "127.0.0.1"
PORT = int(os.environ.get("NEXUS_BRIDGE_PORT", "8766"))
TOKEN_FILE = os.path.expanduser("~/.nexus_bridge_token")
def load_bridge_token():
    configured = os.environ.get("NEXUS_BRIDGE_TOKEN", "").strip()
    if configured:
        return configured
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as token_file:
            stored = token_file.read().strip()
        if stored:
            return stored
    except OSError:
        pass
    token = secrets.token_urlsafe(32)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as token_file:
        token_file.write(token + "\n")
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass
    return token

TOKEN = load_bridge_token()
ALLOWED_ORIGINS = {
    item.strip() for item in os.environ.get(
        "NEXUS_ALLOWED_ORIGINS",
        "https://nexus-ai-android-3.onrender.com,https://nexus-ai-android.onrender.com,http://127.0.0.1:8080,http://localhost:8080,http://127.0.0.1:8081,http://localhost:8081"
    ).split(",") if item.strip()
}
PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
    27017: "MongoDB"
}
CONNECT_TIMEOUT = 0.45
WIFI_CACHE_FILE = os.path.join(os.path.expanduser("~"), ".cache", "nexus-ai", "wifi-inventory.json")
WIFI_CACHE_TTL_SECONDS = 900


def load_wifi_cache():
    try:
        with open(WIFI_CACHE_FILE, "r", encoding="utf-8") as cache_file:
            payload = json.load(cache_file)
        saved_at = float(payload.get("saved_at", 0))
        networks = payload.get("networks", [])
        if isinstance(networks, list) and networks and 0 <= time.time() - saved_at <= WIFI_CACHE_TTL_SECONDS:
            return networks, saved_at
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return [], 0.0


def save_wifi_cache(networks):
    saved_at = time.time()
    directory = os.path.dirname(WIFI_CACHE_FILE)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary = WIFI_CACHE_FILE + "." + secrets.token_hex(6) + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as cache_file:
        json.dump({"saved_at": saved_at, "networks": networks}, cache_file, ensure_ascii=False)
    os.replace(temporary, WIFI_CACHE_FILE)
    try:
        os.chmod(WIFI_CACHE_FILE, 0o600)
    except OSError:
        pass
    return saved_at


WIFI_CACHE, WIFI_CACHE_SAVED_AT = load_wifi_cache()


def validate_lan_target(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError("Introduce una dirección IP local válida; no se admiten nombres de dominio.") from exc
    private_lan_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if address.version != 4 or not any(address in network for network in private_lan_ranges):
        raise ValueError("Solo se permiten direcciones IPv4 RFC1918 de tu red local.")
    return str(address)


def probe_port(target, port, timeout=CONNECT_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0
    except OSError:
        return False


def scan_host(target):
    target = validate_lan_target(target)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda port: (port, probe_port(target, port)), PORTS))
    open_ports = [
        {"port": port, "service": PORTS[port], "protocol": "tcp", "state": "open"}
        for port, is_open in results if is_open
    ]
    return {
        "ok": True,
        "target": target,
        "mode": "single_host_tcp_connect",
        "scanned_ports": len(PORTS),
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "note": "El servicio se infiere del número de puerto; no se identifica versión ni vulnerabilidad."
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[NEXUS bridge] " + (fmt % args))

    def _reply(self, status, data, origin=""):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        self.wfile.write(body)

    def _origin(self):
        origin = self.headers.get("Origin", "")
        if origin and origin not in ALLOWED_ORIGINS:
            self._reply(403, {"ok": False, "error": "Origen no permitido"})
            return ""
        return origin

    def _authorized(self, origin):
        supplied = self.headers.get("Authorization", "")
        if not secrets.compare_digest(supplied, "Bearer " + TOKEN):
            self._reply(401, {"ok": False, "error": "Token local incorrecto o ausente"}, origin)
            return False
        return True

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        if origin and origin not in ALLOWED_ORIGINS:
            return self._reply(403, {"ok": False, "error": "Origen no permitido"})
        self.send_response(204)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):
        global WIFI_CACHE, WIFI_CACHE_SAVED_AT
        origin = self._origin()
        if self.headers.get("Origin") and not origin:
            return
        if not self._authorized(origin):
            return
        path = urlparse(self.path).path
        if path == "/api/status":
            return self._reply(200, {"ok": True, "service": "NEXUS IA local bridge", "host": HOST, "port": PORT, "wifi_api": bool(shutil.which("termux-wifi-scaninfo")), "cached_networks": len(WIFI_CACHE), "cache_age_seconds": max(0, int(time.time() - WIFI_CACHE_SAVED_AT)) if WIFI_CACHE_SAVED_AT else None}, origin)
        if path == "/api/tooling":
            return self._reply(200, inventory_tools(), origin)
        if path == "/api/plugins":
            try:
                return self._reply(200, {"ok": True, "plugins": list_plugins()}, origin)
            except Exception as exc:
                return self._reply(500, {"ok": False, "error": type(exc).__name__}, origin)
        if path != "/api/wifi":
            return self._reply(404, {"ok": False, "error": "Ruta no encontrada"}, origin)
        command = shutil.which("termux-wifi-scaninfo")
        if not command:
            return self._reply(503, {"ok": False, "error": "No se encuentra termux-wifi-scaninfo. Instala Termux:API y concede permisos."}, origin)
        import subprocess
        try:
            result = subprocess.run([command], capture_output=True, text=True, timeout=25)
            if result.returncode:
                return self._reply(502, {"ok": False, "error": (result.stderr or result.stdout or "Error Termux:API")[:800]}, origin)
            raw = json.loads(result.stdout or "[]")
            if not isinstance(raw, list):
                raise ValueError("Respuesta JSON inesperada")
            networks = [{
                "ssid": item.get("ssid", ""), "bssid": item.get("bssid", ""),
                "rssi": item.get("rssi", item.get("level")),
                "frequency_mhz": item.get("frequency_mhz", item.get("frequency")),
                "channel_bandwidth_mhz": item.get("channel_bandwidth_mhz"),
                "capabilities": item.get("capabilities", "")
            } for item in raw if isinstance(item, dict)]

            # Android may temporarily return an empty/partial scan because of
            # Wi-Fi scan throttling. Preserve the last non-empty inventory.
            now = time.time()
            if networks:
                WIFI_CACHE = networks
                try:
                    WIFI_CACHE_SAVED_AT = save_wifi_cache(networks)
                except OSError:
                    WIFI_CACHE_SAVED_AT = now
                cached = False
            elif WIFI_CACHE and 0 <= now - WIFI_CACHE_SAVED_AT <= WIFI_CACHE_TTL_SECONDS:
                networks = list(WIFI_CACHE)
                cached = True
            else:
                WIFI_CACHE = []
                WIFI_CACHE_SAVED_AT = 0.0
                cached = False
            return self._reply(200, {
                "ok": True,
                "mode": "cached" if cached else "live",
                "cached": cached,
                "count": len(networks),
                "networks": networks,
                "note": "Se muestra el último inventario válido porque Android no devolvió resultados nuevos." if cached else ""
            }, origin)
        except subprocess.TimeoutExpired:
            return self._reply(504, {"ok": False, "error": "Termux:API superó 25 segundos"}, origin)
        except Exception as exc:
            return self._reply(500, {"ok": False, "error": type(exc).__name__ + ": " + str(exc)}, origin)

    def do_POST(self):
        origin = self._origin()
        if self.headers.get("Origin") and not origin:
            return
        if not self._authorized(origin):
            return
        path = urlparse(self.path).path
        if path == "/api/plugins/launch":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 2048:
                    return self._reply(413, {"ok": False, "error": "Tamaño de solicitud no válido"}, origin)
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    return self._reply(400, {"ok": False, "error": "El cuerpo JSON debe ser un objeto"}, origin)
                result = launch_plugin(str(data.get("plugin_id", "")))
                return self._reply(200, result, origin)
            except PermissionError as exc:
                return self._reply(403, {"ok": False, "error": str(exc)}, origin)
            except (ValueError, json.JSONDecodeError) as exc:
                return self._reply(400, {"ok": False, "error": str(exc)}, origin)
            except Exception as exc:
                return self._reply(500, {"ok": False, "error": type(exc).__name__}, origin)
        if path == "/api/tooling/launch":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 2048:
                    return self._reply(413, {"ok": False, "error": "Tamaño de solicitud no válido"}, origin)
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    return self._reply(400, {"ok": False, "error": "El cuerpo JSON debe ser un objeto"}, origin)
                result = run_tool_module(data.get("module_id", ""))
                return self._reply(200, result, origin)
            except (ValueError, json.JSONDecodeError) as exc:
                return self._reply(400, {"ok": False, "error": str(exc)}, origin)
            except Exception as exc:
                return self._reply(500, {"ok": False, "error": type(exc).__name__}, origin)
        if path != "/api/scan":
            return self._reply(404, {"ok": False, "error": "Ruta no encontrada"}, origin)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                return self._reply(413, {"ok": False, "error": "Tamaño de solicitud no válido"}, origin)
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                return self._reply(400, {"ok": False, "error": "El cuerpo JSON debe ser un objeto"}, origin)
            if data.get("authorized") is not True:
                return self._reply(403, {"ok": False, "error": "Confirma que tienes autorización para revisar ese equipo"}, origin)
            result = scan_host(data.get("target", ""))
            return self._reply(200, result, origin)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._reply(400, {"ok": False, "error": str(exc)}, origin)
        except Exception as exc:
            return self._reply(500, {"ok": False, "error": type(exc).__name__}, origin)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"NEXUS bridge: http://{HOST}:{PORT} (solo loopback)")
    print("Token privado cargado desde NEXUS_BRIDGE_TOKEN o ~/.nexus_bridge_token; no se muestra.")
    print("No publiques ni reenvíes el puerto 8766.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
