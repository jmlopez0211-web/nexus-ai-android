"""NEXUS defensive Python engine: runtime self-test and read-only Android diagnostics."""
from __future__ import annotations
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ENGINE_VERSION = "1.4.0"
TOOL_CATALOG = (
    {"id":"wacker","name":"Wacker","commands":("wacker.py","wacker"),"purpose":"Herramienta de auditoría WPA3 conocida por realizar intentos de diccionario online.","risk":"alto","execution":"deshabilitada"},
    {"id":"hostapd_mana","name":"hostapd-mana","commands":("hostapd-mana",),"purpose":"Implementación de punto de acceso de pruebas con capacidades de suplantación y captura.","risk":"alto","execution":"deshabilitada"},
    {"id":"wifite2","name":"Wifite2","commands":("wifite","wifite2"),"purpose":"Orquestador de auditorías Wi-Fi que incluye técnicas de captura y recuperación de claves.","risk":"alto","execution":"deshabilitada"},
    {"id":"eaphammer","name":"EAPHammer","commands":("eaphammer",),"purpose":"Herramienta de evaluación WPA2-Enterprise con escenarios Evil Twin y pruebas EAP.","risk":"alto","execution":"deshabilitada"},
)
SAFE_UTILITIES = ("termux-wifi-scaninfo", "iw", "ip", "airmon-ng")

def _find_tool(commands):
    for command in commands:
        found = shutil.which(command)
        if found:
            return command
    return None

def _wireless_interfaces():
    interfaces = []
    try:
        for entry in Path("/sys/class/net").iterdir():
            if (entry / "wireless").exists():
                interfaces.append(entry.name)
    except OSError:
        pass
    return sorted(interfaces)

def inspect_environment():
    utilities = {name: bool(shutil.which(name)) for name in SAFE_UTILITIES}
    interfaces = _wireless_interfaces()
    try:
        phy_visible = any(Path("/sys/class/ieee80211").iterdir())
    except OSError:
        phy_visible = False
    return {
        "python_version": platform.python_version(), "platform": platform.system(),
        "machine": platform.machine() or platform.architecture()[0],
        "termux_api_cli": utilities["termux-wifi-scaninfo"], "iw_available": utilities["iw"],
        "ip_available": utilities["ip"], "airmon_ng_available": utilities["airmon-ng"],
        "wireless_interfaces_visible": interfaces, "wireless_phy_visible": phy_visible,
        "monitor_mode_supported": None, "packet_injection_supported": None,
        "hardware_note": (
            "Android puede entregar inventario Wi-Fi mediante Termux:API aunque wlan0/PHY "
            "no sean visibles dentro del entorno de usuario. La ausencia de interfaz visible "
            "no significa que falle el escaneo Termux:API. No se prueban modo monitor ni inyección."
        ),
    }

def _python_self_test():
    checks = []
    for module in ("json", "ssl", "socket", "subprocess", "http.server"):
        try:
            __import__(module)
            checks.append({"name": "Módulo Python " + module, "ok": True})
        except Exception:
            checks.append({"name": "Módulo Python " + module, "ok": False})
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-python-") as directory:
            path = Path(directory) / "self-test.json"
            path.write_text(json.dumps({"nexus": True}), encoding="utf-8")
            valid = json.loads(path.read_text(encoding="utf-8")).get("nexus") is True
        checks.append({"name": "Lectura/escritura temporal y JSON", "ok": valid})
    except Exception:
        checks.append({"name": "Lectura/escritura temporal y JSON", "ok": False})
    return checks

def _termux_wifi_command():
    """Find Termux:API even when the bridge was launched with a reduced PATH."""
    command = shutil.which("termux-wifi-scaninfo")
    if command:
        return command
    candidates = []
    prefix = os.environ.get("PREFIX", "").strip()
    if prefix:
        candidates.append(Path(prefix) / "bin" / "termux-wifi-scaninfo")
    candidates.extend((
        Path("/data/data/com.termux/files/usr/bin/termux-wifi-scaninfo"),
        Path("/data/user/0/com.termux/files/usr/bin/termux-wifi-scaninfo"),
    ))
    for candidate in candidates:
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            continue
    return None


def _wifi_api_check(timeout=25):
    command = _termux_wifi_command()
    if not command:
        return {
            "available": False, "ok": False, "network_count": 0,
            "source": "unavailable", "command_path": None,
            "message": "No se encuentra termux-wifi-scaninfo en PATH ni en las rutas habituales de Termux. Comprueba que el puente se ejecuta dentro de Termux.",
        }
    try:
        env = os.environ.copy()
        prefix = os.environ.get("PREFIX", "").strip()
        if prefix:
            env["PATH"] = str(Path(prefix) / "bin") + os.pathsep + env.get("PATH", "")
        result = subprocess.run([command], capture_output=True, text=True, timeout=timeout, check=False, env=env)
        if result.returncode != 0:
            return {"available": True, "ok": False, "network_count": 0, "source": "error", "command_path": command,
                    "message": "El comando Termux:API existe, pero devolvió un error. Revisa permisos y la aplicación Termux:API."}
        payload = json.loads(result.stdout or "[]")
        if not isinstance(payload, list):
            raise ValueError("Respuesta no válida")
        count = sum(1 for item in payload if isinstance(item, dict))
        if count:
            return {"available": True, "ok": True, "network_count": count, "source": "live",
                    "command_path": command, "message": "Termux:API respondió y entregó redes en esta consulta."}

        # Android puede aplicar limitación de escaneos y devolver [] temporalmente.
        # Reutiliza únicamente el último inventario no vacío del puente, con TTL.
        cache_file = Path.home() / ".cache" / "nexus-ai" / "wifi-inventory.json"
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            saved_at = float(cached.get("saved_at", 0))
            networks = cached.get("networks", [])
            age = max(0, int(time.time() - saved_at))
            if isinstance(networks, list) and networks and age <= 900:
                return {"available": True, "ok": True, "network_count": len(networks),
                        "source": "cache", "cache_age_seconds": age, "command_path": command,
                        "message": "Android no entregó redes nuevas; se utiliza el último inventario válido guardado por el puente."}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
        return {"available": True, "ok": True, "network_count": 0, "source": "live_empty",
                "command_path": command,
                "message": "Termux:API respondió, pero Android no entregó redes nuevas y no hay inventario reciente en caché."}
    except subprocess.TimeoutExpired:
        return {"available": True, "ok": False, "network_count": 0, "source": "timeout", "command_path": command,
                "message": "La consulta Wi-Fi superó 25 segundos. Comprueba que Termux:API responde desde la misma sesión."}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"available": True, "ok": False, "network_count": 0, "source": "error", "command_path": command,
                "message": "El comando existe, pero su respuesta no es JSON válido o no se pudo ejecutar."}



def run_tool_module(module_id):
    """Start a bounded read-only Python diagnostic profile; never invoke third-party attack tools."""
    profiles = {
        "wacker": ("WPA3 configuration review", ("Termux:API inventory", "WPA3/SAE capability metadata")),
        "hostapd_mana": ("Access-point readiness review", ("Wireless interface visibility", "Wireless PHY visibility")),
        "wifite2": ("Passive Wi-Fi inventory review", ("Termux:API availability", "Current/cached inventory status")),
        "eaphammer": ("WPA2-Enterprise posture review", ("Enterprise metadata availability", "Wireless interface visibility")),
    }
    module_id = str(module_id or "").strip().lower()
    if module_id not in profiles:
        raise ValueError("Módulo desconocido.")
    catalog = next(item for item in TOOL_CATALOG if item["id"] == module_id)
    detected = _find_tool(catalog["commands"])
    environment = inspect_environment()
    wifi = _wifi_api_check(timeout=12)
    profile, _ = profiles[module_id]
    checks = []
    if module_id in ("wacker", "wifite2"):
        checks.extend([
            {"name": "Termux:API disponible", "ok": wifi["available"], "detail": wifi["message"]},
            {"name": "Inventario Wi-Fi", "ok": wifi["network_count"] > 0,
             "detail": str(wifi["network_count"]) + " redes; origen: " + wifi.get("source", "N/D")},
        ])
    else:
        checks.extend([
            {"name": "Interfaz inalámbrica visible", "ok": bool(environment["wireless_interfaces_visible"]),
             "detail": ", ".join(environment["wireless_interfaces_visible"]) or "No visible desde Termux."},
            {"name": "PHY inalámbrico visible", "ok": environment["wireless_phy_visible"],
             "detail": "La visibilidad PHY no se deduce del inventario Termux:API."},
        ])
    return {
        "ok": True, "module_id": module_id, "module_name": catalog["name"],
        "started": True, "mode": "read_only_python_diagnostic", "profile": profile,
        "checks": checks,
        "external_tool": {"detected": detected is not None, "command": detected,
                          "executed": False, "installed_by_nexus": False},
        "limitations": [
            "Se ha iniciado el perfil Python de diagnóstico seguro; no el ejecutable ofensivo de terceros.",
            "No se crean puntos de acceso, no se suplanta ninguna red ni se capturan credenciales o handshakes.",
            "No se prueban contraseñas, no se desautentican clientes ni se modifica la radio.",
            "Android/Termux puede no exponer hardware o controladores necesarios para funciones avanzadas.",
        ],
    }

def inventory_tools():
    """Read-only catalogue plus actual Python runtime self-tests."""
    tools = []
    for item in TOOL_CATALOG:
        detected = _find_tool(item["commands"])
        tools.append({
            "id": item["id"], "name": item["name"], "purpose": item["purpose"],
            "risk": item["risk"], "execution": item["execution"],
            "detected": detected is not None, "detected_command": detected,
            "status": "detectada; no ejecutada" if detected else "no detectada",\n            "launchable": True, "launch_mode": "diagnóstico Python de solo lectura",
        })
    checks = _python_self_test()
    wifi = _wifi_api_check()
    checks.extend([
        {"name": "Cliente Termux:API", "ok": wifi["available"]},
        {"name": "Consulta real Termux:API", "ok": wifi["ok"]},
    ])
    passed = sum(1 for item in checks if item["ok"])
    failed = len(checks) - passed
    return {
        "ok": failed == 0, "engine": "NEXUS Python Wireless Engine",
        "engine_version": ENGINE_VERSION, "mode": "runtime_diagnostic_read_only",
        "runtime_diagnostic": {
            "status": "operativo" if failed == 0 else "parcial",
            "checks_passed": passed, "checks_total": len(checks), "checks_failed": failed,
            "checks": checks, "wifi_api": wifi,
        },
        "tools": tools, "environment": inspect_environment(),
        "safety": {
            "tools_executed": False, "tools_installed": False, "radio_modified": False,
            "credential_capture": False, "password_attempts": False,
            "note": "Autodiagnóstico Python y consulta Wi-Fi de solo lectura. El catálogo especializado solo se inventaría; no se ejecuta.",
        },
    }
