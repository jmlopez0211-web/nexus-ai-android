"""NEXUS defensive Python engine: runtime self-test and read-only Android diagnostics."""
from __future__ import annotations
import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

ENGINE_VERSION = "1.1.0"
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

def _wifi_api_check(timeout=20):
    command = shutil.which("termux-wifi-scaninfo")
    if not command:
        return {"available": False, "ok": False, "network_count": 0, "message": "No se encuentra termux-wifi-scaninfo."}
    try:
        result = subprocess.run([command], capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0:
            return {"available": True, "ok": False, "network_count": 0, "message": "Termux:API devolvió un error. Revisa permisos y aplicación Termux:API."}
        payload = json.loads(result.stdout or "[]")
        if not isinstance(payload, list):
            raise ValueError("Respuesta no válida")
        count = sum(1 for item in payload if isinstance(item, dict))
        return {"available": True, "ok": True, "network_count": count,
                "message": "Termux:API respondió correctamente." if count else
                "Termux:API respondió, pero Android no entregó redes en esta consulta."}
    except subprocess.TimeoutExpired:
        return {"available": True, "ok": False, "network_count": 0, "message": "La consulta Wi-Fi superó el tiempo límite."}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"available": True, "ok": False, "network_count": 0, "message": "No se pudo interpretar la respuesta de Termux:API."}

def inventory_tools():
    """Read-only catalogue plus actual Python runtime self-tests."""
    tools = []
    for item in TOOL_CATALOG:
        detected = _find_tool(item["commands"])
        tools.append({
            "id": item["id"], "name": item["name"], "purpose": item["purpose"],
            "risk": item["risk"], "execution": item["execution"],
            "detected": detected is not None, "detected_command": detected,
            "status": "detectada; no ejecutada" if detected else "no detectada",
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
