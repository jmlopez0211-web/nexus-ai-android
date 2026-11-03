"""NEXUS IA defensive wireless engine.

This module inventories selected wireless security utilities and reports the
local runtime environment. It never launches, installs, configures, or invokes
the listed utilities.
"""
from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path

ENGINE_VERSION = "1.0.0"

# Informational catalogue only. No execution hooks are provided.
TOOL_CATALOG = (
    {
        "id": "wacker",
        "name": "Wacker",
        "commands": ("wacker.py", "wacker"),
        "purpose": "Herramienta de auditoría WPA3 conocida por realizar intentos de diccionario online.",
        "risk": "alto",
        "execution": "deshabilitada",
    },
    {
        "id": "hostapd_mana",
        "name": "hostapd-mana",
        "commands": ("hostapd-mana",),
        "purpose": "Implementación de punto de acceso de pruebas con capacidades de suplantación y captura.",
        "risk": "alto",
        "execution": "deshabilitada",
    },
    {
        "id": "wifite2",
        "name": "Wifite2",
        "commands": ("wifite", "wifite2"),
        "purpose": "Orquestador de auditorías Wi-Fi que incluye técnicas de captura y recuperación de claves.",
        "risk": "alto",
        "execution": "deshabilitada",
    },
    {
        "id": "eaphammer",
        "name": "EAPHammer",
        "commands": ("eaphammer",),
        "purpose": "Herramienta de evaluación WPA2-Enterprise con escenarios Evil Twin y pruebas EAP.",
        "risk": "alto",
        "execution": "deshabilitada",
    },
)

SAFE_UTILITIES = ("termux-wifi-scaninfo", "iw", "ip", "airmon-ng")


def _find_tool(commands: tuple[str, ...]) -> str | None:
    for command in commands:
        found = shutil.which(command)
        if found:
            return command
    return None


def _wireless_interfaces() -> list[str]:
    interfaces: list[str] = []
    root = Path("/sys/class/net")
    try:
        for entry in root.iterdir():
            if (entry / "wireless").exists():
                interfaces.append(entry.name)
    except OSError:
        pass
    return sorted(interfaces)


def inspect_environment() -> dict:
    """Return read-only environment facts; do not probe or alter radio state."""
    utilities = {name: bool(shutil.which(name)) for name in SAFE_UTILITIES}
    interfaces = _wireless_interfaces()
    ieee80211_root = Path("/sys/class/ieee80211")
    phy_visible = False
    try:
        phy_visible = any(ieee80211_root.iterdir())
    except OSError:
        pass

    return {
        "python_version": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine() or platform.architecture()[0],
        "termux_api_cli": utilities["termux-wifi-scaninfo"],
        "iw_available": utilities["iw"],
        "ip_available": utilities["ip"],
        "airmon_ng_available": utilities["airmon-ng"],
        "wireless_interfaces_visible": interfaces,
        "wireless_phy_visible": phy_visible,
        "monitor_mode_supported": None,
        "packet_injection_supported": None,
        "hardware_note": (
            "La presencia de una interfaz no demuestra compatibilidad con modo monitor "
            "ni inyección. Este motor no cambia el estado de la radio ni realiza pruebas "
            "de transmisión; esas capacidades requieren validación independiente con "
            "hardware y controladores compatibles."
        ),
    }


def inventory_tools() -> dict:
    """List tool presence without executing any tool."""
    tools = []
    for item in TOOL_CATALOG:
        detected_command = _find_tool(item["commands"])
        tools.append({
            "id": item["id"],
            "name": item["name"],
            "purpose": item["purpose"],
            "risk": item["risk"],
            "execution": item["execution"],
            "detected": detected_command is not None,
            "detected_command": detected_command,
            "status": "detectada; no ejecutada" if detected_command else "no detectada",
        })
    return {
        "ok": True,
        "engine": "NEXUS Python Wireless Engine",
        "engine_version": ENGINE_VERSION,
        "mode": "read_only_inventory",
        "tools": tools,
        "environment": inspect_environment(),
        "safety": {
            "tools_executed": False,
            "tools_installed": False,
            "radio_modified": False,
            "credential_capture": False,
            "password_attempts": False,
            "note": (
                "Inventario informativo. No instala ni inicia herramientas ofensivas, "
                "no crea puntos de acceso, no captura autenticaciones y no prueba claves."
            ),
        },
    }
