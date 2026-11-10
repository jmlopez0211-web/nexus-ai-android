"""Read-only Android Wi-Fi chipset, driver, interface, permission and scan diagnostics."""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

TIMEOUT = 12
MAX_TEXT = 1600
INTERFACE_PATHS = (Path("/sys/class/net/wlan0"), Path("/sys/class/net/wifi0"))


def _run(command: str, args: tuple[str, ...] = (), timeout: int = TIMEOUT) -> dict[str, Any]:
    path = shutil.which(command)
    if not path:
        return {"available": False, "ok": False, "returncode": None, "stdout": "",
                "stderr": "", "error": "comando_no_disponible"}
    try:
        result = subprocess.run([path, *args], capture_output=True, text=True,
                                timeout=timeout, check=False)
        return {"available": True, "ok": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": (result.stdout or "")[:MAX_TEXT],
                "stderr": (result.stderr or "")[:MAX_TEXT],
                "error": None if result.returncode == 0 else "comando_devolvio_error"}
    except subprocess.TimeoutExpired:
        return {"available": True, "ok": False, "returncode": None,
                "stdout": "", "stderr": "", "error": "timeout"}
    except OSError as exc:
        return {"available": True, "ok": False, "returncode": None,
                "stdout": "", "stderr": "", "error": type(exc).__name__}


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()[:MAX_TEXT]
    except OSError:
        return None


def _link_target(path: Path) -> str | None:
    try:
        return str(path.resolve(strict=True))
    except (OSError, RuntimeError):
        return None


def _safe_identifier(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    return value[:160] if re.fullmatch(r"[A-Za-z0-9_.:/+ -]+", value) else None


def inspect_hardware() -> dict[str, Any]:
    interface = next((p for p in INTERFACE_PATHS if p.exists()), None)
    if interface is None:
        return {"interface": None, "available": False, "state": None,
                "driver": None, "module": None, "chipset_ids": {},
                "device_path": None, "diagnosis": "No se ve wlan0/wifi0 en sysfs; Android puede ocultar la interfaz a Termux."}
    device = interface / "device"
    driver_link = device / "driver"
    module_link = driver_link / "module"
    driver_path = _link_target(driver_link)
    module_path = _link_target(module_link)
    ids = {}
    for name in ("vendor", "device", "subsystem_vendor", "subsystem_device"):
        value = _read(device / name)
        if value:
            ids[name] = value
    uevent = _read(device / "uevent")
    if uevent:
        for line in uevent.splitlines():
            if line.startswith(("DRIVER=", "PCI_ID=", "SDIO_ID=", "MODALIAS=")):
                key, value = line.split("=", 1)
                ids[key.lower()] = value[:160]
    state = _read(interface / "operstate")
    driver = Path(driver_path).name if driver_path else None
    module = Path(module_path).name if module_path else None
    return {
        "interface": interface.name, "available": True, "state": state,
        "driver": _safe_identifier(driver), "module": _safe_identifier(module),
        "chipset_ids": ids, "device_path": _safe_identifier(str(device.resolve())) if device.exists() else None,
        "diagnosis": ("Interfaz visible y controlador enlazado." if driver else
                      "Interfaz visible, pero sysfs no expone un enlace de controlador identificable."),
    }


def _android_properties() -> dict[str, Any]:
    names = ("ro.product.model", "ro.hardware", "ro.board.platform",
             "ro.build.version.release", "ro.build.version.sdk")
    values = {}
    for name in names:
        result = _run("getprop", (name,))
        if result["ok"] and result["stdout"]:
            values[name] = result["stdout"].strip()[:120]
    return values


def _android_services() -> dict[str, Any]:
    wifi = _run("dumpsys", ("wifi",), timeout=15)
    package = _run("dumpsys", ("package", "com.termux"), timeout=15)
    text = wifi["stdout"].lower()
    state = "unknown"
    if wifi["ok"]:
        if re.search(r"wifi is disabled|wifienabled=false|wifi enabled: false", text):
            state = "disabled"
        elif re.search(r"wifi is enabled|wifienabled=true|wifi enabled: true", text):
            state = "enabled"
    permissions = []
    for line in package["stdout"].splitlines():
        lower = line.lower()
        if "android.permission.access_fine_location" in lower or "android.permission.nearby_wifi_devices" in lower:
            if "granted=true" in lower or "granted: true" in lower:
                permissions.append(line.strip()[:200])
    return {
        "wifi_service": {"available": wifi["available"], "query_ok": wifi["ok"],
                         "state": state, "error": wifi["error"]},
        "termux_package": {"available": package["available"], "query_ok": package["ok"],
                           "location_or_nearby_permissions_seen": permissions,
                           "permission_state": "granted" if permissions else "not_confirmed"},
        "note": "La salida de dumpsys puede estar limitada por el aislamiento Android; ausencia de permiso visible no prueba que esté denegado."
    }


def _scan_api() -> dict[str, Any]:
    scan = _run("termux-wifi-scaninfo", timeout=25)
    connection = _run("termux-wifi-connectioninfo", timeout=15)
    parsed = None
    if scan["ok"]:
        try:
            data = json.loads(scan["stdout"] or "[]")
            if isinstance(data, list):
                parsed = data
            else:
                scan["ok"] = False
                scan["error"] = "respuesta_no_es_lista"
        except json.JSONDecodeError:
            scan["ok"] = False
            scan["error"] = "json_invalido"
    count = len(parsed) if parsed is not None else 0
    # Never include SSIDs, BSSIDs, IPs or connection identifiers in this report.
    return {
        "scaninfo": {"available": scan["available"], "ok": scan["ok"],
                     "network_count": count, "result": "networks_found" if count else
                     ("empty_android_result" if scan["ok"] else "scan_unavailable_or_failed"),
                     "error": scan["error"], "stderr": scan["stderr"][:500]},
        "connectioninfo": {"available": connection["available"], "ok": connection["ok"],
                           "error": connection["error"]},
        "behavior": "Termux:API lee los últimos resultados publicados por Android; no garantiza iniciar un nuevo escaneo de radio.",
    }


def diagnose_wifi_driver() -> dict[str, Any]:
    hardware = inspect_hardware()
    services = _android_services()
    scan = _scan_api()
    props = _android_properties()
    findings = []
    if not hardware["available"]:
        findings.append({"level": "warning", "code": "WIFI_INTERFACE_NOT_VISIBLE",
                         "message": "La interfaz Wi-Fi no es visible en sysfs desde este entorno."})
    elif not hardware["driver"]:
        findings.append({"level": "warning", "code": "WIFI_DRIVER_NOT_IDENTIFIED",
                         "message": "La interfaz existe, pero no se pudo resolver el controlador en sysfs."})
    if services["wifi_service"]["state"] == "disabled":
        findings.append({"level": "warning", "code": "ANDROID_WIFI_DISABLED",
                         "message": "El servicio Android informa que Wi-Fi está desactivado."})
    if services["termux_package"]["permission_state"] != "granted":
        findings.append({"level": "info", "code": "ANDROID_PERMISSION_NOT_CONFIRMED",
                         "message": "Termux no expone permisos de ubicación/Wi-Fi como concedidos en dumpsys; revisar Ajustes de Android."})
    if not scan["scaninfo"]["available"]:
        findings.append({"level": "error", "code": "TERMUX_WIFI_API_MISSING",
                         "message": "No se encuentra termux-wifi-scaninfo en PATH."})
    elif not scan["scaninfo"]["ok"]:
        findings.append({"level": "error", "code": "TERMUX_WIFI_SCAN_FAILED",
                         "message": "Termux:API no pudo completar o interpretar la consulta Wi-Fi."})
    elif scan["scaninfo"]["network_count"] == 0:
        findings.append({"level": "warning", "code": "ANDROID_SCAN_RESULTS_EMPTY",
                         "message": "Termux:API respondió correctamente, pero Android devolvió cero resultados."})
    else:
        findings.append({"level": "info", "code": "ANDROID_SCAN_RESULTS_AVAILABLE",
                         "message": "Android proporcionó resultados Wi-Fi."})
    return {
        "ok": True, "component": "NEXUS Android Wi-Fi Driver Diagnostics",
        "version": "1.0.0", "mode": "read_only",
        "device": {"model": props.get("ro.product.model"),
                   "hardware": props.get("ro.hardware"),
                   "board_platform": props.get("ro.board.platform"),
                   "android_release": props.get("ro.build.version.release"),
                   "sdk": props.get("ro.build.version.sdk"),
                   "kernel": platform.release(), "machine": platform.machine()},
        "hardware": hardware, "android": services, "termux_api": scan,
        "findings": findings,
        "limitations": [
            "El chipset solo se identifica si Android expone IDs en sysfs o uevent.",
            "Termux puede no tener permiso para leer todos los datos de hardware o dumpsys.",
            "No se modifica el kernel, firmware, controlador ni estado de radio.",
            "No se guardan SSID, BSSID, IP ni datos de conexión en el informe."
        ]
    }
