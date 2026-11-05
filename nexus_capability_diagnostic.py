"""Read-only, evidence-based runtime and wireless capability diagnostics for NEXUS.

This module never enables monitor mode, changes interfaces, injects frames, captures
credentials, or elevates privileges. It reports observable facts and keeps unknowns explicit.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path

DIAGNOSTIC_VERSION = "1.0.0"
COMMAND_TIMEOUT_SECONDS = 1.5
PROOT_TIMEOUT_SECONDS = 18

TOOL_DEFINITIONS = (
    {"id": "wacker", "name": "Wacker", "commands": ("wacker.py", "wacker"), "probe_args": ("--help",), "environment": "either"},
    {"id": "hostapd_mana", "name": "hostapd-mana", "commands": ("hostapd-mana",), "probe_args": ("--help",), "environment": "either"},
    {"id": "wifite2", "name": "Wifite2", "commands": ("wifite", "wifite2"), "probe_args": ("--help",), "environment": "either"},
    {"id": "eaphammer", "name": "EAPHammer", "commands": ("eaphammer",), "probe_args": ("--help",), "environment": "either"},
    {"id": "aircrack_ng", "name": "Aircrack-ng", "commands": ("aircrack-ng",), "probe_args": ("--help",), "environment": "either"},
    {"id": "airmon_ng", "name": "airmon-ng", "commands": ("airmon-ng",), "probe_args": ("--help",), "environment": "either"},
    {"id": "airodump_ng", "name": "airodump-ng", "commands": ("airodump-ng",), "probe_args": ("--help",), "environment": "either"},
    {"id": "aireplay_ng", "name": "aireplay-ng", "commands": ("aireplay-ng",), "probe_args": ("--help",), "environment": "either"},
    {"id": "iw", "name": "iw", "commands": ("iw",), "probe_args": ("--version",), "environment": "either"},
    {"id": "ip", "name": "ip", "commands": ("ip",), "probe_args": ("-Version",), "environment": "either"},
    {"id": "termux_wifi_api", "name": "Termux:API Wi-Fi", "commands": ("termux-wifi-scaninfo",), "probe_args": (), "environment": "termux"},
)


def _read_text(path: str, limit: int = 12000) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _capability_bits(status_text: str) -> dict:
    match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status_text, re.MULTILINE)
    if not match:
        return {"effective_hex": None, "cap_net_admin": None, "cap_net_raw": None,
                "note": "El kernel no expuso CapEff en /proc/self/status."}
    value = int(match.group(1), 16)
    return {"effective_hex": match.group(1).lower(),
            "cap_net_admin": bool(value & (1 << 12)),
            "cap_net_raw": bool(value & (1 << 13)),
            "note": "Bits declarados por el namespace actual; en Proot no prueban privilegios reales del kernel Android."}


def _groups() -> list[dict]:
    result = []
    try:
        import grp
        for gid in sorted(set(os.getgroups())):
            try:
                name = grp.getgrgid(gid).gr_name
            except KeyError:
                name = None
            result.append({"gid": gid, "name": name})
    except (OSError, ImportError):
        return []
    return result


def inspect_privileges(context: str = "termux") -> dict:
    try:
        uid, euid, gids = os.getuid(), os.geteuid(), list(os.getgroups())
    except AttributeError:
        uid = euid = None
        gids = []
    status_text = _read_text("/proc/self/status")
    is_uid_zero = euid == 0
    is_proot = context == "ubuntu_proot" or bool(
        os.environ.get("PROOT_TMP_DIR") or os.environ.get("PROOT_LOADER")
    )
    if context == "ubuntu_proot" or is_proot:
        proot_root = is_uid_zero
        android_root = "not_inferred_from_proot"
    else:
        proot_root = False
        if context == "termux":
            android_root = "not_root" if not is_uid_zero else "uid_zero_not_independently_verified"
        else:
            android_root = True if platform.system() == "Android" and is_uid_zero else (
                False if platform.system() == "Android" else "not_android_runtime"
            )
    return {
        "uid": uid, "effective_uid": euid, "groups": _groups(),
        "group_ids": gids, "uid_zero_in_current_namespace": is_uid_zero,
        "proot_detected": is_proot, "root_in_proot": proot_root,
        "android_root": android_root, "capabilities": _capability_bits(status_text),
        "permission_note": (
            "UID 0 dentro de Proot no equivale a root Android ni garantiza acceso al kernel, Netlink o dispositivos físicos. No se ha intentado elevar privilegios."
            if is_proot else
            "Se muestran únicamente UID, grupos y capacidades declaradas del proceso actual. No se ha intentado elevar privilegios."
        ),
    }


def _find_command(commands: tuple[str, ...]) -> str | None:
    for command in commands:
        path = shutil.which(command)
        if path:
            return path
    return None


def _probe_executable(definition: dict) -> dict:
    path = _find_command(definition["commands"])
    if not path:
        return {"installed": False, "executable_permission": False,
                "execution_probe": "not_installed", "path": None,
                "exit_code": None, "version_or_help": None}
    executable = os.access(path, os.X_OK)
    if not executable:
        return {"installed": True, "executable_permission": False,
                "execution_probe": "permission_denied", "path": path,
                "exit_code": None, "version_or_help": None}
    try:
        completed = subprocess.run([path, *definition["probe_args"]],
                                   capture_output=True, text=True,
                                   timeout=COMMAND_TIMEOUT_SECONDS, check=False)
        if definition["id"] == "termux_wifi_api":
            # Never expose SSIDs/BSSIDs in a capability report.
            try:
                payload = json.loads(completed.stdout or "[]")
                valid = isinstance(payload, list)
                count = sum(1 for item in payload if isinstance(item, dict)) if valid else 0
            except (TypeError, ValueError, json.JSONDecodeError):
                valid, count = False, 0
            return {"installed": True, "executable_permission": True,
                    "execution_probe": "responded" if completed.returncode == 0 and valid else "invalid_response",
                    "path": path, "exit_code": completed.returncode,
                    "version_or_help": None, "network_count": count,
                    "network_identifiers_included": False}
        output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
        responded = completed.returncode == 0 or bool(output)
        return {"installed": True, "executable_permission": True,
                "execution_probe": "responded" if responded else "no_response",
                "path": path, "exit_code": completed.returncode,
                "version_or_help": output[:240] or None}
    except subprocess.TimeoutExpired:
        return {"installed": True, "executable_permission": True,
                "execution_probe": "timeout", "path": path,
                "exit_code": None, "version_or_help": None}
    except OSError as exc:
        return {"installed": True, "executable_permission": True,
                "execution_probe": "execution_error", "path": path,
                "exit_code": None, "version_or_help": type(exc).__name__}


def _interfaces() -> tuple[list[str], list[str]]:
    names, phys = [], []
    try:
        names = sorted(item.name for item in Path("/sys/class/net").iterdir())
    except OSError:
        pass
    try:
        phys = sorted(item.name for item in Path("/sys/class/ieee80211").iterdir())
    except OSError:
        pass
    return names, phys


def _iw_probe(iw_path: str | None) -> dict:
    if not iw_path:
        return {"installed": False, "netlink": "unknown", "wireless_interfaces": [],
                "phy_devices": [], "monitor_mode": {"status": "unknown", "evidence": "iw no está instalado en este entorno."}}
    try:
        dev = subprocess.run([iw_path, "dev"], capture_output=True, text=True,
                             timeout=COMMAND_TIMEOUT_SECONDS, check=False)
        phy = subprocess.run([iw_path, "list"], capture_output=True, text=True,
                             timeout=COMMAND_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        return {"installed": True, "netlink": "timeout", "wireless_interfaces": [],
                "phy_devices": [], "monitor_mode": {"status": "unknown", "evidence": "La consulta iw superó el límite de tiempo."}}
    except OSError as exc:
        return {"installed": True, "netlink": "execution_error", "wireless_interfaces": [],
                "phy_devices": [], "monitor_mode": {"status": "unknown", "evidence": type(exc).__name__}}
    combined = ((dev.stdout or "") + (dev.stderr or "") + (phy.stdout or "") + (phy.stderr or "")).lower()
    if dev.returncode == 0 and phy.returncode == 0:
        netlink = "accessible"
    elif "generic netlink" in combined or "operation not permitted" in combined or "permission denied" in combined:
        netlink = "blocked_or_unavailable"
    else:
        netlink = "unavailable_or_error"
    interface_names = re.findall(r"^\s*Interface\s+(\S+)", dev.stdout or "", re.MULTILINE)
    phy_names = re.findall(r"^Wiphy\s+(\S+)", phy.stdout or "", re.MULTILINE)
    section = re.search(r"Supported interface modes\s*:\s*(.*?)(?:\n\S|\Z)", phy.stdout or "", re.DOTALL)
    monitor_advertised = bool(section and re.search(r"\*\s*monitor\b", section.group(1)))
    if netlink != "accessible":
        monitor = {"status": "blocked_or_unknown", "driver_advertises": None,
                   "evidence": (dev.stderr or phy.stderr or "Netlink/iw no accesible.").strip()[:240]}
    elif monitor_advertised:
        monitor = {"status": "advertised_not_functionally_verified", "driver_advertises": True,
                   "evidence": "El controlador anuncia monitor en iw list; no se ha creado ni activado una interfaz monitor."}
    else:
        monitor = {"status": "not_advertised_or_unknown", "driver_advertises": False,
                   "evidence": "La consulta no muestra monitor entre los modos soportados."}
    return {"installed": True, "netlink": netlink, "wireless_interfaces": interface_names,
            "phy_devices": phy_names, "monitor_mode": monitor,
            "raw_error": (dev.stderr or phy.stderr or "").strip()[:240] or None}


def inspect_runtime(context: str = "termux") -> dict:
    tools = []
    for definition in TOOL_DEFINITIONS:
        if definition["environment"] in ("either", context):
            tools.append({"id": definition["id"], "name": definition["name"], **_probe_executable(definition)})
    names, phys = _interfaces()
    iw_path = next((item["path"] for item in tools if item["id"] == "iw" and item.get("path")), None)
    iw = _iw_probe(iw_path)
    environment = "Ubuntu Proot" if context == "ubuntu_proot" else (
        "Termux / Android" if "com.termux" in os.environ.get("PREFIX", "") else platform.platform()
    )
    return {
        "context": context, "environment": environment,
        "python_version": platform.python_version(), "kernel_release": platform.release(),
        "architecture": platform.machine(), "tools": tools,
        "privileges": inspect_privileges(context), "network_interfaces": names,
        "wireless_interfaces_sysfs": [name for name in names if Path(f"/sys/class/net/{name}/wireless").exists()],
        "wireless_interfaces_iw": iw["wireless_interfaces"],
        "wireless_phy_sysfs": phys,
        "hardware_access": {
            "status": "visible" if phys or iw["wireless_interfaces"] else (
                "blocked_or_not_exposed" if iw["netlink"] == "blocked_or_unavailable" else "not_detected"
            ),
            "iw_netlink": iw["netlink"],
            "evidence": iw.get("raw_error") or "Visibilidad de interfaces y PHY consultada en sysfs/iw.",
        },
        "monitor_mode": iw["monitor_mode"],
        "packet_injection": {"status": "unknown", "verified": False,
            "evidence": "No existe una comprobación pasiva que demuestre inyección real. NEXUS no envía tramas de prueba ni realiza ataques."},
        "diagnostic_limits": [
            "La presencia del ejecutable no demuestra acceso al hardware.",
            "UID 0 en Proot no equivale a root Android.",
            "El modo monitor anunciado por un controlador no prueba que pueda activarse.",
            "La inyección permanece desconocida sin una prueba técnica controlada sobre hardware de laboratorio.",
        ],
    }


_REMOTE_SCRIPT = r'''import json, os, platform, re, shutil, subprocess
names = ("wacker", "hostapd-mana", "wifite", "eaphammer", "aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng", "iw", "ip")
args = {"iw": ["--version"], "ip": ["-Version"]}
items = []
for name in names:
    path = shutil.which(name)
    row = {"name": name, "installed": bool(path), "path": path, "executable_permission": bool(path and os.access(path, os.X_OK)), "execution_probe": "not_installed" if not path else "unknown", "exit_code": None}
    if path and row["executable_permission"]:
        try:
            p = subprocess.run([path] + args.get(name, ["--help"]), capture_output=True, text=True, timeout=1.2, check=False)
            row["exit_code"] = p.returncode
            row["execution_probe"] = "responded" if p.returncode == 0 or p.stdout or p.stderr else "no_response"
        except subprocess.TimeoutExpired:
            row["execution_probe"] = "timeout"
        except OSError:
            row["execution_probe"] = "execution_error"
    items.append(row)
status = ""
try:
    status = open("/proc/self/status", encoding="utf-8").read()
except OSError:
    pass
m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status, re.M)
cap = int(m.group(1), 16) if m else None
try:
    uid, euid = os.getuid(), os.geteuid()
except AttributeError:
    uid = euid = None
interfaces, phys = [], []
try:
    interfaces = sorted(os.listdir("/sys/class/net"))
except OSError:
    pass
try:
    phys = sorted(os.listdir("/sys/class/ieee80211"))
except OSError:
    pass
iw = shutil.which("iw")
wireless_iw = []
netlink, monitor, iw_error = "unknown", {"status":"unknown","driver_advertises":None,"evidence":"iw no disponible"}, None
if iw:
    try:
        d = subprocess.run([iw,"dev"],capture_output=True,text=True,timeout=1.5)
        l = subprocess.run([iw,"list"],capture_output=True,text=True,timeout=1.5)
        combined=(d.stdout or "")+(d.stderr or "")+(l.stdout or "")+(l.stderr or "")
        wireless_iw=re.findall(r"^\\s*Interface\\s+(\\S+)",d.stdout or "",re.M)
        if d.returncode == 0 and l.returncode == 0: netlink="accessible"
        elif "generic netlink" in combined.lower() or "operation not permitted" in combined.lower(): netlink="blocked_or_unavailable"
        else: netlink="unavailable_or_error"
        section=re.search(r"Supported interface modes\s*:\s*(.*?)(?:\n\S|\Z)",l.stdout or "",re.S)
        advertised=bool(section and re.search(r"\*\s*monitor\b",section.group(1)))
        monitor={"status":"advertised_not_functionally_verified" if netlink=="accessible" and advertised else ("not_advertised_or_unknown" if netlink=="accessible" else "blocked_or_unknown"),"driver_advertises":advertised if netlink=="accessible" else None,"evidence":"Controlador anuncia monitor; no activado" if advertised else (l.stderr or d.stderr or "No se ha podido demostrar el modo monitor")[:240]}
        iw_error=(d.stderr or l.stderr or "")[:240] or None
    except Exception as e:
        netlink="probe_error"; iw_error=type(e).__name__
print(json.dumps({"environment":"Ubuntu Proot","python_version":platform.python_version(),"kernel_release":platform.release(),"architecture":platform.machine(),"tools":items,"privileges":{"uid":uid,"effective_uid":euid,"uid_zero_in_current_namespace":euid==0,"root_in_proot":euid==0,"android_root":"not_inferred_from_proot","capabilities":{"effective_hex":m.group(1).lower() if m else None,"cap_net_admin":bool(cap & (1<<12)) if cap is not None else None,"cap_net_raw":bool(cap & (1<<13)) if cap is not None else None},"permission_note":"UID 0 corresponde al namespace Proot; no equivale a root Android."},"network_interfaces":interfaces,"wireless_interfaces_iw":wireless_iw,"wireless_phy_sysfs":phys,"hardware_access":{"status":"visible" if phys else ("blocked_or_not_exposed" if netlink=="blocked_or_unavailable" else "not_detected"),"iw_netlink":netlink,"evidence":iw_error or "Consultas sysfs e iw."},"monitor_mode":monitor,"packet_injection":{"status":"unknown","verified":False,"evidence":"No se envían tramas de prueba ni se realizan ataques."}},ensure_ascii=False))'''


def inspect_ubuntu_proot(timeout: int = PROOT_TIMEOUT_SECONDS) -> dict:
    launcher = shutil.which("proot-distro")
    if not launcher:
        return {"available": False, "status": "proot_distro_not_found", "environment": "Ubuntu Proot"}
    try:
        completed = subprocess.run(
            [launcher, "login", "ubuntu", "--", "python3", "-c", _REMOTE_SCRIPT],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if completed.returncode != 0:
            return {"available": True, "status": "probe_failed", "exit_code": completed.returncode,
                    "error": (completed.stderr or completed.stdout or "Proot diagnostic failed")[:300],
                    "environment": "Ubuntu Proot"}
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        return {"available": True, "status": "ok", **payload}
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "timeout", "environment": "Ubuntu Proot",
                "error": "El diagnóstico Ubuntu superó el límite de tiempo."}
    except (OSError, ValueError, IndexError, json.JSONDecodeError) as exc:
        return {"available": True, "status": "probe_error", "environment": "Ubuntu Proot",
                "error": type(exc).__name__}


def build_capability_report(include_ubuntu: bool = True) -> dict:
    return {
        "ok": True, "diagnostic": "NEXUS Hardware & Permissions Diagnostic",
        "version": DIAGNOSTIC_VERSION, "mode": "read_only_capability_assessment",
        "generated_at_epoch": int(time.time()),
        "environments": {
            "termux": inspect_runtime("termux"),
            "ubuntu_proot": inspect_ubuntu_proot() if include_ubuntu else {
                "available": False, "status": "not_requested", "environment": "Ubuntu Proot"
            },
        },
        "safety": {
            "interfaces_changed": False, "monitor_mode_enabled": False,
            "frames_injected": False, "credentials_captured": False,
            "privileges_escalated": False,
        },
        "interpretation": (
            "installed means found on PATH; execution_probe means a harmless help/version command responded; "
            "monitor_mode is driver-advertisement evidence only; packet_injection remains unknown unless independently validated in a controlled lab."
        ),
    }
