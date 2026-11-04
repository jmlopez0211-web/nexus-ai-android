"""NEXUS trusted Python plugin launcher.

Plugins are user-installed, explicitly approved Python entrypoints. This is a
process launcher, not a security sandbox: only install scripts you trust.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_HOME = Path(os.environ.get(
    "NEXUS_PLUGIN_HOME",
    str(Path.home() / ".nexus-ai" / "plugins")
)).expanduser()
REGISTRY = PLUGIN_HOME / "registry.json"
MAX_RUNTIME_SECONDS = 30
MAX_OUTPUT_CHARS = 12000


def _load_registry():
    try:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError):
        raise ValueError("El registro de plugins no se puede leer.")
    if not isinstance(data, list):
        raise ValueError("El registro de plugins debe ser una lista JSON.")
    return data


def list_plugins():
    PLUGIN_HOME.mkdir(parents=True, exist_ok=True)
    result = []
    seen = set()
    for item in _load_registry():
        if not isinstance(item, dict):
            continue
        plugin_id = str(item.get("id", "")).strip()
        entry = str(item.get("entrypoint", "")).strip()
        if not plugin_id or plugin_id in seen:
            continue
        seen.add(plugin_id)
        valid_id = all(ch.isalnum() or ch in "_-" for ch in plugin_id)
        path = (PLUGIN_HOME / "modules" / entry).resolve()
        root = (PLUGIN_HOME / "modules").resolve()
        exists = valid_id and path.is_relative_to(root) and path.suffix == ".py" and path.is_file()
        result.append({
            "id": plugin_id,
            "name": str(item.get("name") or plugin_id),
            "description": str(item.get("description") or "Módulo Python añadido por el usuario."),
            "entrypoint": entry,
            "approved": item.get("approved") is True,
            "detected": bool(exists),
            "status": "disponible" if exists and item.get("approved") is True
                      else "requiere aprobación o archivo válido",
            "timeout_seconds": MAX_RUNTIME_SECONDS,
        })
    return result


def launch_plugin(plugin_id):
    selected = next((p for p in _load_registry()
                     if isinstance(p, dict) and p.get("id") == plugin_id), None)
    if selected is None:
        raise ValueError("Plugin no registrado.")
    if selected.get("approved") is not True:
        raise PermissionError("El plugin requiere aprobación explícita en registry.json.")
    entry = str(selected.get("entrypoint", "")).strip()
    if not entry or Path(entry).is_absolute():
        raise ValueError("Entry point no válido.")
    root = (PLUGIN_HOME / "modules").resolve()
    script = (root / entry).resolve()
    if script.suffix != ".py" or not script.is_relative_to(root) or not script.is_file():
        raise ValueError("El script debe ser un archivo .py dentro de la carpeta modules.")
    args = selected.get("args", [])
    if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError("Los argumentos del plugin deben ser una lista de textos.")
    try:
        completed = subprocess.run(
            [sys.executable, str(script), *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=MAX_RUNTIME_SECONDS,
            check=False,
            shell=False,
            env={
                "PATH": os.environ.get("PATH", ""),
                "PREFIX": os.environ.get("PREFIX", ""),
                "HOME": os.environ.get("HOME", str(Path.home())),
                "PYTHONUNBUFFERED": "1",
            },
        )
        return {
            "ok": completed.returncode == 0,
            "plugin_id": plugin_id,
            "name": str(selected.get("name") or plugin_id),
            "started": True,
            "returncode": completed.returncode,
            "stdout": (completed.stdout or "")[-MAX_OUTPUT_CHARS:],
            "stderr": (completed.stderr or "")[-MAX_OUTPUT_CHARS:],
            "note": "Proceso Python iniciado. Los plugins aprobados se ejecutan con los permisos del usuario Termux; este lanzador no es un sandbox.",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False, "plugin_id": plugin_id, "name": str(selected.get("name") or plugin_id),
            "started": True, "timeout": True,
            "stdout": str(exc.stdout or "")[-MAX_OUTPUT_CHARS:],
            "stderr": str(exc.stderr or "")[-MAX_OUTPUT_CHARS:],
            "note": "El plugin superó el límite de 30 segundos y se detuvo.",
        }
