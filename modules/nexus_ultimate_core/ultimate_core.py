#!/usr/bin/env python3
"""NEXUS IA UltimateCore: motor local para Termux/Android ARM64.

Ejecución real de Nmap TCP-connect sobre un único host privado/loopback,
consultas Termux:API registradas, diagnóstico del entorno, logs e informes.
No sustituye el puente ni la interfaz web actuales.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

MODULE_DIR = Path(__file__).resolve().parent
TERMUX_ACTIONS: dict[str, tuple[str, ...]] = {
    "battery": ("termux-battery-status",),
    "wifi_connection": ("termux-wifi-connectioninfo",),
    "wifi_scan": ("termux-wifi-scaninfo",),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return str(value)


class UltimateCore:
    """Catálogo fijo de motores, ejecución controlada y resultados JSON."""

    def __init__(self, config_path: str | Path = "config.json") -> None:
        candidate = Path(config_path)
        self.config_path = candidate if candidate.is_absolute() else MODULE_DIR / candidate
        self.config = self.load_config()
        self.settings = self.config["settings"]
        self.paths = self.config["paths"]

        self.report_dir = self._owned_path(self.settings["report_directory"])
        self.log_dir = self._owned_path(self.settings["log_directory"])
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = self._configure_logging()

        self.modules: dict[str, Callable[..., dict[str, Any]]] = {
            "nmap": self.run_nmap,
            "termux_api": self.run_termux_api,
            "system_check": self.run_system_check,
        }

    @staticmethod
    def _defaults() -> dict[str, Any]:
        return {
            "settings": {
                "timeout": 45,
                "debug_mode": False,
                "logs_enabled": True,
                "auto_execute": False,
                "report_directory": "reports",
                "log_directory": "logs",
                "bridge_host": "127.0.0.1",
                "bridge_port": 8766,
            },
            "paths": {"nmap": "nmap"},
        }

    @staticmethod
    def _validate_relative_path(value: Any) -> Path:
        path = Path(str(value))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Las carpetas de informes y logs deben ser relativas.")
        return path

    def _owned_path(self, relative: str) -> Path:
        return MODULE_DIR / self._validate_relative_path(relative)

    def load_config(self) -> dict[str, Any]:
        """Carga config.json; si no existe, lo crea con valores conservadores."""
        if not self.config_path.exists():
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            config = self._defaults()
            temporary = self.config_path.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(config, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary.replace(self.config_path)
            return config

        try:
            loaded = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"No se pudo leer config.json: {type(exc).__name__}: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise ValueError("config.json debe contener un objeto JSON.")

        config = self._defaults()
        settings = loaded.get("settings", {})
        paths = loaded.get("paths", {})
        if not isinstance(settings, dict) or not isinstance(paths, dict):
            raise ValueError("'settings' y 'paths' deben ser objetos JSON.")
        config["settings"].update(settings)
        config["paths"].update(paths)

        try:
            timeout = int(config["settings"]["timeout"])
        except (TypeError, ValueError):
            timeout = 45
        config["settings"]["timeout"] = max(5, min(timeout, 180))
        config["settings"]["auto_execute"] = False
        config["settings"]["logs_enabled"] = bool(config["settings"]["logs_enabled"])
        config["settings"]["bridge_port"] = int(config["settings"]["bridge_port"])
        for key in ("report_directory", "log_directory"):
            self._validate_relative_path(config["settings"][key])
        return config

    def _configure_logging(self) -> logging.Logger:
        logger = logging.getLogger("nexus_ultimate_core")
        logger.setLevel(logging.DEBUG if self.settings["debug_mode"] else logging.INFO)
        logger.handlers.clear()
        logger.propagate = False
        if self.settings["logs_enabled"]:
            handler = logging.FileHandler(
                self.log_dir / "ultimate_core.log", encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s"
            ))
            logger.addHandler(handler)
        return logger

    def _timeout(self) -> int:
        return max(5, min(int(self.settings.get("timeout", 45)), 180))

    def _save_report(self, module: str, result: dict[str, Any]) -> str | None:
        execution_id = str(result.get("execution_id") or uuid.uuid4())
        filename = (
            f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_"
            f"{module}_{execution_id[:8]}.json"
        )
        destination = self.report_dir / filename
        payload = dict(result)
        payload.setdefault("generated_at", utc_now())
        try:
            destination.write_text(
                json.dumps(json_safe(payload), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return str(destination.relative_to(MODULE_DIR))
        except OSError as exc:
            self.logger.error("No se pudo guardar el informe (%s).", type(exc).__name__)
            return None

    def execute(
        self,
        module_name: str,
        target: str = "",
        *,
        action: str = "battery",
        authorization_confirmed: bool = False,
    ) -> dict[str, Any]:
        """Ejecuta únicamente módulos registrados y devuelve un resultado uniforme."""
        name = str(module_name or "").strip().lower()
        if name not in self.modules:
            return {
                "status": "error",
                "message": f"Módulo '{name}' inexistente.",
                "available_modules": sorted(self.modules),
            }

        execution_id = str(uuid.uuid4())
        started = time.monotonic()
        self.logger.info(
            "Inicio módulo=%s ejecución=%s objetivo=%s",
            name, execution_id, target or "Local",
        )
        try:
            if name == "nmap":
                result = self.run_nmap(
                    target or "127.0.0.1",
                    authorization_confirmed=authorization_confirmed,
                    execution_id=execution_id,
                )
            elif name == "termux_api":
                result = self.run_termux_api(action=action, execution_id=execution_id)
            else:
                result = self.run_system_check(execution_id=execution_id)
        except Exception as exc:
            self.logger.exception("Excepción durante el módulo %s.", name)
            result = {
                "status": "critical_error",
                "message": f"{type(exc).__name__}: {str(exc)[:300]}",
                "execution_id": execution_id,
            }

        result.setdefault("execution_id", execution_id)
        result.setdefault("module", name)
        result.setdefault("duration_ms", round((time.monotonic() - started) * 1000, 2))
        self.logger.info(
            "Fin módulo=%s ejecución=%s estado=%s",
            name, execution_id, result.get("status", "unknown"),
        )
        if result.get("status") == "success":
            report_path = self._save_report(name, result)
            if report_path:
                result["report_path"] = report_path
        return result

    @staticmethod
    def validate_target(target: str) -> str:
        try:
            address = ipaddress.ip_address(str(target).strip())
        except ValueError as exc:
            raise ValueError("Introduce una sola dirección IPv4 literal.") from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError("Solo se admiten direcciones IPv4.")
        if not (
            address.is_loopback
            or (
                address.is_private
                and not address.is_link_local
                and not address.is_multicast
                and not address.is_unspecified
                and not address.is_reserved
            )
        ):
            raise ValueError("El objetivo debe ser una IPv4 privada o loopback.")
        return str(address)

    @staticmethod
    def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
        if not xml_text.strip():
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []
        hosts = []
        for host in root.findall("host"):
            address_node = host.find("address")
            address = address_node.get("addr", "") if address_node is not None else ""
            ports = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service_node = port.find("service")
                service = {}
                if service_node is not None:
                    for key in ("name", "product", "version", "tunnel", "method"):
                        value = service_node.get(key)
                        if value:
                            service[key] = value
                ports.append({
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "state": "open",
                    "service": service,
                })
            hosts.append({"address": address, "open_ports": ports})
        return hosts

    def run_nmap(
        self,
        target: str = "127.0.0.1",
        *,
        authorization_confirmed: bool = False,
        execution_id: str | None = None,
    ) -> dict[str, Any]:
        if authorization_confirmed is not True:
            return {
                "status": "blocked",
                "message": "Confirma expresamente que tienes autorización para analizar este equipo.",
            }
        try:
            target = self.validate_target(target)
        except ValueError as exc:
            return {"status": "error", "message": str(exc)}

        configured = str(self.paths.get("nmap", "nmap"))
        binary = shutil.which(configured) if os.sep not in configured else (
            configured if os.path.isfile(configured) and os.access(configured, os.X_OK) else None
        )
        if not binary:
            return {
                "status": "unavailable",
                "message": "El binario Nmap no está instalado o no está en PATH.",
                "install_hint": "En Termux ejecuta: pkg install nmap",
            }

        command = [binary, "-n", "-sT", "-T3", "-F", "-oX", "-", target]
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True,
                timeout=self._timeout(), check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "target": target,
                "message": f"Nmap superó el límite de {self._timeout()} segundos.",
            }
        except OSError as exc:
            return {
                "status": "error",
                "target": target,
                "message": f"No se pudo iniciar Nmap: {type(exc).__name__}",
            }

        hosts = self.parse_nmap_xml(completed.stdout)
        ports = [
            {"host": host["address"], **port}
            for host in hosts for port in host["open_ports"]
        ]
        return {
            "status": "success" if completed.returncode == 0 else "error",
            "execution_id": execution_id,
            "engine": "nmap",
            "binary": binary,
            "target": target,
            "scope": "un único host IPv4 privado o loopback",
            "profile": "TCP connect; top 100 puertos frecuentes; T3",
            "exit_code": completed.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "hosts": hosts,
            "open_ports": ports,
            "open_count": len(ports),
            "stderr": (completed.stderr or "")[-2000:],
            "note": "Un puerto abierto es una observación; no demuestra por sí solo una vulnerabilidad.",
        }

    def run_termux_api(
        self,
        action: str = "battery",
        *,
        execution_id: str | None = None,
    ) -> dict[str, Any]:
        action_name = str(action or "").strip().lower()
        command = TERMUX_ACTIONS.get(action_name)
        if command is None:
            return {
                "status": "error",
                "message": "Acción Termux:API no registrada.",
                "available_actions": sorted(TERMUX_ACTIONS),
            }
        binary = shutil.which(command[0])
        if not binary:
            return {
                "status": "unavailable",
                "action": action_name,
                "message": f"No se encuentra {command[0]}.",
                "install_hint": "Instala el paquete termux-api y la app Termux:API compatible.",
            }
        try:
            completed = subprocess.run(
                [binary], capture_output=True, text=True, timeout=20, check=False
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "action": action_name, "message": "Termux:API agotó el tiempo límite."}
        except OSError as exc:
            return {"status": "error", "action": action_name, "message": f"No se pudo iniciar API: {type(exc).__name__}"}
        if completed.returncode != 0:
            return {
                "status": "error",
                "action": action_name,
                "exit_code": completed.returncode,
                "message": (completed.stderr or completed.stdout or "Error Termux:API")[-1000:],
            }
        try:
            data = json.loads(completed.stdout or "null")
        except json.JSONDecodeError:
            return {"status": "error", "action": action_name, "message": "La API no devolvió JSON válido."}
        return {
            "status": "success",
            "execution_id": execution_id,
            "engine": "termux_api",
            "action": action_name,
            "exit_code": completed.returncode,
            "count": len(data) if isinstance(data, list) else None,
            "data": json_safe(data),
            "note": (
                "Termux:API consulta los últimos resultados Wi-Fi disponibles en Android; "
                "no garantiza que se fuerce un nuevo escaneo de radio."
                if action_name == "wifi_scan"
                else "Consulta real de Termux:API."
            ),
        }

    def run_system_check(self, _target: str = "", *, execution_id: str | None = None) -> dict[str, Any]:
        programs = {
            "python": sys.executable,
            "nmap": shutil.which(str(self.paths.get("nmap", "nmap"))),
            "termux_battery_status": shutil.which("termux-battery-status"),
            "termux_wifi_scaninfo": shutil.which("termux-wifi-scaninfo"),
            "termux_wifi_connectioninfo": shutil.which("termux-wifi-connectioninfo"),
        }
        host = str(self.settings.get("bridge_host", "127.0.0.1"))
        port = int(self.settings.get("bridge_port", 8766))
        bridge_reachable = False
        try:
            with socket.create_connection((host, port), timeout=0.5):
                bridge_reachable = True
        except OSError:
            pass
        return {
            "status": "success",
            "execution_id": execution_id,
            "environment": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "machine": platform.machine(),
                "termux": bool(os.environ.get("TERMUX_VERSION")),
                "termux_version": os.environ.get("TERMUX_VERSION"),
            },
            "tools": {
                name: {"available": bool(path), "path": path}
                for name, path in programs.items()
            },
            "bridge": {
                "host": host,
                "port": port,
                "tcp_listener_reachable": bridge_reachable,
                "note": "La conexión TCP no autentica ni valida endpoints del puente.",
            },
            "auto_execute": False,
        }


# Compatibilidad de importación con el primer núcleo generado.
NexusCore = UltimateCore


def main() -> int:
    parser = argparse.ArgumentParser(description="NEXUS IA UltimateCore")
    parser.add_argument("--module", choices=("system_check", "termux_api", "nmap"), default="system_check")
    parser.add_argument("--action", choices=tuple(TERMUX_ACTIONS), default="battery")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--yes-authorized", action="store_true")
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    app = UltimateCore(args.config)
    authorized = args.yes_authorized
    if args.module == "nmap" and not authorized and sys.stdin.isatty():
        authorized = input(f"¿Tienes autorización para analizar {args.target}? Escribe SI: ").strip() == "SI"

    result = app.execute(
        args.module,
        args.target,
        action=args.action,
        authorization_confirmed=authorized,
    )
    print(json.dumps(json_safe(result), ensure_ascii=False, indent=2))
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
