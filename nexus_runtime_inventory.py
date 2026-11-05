"""NEXUS cross-runtime inventory and safe maintenance diagnostics.

Read-only inventory by default. Repair is limited to NEXUS-owned directories;
it never installs packages, edits project source, or changes Android settings.
"""
from __future__ import annotations

import importlib.util
import importlib.metadata
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
HOME = Path.home()
APP_DIR = HOME / ".cache" / "nexus-ai"
OWNED_DIRS = (
    APP_DIR,
    APP_DIR / "reports",
    APP_DIR / "security-baselines",
    HOME / ".nexus-ai" / "plugins",
    HOME / ".nexus-ai" / "plugins" / "modules",
)
MAX_VERSION_SECONDS = 3

# These are descriptive catalogs, not claims that every runtime is installed.
RUNTIMES = (
    ("python", "Python", ("python", "python3"), "Motor principal; scripts y módulos internos"),
    ("node", "Node.js", ("node",), "JavaScript y herramientas Node"),
    ("bash", "Bash", ("bash",), "Automatización shell"),
    ("php", "PHP", ("php",), "Scripts y aplicaciones PHP"),
    ("java", "Java / JVM", ("java",), "Aplicaciones Java"),
    ("ruby", "Ruby", ("ruby",), "Scripts Ruby"),
    ("perl", "Perl", ("perl",), "Scripts Perl"),
    ("lua", "Lua", ("lua", "lua5.4", "lua5.3"), "Scripts Lua"),
    ("r", "R", ("R",), "Análisis estadístico"),
    ("git", "Git", ("git",), "Control de versiones"),
)

TOOLS = (
    ("nmap", "Nmap", ("nmap",), "Inventario de red autorizado"),
    ("aircrack-ng", "Aircrack-ng", ("aircrack-ng",), "Auditoría inalámbrica; detección solamente"),
    ("airmon-ng", "Airmon-ng", ("airmon-ng",), "Gestión de interfaces monitor; detección solamente"),
    ("airodump-ng", "Airodump-ng", ("airodump-ng",), "Inventario inalámbrico; detección solamente"),
    ("aireplay-ng", "Aireplay-ng", ("aireplay-ng",), "Herramienta de pruebas inalámbricas; detección solamente"),
    ("wifite", "Wifite2", ("wifite", "wifite2"), "Auditoría inalámbrica; detección solamente"),
    ("iw", "iw", ("iw",), "Información de interfaces inalámbricas"),
    ("iwconfig", "iwconfig", ("iwconfig",), "Información inalámbrica heredada"),
    ("ip", "iproute2", ("ip",), "Información de interfaces y rutas"),
    ("curl", "cURL", ("curl",), "Comprobación HTTP"),
    ("wget", "Wget", ("wget",), "Descarga HTTP"),
    ("openssl", "OpenSSL", ("openssl",), "Diagnóstico TLS"),
    ("sqlite3", "SQLite CLI", ("sqlite3",), "Consultas SQLite"),
    ("psql", "PostgreSQL CLI", ("psql",), "Cliente PostgreSQL"),
    ("duckdb", "DuckDB CLI", ("duckdb",), "Motor analítico DuckDB"),
    ("termux-api", "Termux:API Wi-Fi", ("termux-wifi-scaninfo",), "Lectura de resultados Wi-Fi Android"),
    ("git", "Git", ("git",), "Control de versiones"),
)

INTERNAL_MODULES = (
    ("main", "Servidor Flask y API", "main.py"),
    ("audit_engine", "Auditoría web HTTP", "audit_engine.py"),
    ("nexus_wireless_engine", "Motor Python inalámbrico", "nexus_wireless_engine.py"),
    ("nexus_plugin_manager", "Gestor de plugins Python", "nexus_plugin_manager.py"),
    ("nexus_security_audit", "Auditoría LAN defensiva", "nexus_security_audit.py"),
    ("nexus_audit_baseline", "Línea base de auditoría", "nexus_audit_baseline.py"),
    ("nexus_bridge_termux", "Puente Android local", "nexus_bridge_termux.py"),
    ("nexus_runtime_inventory", "Inventario de motores", "nexus_runtime_inventory.py"),
)

PYTHON_MODULES = (
    "flask", "groq", "requests", "sqlite3", "ssl", "json", "socket",
    "subprocess", "venv", "pip", "importlib.metadata",
)

SQL_ENGINES = (
    ("sqlite", "SQLite", "sqlite3", "built-in", "Base de datos local integrada en Python"),
    ("duckdb", "DuckDB", "duckdb", "optional", "Analítica local; requiere paquete duckdb"),
    ("postgresql", "PostgreSQL", "psycopg", "optional", "Servidor externo; requiere cliente o driver"),
)

def _which(names):
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None

def _version(path):
    if not path:
        return None
    try:
        result = subprocess.run(
            [path, "--version"], capture_output=True, text=True,
            timeout=MAX_VERSION_SECONDS, check=False, shell=False,
            env={**os.environ, "PAGER": "cat"},
        )
        line = (result.stdout or result.stderr or "").strip().splitlines()
        return line[0][:180] if line else ("exit " + str(result.returncode))
    except (OSError, subprocess.TimeoutExpired):
        return "versión no consultable"

def _python_packages():
    found = {}
    for name in PYTHON_MODULES:
        try:
            spec = importlib.util.find_spec(name)
            found[name] = bool(spec)
        except (ImportError, ValueError, AttributeError):
            found[name] = False
    return found

def _read_plugin_registry():
    registry = HOME / ".nexus-ai" / "plugins" / "registry.json"
    try:
        entries = json.loads(registry.read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            return {"registry_managed_by": "nexus_plugin_manager", "items": [], "error": "registro_no_es_lista"}
        return {"registry_managed_by": "nexus_plugin_manager", "registry_path": str(registry),
                "execution_requires_approval": True,
                "items": [{"id": str(item.get("id", "")), "name": str(item.get("name", item.get("id", ""))),
                           "approved": item.get("approved") is True, "entrypoint": str(item.get("entrypoint", ""))}
                          for item in entries if isinstance(item, dict)]}
    except FileNotFoundError:
        return {"registry_managed_by": "nexus_plugin_manager", "registry_path": str(registry),
                "execution_requires_approval": True, "items": []}
    except (OSError, ValueError, TypeError):
        return {"registry_managed_by": "nexus_plugin_manager", "registry_path": str(registry),
                "execution_requires_approval": True, "items": [], "error": "registro_no_legible"}

def inventory():
    runtimes = []
    for key, name, commands, purpose in RUNTIMES:
        path = _which(commands)
        runtimes.append({
            "id": key, "name": name, "purpose": purpose,
            "installed": bool(path), "path": path, "version": _version(path),
            "executable": bool(path), "execution_policy": "manual_authorization_required",
        })

    tools = []
    for key, name, commands, purpose in TOOLS:
        path = _which(commands)
        tools.append({
            "id": key, "name": name, "purpose": purpose,
            "installed": bool(path), "path": path,
            "version": "detectada; no ejecutada" if path else None,
            "execution_policy": "inventory_only",
        })

    modules = []
    known_paths = set()
    for module_id, name, path in INTERNAL_MODULES:
        known_paths.add(path)
        present = Path(path).is_file()
        modules.append({
            "id": module_id, "name": name, "path": path,
            "present": present, "status": "disponible" if present else "no encontrado",
        })

    for source in sorted(Path.cwd().glob("*.py")):
        if source.name not in known_paths:
            modules.append({"id": "project:" + source.stem, "name": source.name,
                            "path": source.name, "present": True,
                            "status": "archivo Python del proyecto; no ejecutado"})

    sql = []
    for key, name, module, kind, purpose in SQL_ENGINES:
        if key == "sqlite":
            installed = True
            detail = sqlite3.sqlite_version
            path = sys.executable
        else:
            installed = bool(importlib.util.find_spec(module))
            cli = _which((key if key != "postgresql" else "psql",))
            detail = _version(cli) if cli else ("módulo Python disponible" if installed else None)
            path = cli
        sql.append({
            "id": key, "name": name, "purpose": purpose,
            "installed": installed, "kind": kind, "module": module,
            "path": path, "version": detail,
            "default_mode": "read_only",
        })

    return {
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine_version": VERSION,
        "device": {
            "system": platform.system(), "release": platform.release(),
            "machine": platform.machine(), "architecture": platform.architecture()[0],
            "python": sys.version.split()[0], "python_executable": sys.executable,
            "prefix": sys.prefix, "base_prefix": sys.base_prefix,
            "termux": "com.termux" in os.environ.get("PREFIX", ""),
        },
        "runtimes": runtimes, "sql_engines": sql, "tools": tools,
        "internal_modules": modules, "python_modules": _python_packages(),
        "plugins": _read_plugin_registry(),
        "policy": {
            "inventory_read_only": True,
            "unknown_plugins_auto_executed": False,
            "package_installation_automatic": False,
            "system_files_modified": False,
        },
    }

def diagnostics():
    checks = []
    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": str(detail)[:240]})

    add("Python runtime", sys.version_info >= (3, 10), sys.version.split()[0])
    add("Arquitectura ARM64 compatible", platform.machine().lower() in ("aarch64", "arm64", "x86_64", "amd64"), platform.machine())
    add("SQLite integrado", sqlite3.sqlite_version_info >= (3, 20, 0), sqlite3.sqlite_version)
    packages = _python_packages()
    add("Flask disponible", packages.get("flask"), "Requerido por la API web")
    add("Groq SDK disponible", packages.get("groq"), "Necesario solo para el proveedor Groq")
    add("Requests disponible", packages.get("requests"), "Necesario para auditoría HTTP")
    try:
        with tempfile.TemporaryDirectory(prefix="nexus-check-") as tmp:
            probe = Path(tmp) / "probe.json"
            probe.write_text(json.dumps({"ok": True}), encoding="utf-8")
            valid = json.loads(probe.read_text(encoding="utf-8")).get("ok") is True
        add("Lectura/escritura temporal", valid, "Prueba temporal; no modifica archivos del proyecto")
    except OSError as exc:
        add("Lectura/escritura temporal", False, type(exc).__name__)

    for path in OWNED_DIRS:
        try:
            exists = path.exists()
            writable = exists and os.access(path, os.W_OK)
            add("Directorio NEXUS " + str(path.name), writable if exists else True,
                "Existe y es escribible" if writable else ("Se puede crear" if not exists else "No escribible"))
        except OSError as exc:
            add("Directorio NEXUS " + str(path.name), False, type(exc).__name__)

    passed = sum(1 for check in checks if check["ok"])
    return {
        "ok": passed == len(checks), "mode": "read_only_diagnostics",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"passed": passed, "failed": len(checks)-passed, "total": len(checks)},
        "checks": checks,
        "repair_policy": "Solo directorios propios de NEXUS; nunca instala paquetes ni modifica código o ajustes Android.",
    }

def repair_owned_storage(confirmed=False):
    if confirmed is not True:
        raise PermissionError("La reparación requiere confirmación explícita.")
    repaired = []
    errors = []
    for path in OWNED_DIRS:
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                path.chmod(0o700)
            except OSError:
                pass
            repaired.append({"path": str(path), "status": "ready"})
        except OSError as exc:
            errors.append({"path": str(path), "error": type(exc).__name__})
    return {
        "ok": not errors, "mode": "nexus_owned_storage_repair",
        "repaired": repaired, "errors": errors,
        "note": "Solo se han preparado carpetas de datos de NEXUS. No se han instalado paquetes, modificado scripts ni cambiado ajustes de Android.",
        "diagnostics_after": diagnostics(),
    }


def run_runtime_check(runtime_id, confirmed=False):
    """Run only fixed, harmless runtime smoke tests; never accept user-supplied commands."""
    if confirmed is not True:
        raise PermissionError("La prueba requiere confirmación explícita.")
    checks = {
        "python": (sys.executable, ["-c", "import json,sqlite3; print('PYTHON_OK', json.dumps({'sqlite': sqlite3.sqlite_version}))"]),
        "node": ("node", ["-e", "console.log('NODE_OK')"]),
        "bash": ("bash", ["-c", "printf 'BASH_OK\\n'"]),
        "php": ("php", ["-r", "echo \"PHP_OK\\n\";"]),
        "ruby": ("ruby", ["-e", "puts 'RUBY_OK'"]),
        "perl": ("perl", ["-e", "print \"PERL_OK\\n\";"]),
        "lua": ("lua", ["-e", "print('LUA_OK')"]),
        "java": ("java", ["-version"]),
    }
    if runtime_id == "sqlite":
        try:
            with sqlite3.connect(":memory:") as connection:
                value = connection.execute("SELECT 1").fetchone()[0]
            return {"ok": value == 1, "id": "sqlite", "mode": "in_memory_read_only_smoke_test",
                    "result": "SQLITE_OK" if value == 1 else "unexpected result"}
        except sqlite3.Error as exc:
            return {"ok": False, "id": "sqlite", "error": type(exc).__name__}
    if runtime_id == "duckdb":
        try:
            import duckdb
            value = duckdb.connect(":memory:", read_only=False).execute("SELECT 1").fetchone()[0]
            return {"ok": value == 1, "id": "duckdb", "mode": "in_memory_smoke_test", "result": "DUCKDB_OK"}
        except ImportError:
            return {"ok": False, "id": "duckdb", "error": "DuckDB no está instalado"}
        except Exception as exc:
            return {"ok": False, "id": "duckdb", "error": type(exc).__name__}
    if runtime_id == "postgresql":
        return {"ok": False, "id": "postgresql", "status": "not_configured",
                "note": "No se ha configurado una conexión PostgreSQL. No se intenta conectar ni modificar bases de datos."}
    if runtime_id not in checks:
        raise ValueError("Motor no autorizado para prueba.")
    executable, args = checks[runtime_id]
    path = shutil.which(executable) if executable != sys.executable else executable
    if not path:
        return {"ok": False, "id": runtime_id, "status": "not_installed"}
    try:
        result = subprocess.run([path, *args], capture_output=True, text=True,
                                timeout=8, check=False, shell=False,
                                env={"PATH": os.environ.get("PATH", ""), "HOME": str(HOME)})
        output = ((result.stdout or "") + (result.stderr or "")).strip()[-1000:]
        return {"ok": result.returncode == 0, "id": runtime_id,
                "returncode": result.returncode, "output": output,
                "mode": "fixed_safe_smoke_test"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "id": runtime_id, "error": "timeout"}
    except OSError as exc:
        return {"ok": False, "id": runtime_id, "error": type(exc).__name__}
