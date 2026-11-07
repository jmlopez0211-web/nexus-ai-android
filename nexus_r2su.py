"""R2SU: persistent, bounded task scheduler for the NEXUS Python core.

Only named NEXUS diagnostic jobs are callable. No shell snippets, arbitrary
Python, plugin launch, credential testing, or public-network scans are accepted.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "1.0.0"
HOME = Path.home()
DB_PATH = Path(os.environ.get(
    "NEXUS_R2SU_DB", str(HOME / ".cache" / "nexus-ai" / "r2su.sqlite3")
)).expanduser()
MAX_TASKS = 100
MAX_INTERVAL_SECONDS = 30 * 24 * 60 * 60
MIN_INTERVAL_SECONDS = 60
MAX_HISTORY = 500
MAX_RESULT_CHARS = 12000
_LOCK = threading.RLock()
_WAKE = threading.Event()
_THREAD: threading.Thread | None = None
_STOP = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    return conn


def initialize():
    with _LOCK, _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, task_type TEXT NOT NULL,
                params TEXT NOT NULL, interval_seconds INTEGER,
                run_at TEXT, enabled INTEGER NOT NULL DEFAULT 1,
                next_run REAL NOT NULL, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
                started_at TEXT NOT NULL, finished_at TEXT NOT NULL,
                ok INTEGER NOT NULL, result TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_r2su_due ON tasks(enabled,next_run)")
        conn.commit()
    return {"ok": True, "version": VERSION, "database": str(DB_PATH)}


def _validate_task(task_type: str, params: dict[str, Any]):
    if task_type not in {"runtime_diagnostics", "wifi_inventory", "lan_scan"}:
        raise ValueError("Tipo de tarea no permitido. Usa runtime_diagnostics, wifi_inventory o lan_scan.")
    if not isinstance(params, dict):
        raise ValueError("params debe ser un objeto JSON.")
    if task_type == "lan_scan":
        if params.get("authorized") is not True:
            raise PermissionError("El inventario LAN requiere authorized=true.")
        import ipaddress
        try:
            ip = ipaddress.ip_address(str(params.get("target", "")).strip())
        except ValueError as exc:
            raise ValueError("Indica una IPv4 privada RFC1918 válida.") from exc
        ranges = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
        if ip.version != 4 or not any(ip in net for net in ranges):
            raise ValueError("R2SU solo permite una IPv4 privada RFC1918; no admite rangos ni objetivos públicos.")
        return {"target": str(ip), "authorized": True}
    if params:
        raise ValueError("Esta tarea no admite parámetros adicionales.")
    return {}


def _execute(task_type: str, params: dict[str, Any]):
    if task_type == "runtime_diagnostics":
        from nexus_runtime_inventory import diagnostics
        return diagnostics()
    if task_type == "wifi_inventory":
        from nexus_wireless_engine import _wifi_api_check
        return _wifi_api_check(timeout=20)
    if task_type == "lan_scan":
        from nexus_bridge_termux import scan_host
        return scan_host(params["target"])
    raise ValueError("Tipo de tarea no registrado.")


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)[:MAX_RESULT_CHARS]
    except (TypeError, ValueError):
        return json.dumps({"error": "resultado_no_serializable"})


def list_tasks(include_history: bool = False):
    initialize()
    with _LOCK, _connect() as conn:
        rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
        tasks = []
        for row in rows:
            item = dict(row)
            item["params"] = json.loads(item["params"])
            item["enabled"] = bool(item["enabled"])
            item["next_run_at"] = datetime.fromtimestamp(item.pop("next_run"), timezone.utc).isoformat()
            tasks.append(item)
        response = {"ok": True, "scheduler": "R2SU", "version": VERSION, "tasks": tasks}
        if include_history:
            runs = conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (MAX_HISTORY,)
            ).fetchall()
            response["history"] = [
                {**dict(row), "ok": bool(row["ok"]), "result": json.loads(row["result"])}
                for row in runs
            ]
        return response


def create_task(name: str, task_type: str, params: dict[str, Any] | None = None,
                interval_seconds: int | None = None, run_at: str | None = None):
    initialize()
    name = str(name or "").strip()[:80]
    if not name:
        raise ValueError("La tarea necesita un nombre.")
    clean = _validate_task(str(task_type), params or {})
    if interval_seconds is not None:
        if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, int):
            raise ValueError("interval_seconds debe ser un entero.")
        if not MIN_INTERVAL_SECONDS <= interval_seconds <= MAX_INTERVAL_SECONDS:
            raise ValueError("La periodicidad debe estar entre 60 segundos y 30 días.")
    if run_at is not None:
        if interval_seconds is not None:
            raise ValueError("Elige periodicidad o ejecución única, no ambas.")
        try:
            when = datetime.fromisoformat(str(run_at).replace("Z", "+00:00"))
            if when.tzinfo is None:
                raise ValueError
            due = when.timestamp()
        except (ValueError, TypeError) as exc:
            raise ValueError("run_at debe ser fecha ISO 8601 con zona horaria.") from exc
        if due < time.time() - 5:
            raise ValueError("La ejecución programada debe estar en el futuro.")
    else:
        due = time.time() + interval_seconds if interval_seconds else time.time()
    task_id = uuid.uuid4().hex[:12]
    now = _now()
    with _LOCK, _connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        if count >= MAX_TASKS:
            raise ValueError("Se alcanzó el límite de 100 tareas.")
        conn.execute(
            "INSERT INTO tasks(id,name,task_type,params,interval_seconds,run_at,enabled,next_run,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (task_id, name, task_type, json.dumps(clean), interval_seconds, run_at, 1, due, now, now)
        )
        conn.commit()
    _WAKE.set()
    return {"ok": True, "task_id": task_id, "message": "Tarea registrada en R2SU.", "next_run": datetime.fromtimestamp(due, timezone.utc).isoformat()}


def run_task(task_id: str):
    initialize()
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id=?", (str(task_id),)).fetchone()
    if row is None:
        raise ValueError("Tarea no encontrada.")
    started = _now()
    try:
        result = _execute(row["task_type"], json.loads(row["params"]))
        ok = bool(result.get("ok", True)) if isinstance(result, dict) else True
        payload = {"ok": ok, "task_type": row["task_type"], "data": result}
    except Exception as exc:
        ok = False
        payload = {"ok": False, "error": type(exc).__name__, "message": str(exc)[:500]}
    finished = _now()
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO runs(task_id,started_at,finished_at,ok,result) VALUES(?,?,?,?,?)",
            (row["id"], started, finished, int(ok), _safe_json(payload))
        )
        if row["interval_seconds"]:
            next_run = time.time() + int(row["interval_seconds"])
            conn.execute("UPDATE tasks SET next_run=?,updated_at=? WHERE id=?",
                         (next_run, finished, row["id"]))
        else:
            conn.execute("UPDATE tasks SET enabled=0,updated_at=? WHERE id=?", (finished, row["id"]))
        conn.execute("DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY id DESC LIMIT ?)", (MAX_HISTORY,))
        conn.commit()
    _WAKE.set()
    return {"ok": ok, "task_id": row["id"], "started_at": started, "finished_at": finished, "result": payload}


def set_task_enabled(task_id: str, enabled: bool):
    initialize()
    with _LOCK, _connect() as conn:
        cursor = conn.execute("UPDATE tasks SET enabled=?,updated_at=? WHERE id=?",
                              (int(bool(enabled)), _now(), str(task_id)))
        conn.commit()
    if not cursor.rowcount:
        raise ValueError("Tarea no encontrada.")
    _WAKE.set()
    return {"ok": True, "task_id": str(task_id), "enabled": bool(enabled)}


def delete_task(task_id: str):
    initialize()
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM runs WHERE task_id=?", (str(task_id),))
        cursor = conn.execute("DELETE FROM tasks WHERE id=?", (str(task_id),))
        conn.commit()
    if not cursor.rowcount:
        raise ValueError("Tarea no encontrada.")
    return {"ok": True, "task_id": str(task_id), "deleted": True}


def _scheduler_loop():
    global _STOP
    initialize()
    while not _STOP:
        now = time.time()
        due_id = None
        with _LOCK, _connect() as conn:
            row = conn.execute(
                "SELECT id FROM tasks WHERE enabled=1 AND next_run<=? ORDER BY next_run LIMIT 1", (now,)
            ).fetchone()
            if row:
                due_id = row["id"]
        if due_id:
            run_task(due_id)
            continue
        _WAKE.wait(5)
        _WAKE.clear()


def start_scheduler():
    global _THREAD, _STOP
    initialize()
    with _LOCK:
        if _THREAD is not None and _THREAD.is_alive():
            return {"ok": True, "running": True, "already_running": True}
        _STOP = False
        _THREAD = threading.Thread(target=_scheduler_loop, name="NEXUS-R2SU", daemon=True)
        _THREAD.start()
    return {"ok": True, "running": True, "scheduler": "R2SU"}


def stop_scheduler():
    global _STOP
    _STOP = True
    _WAKE.set()
    return {"ok": True, "running": False, "note": "El hilo se detendrá; las tareas y su historial permanecen guardados."}


def scheduler_status():
    running = bool(_THREAD is not None and _THREAD.is_alive() and not _STOP)
    return {"ok": True, "scheduler": "R2SU", "version": VERSION, "running": running,
            "database": str(DB_PATH), "task_count": len(list_tasks()["tasks"])}
