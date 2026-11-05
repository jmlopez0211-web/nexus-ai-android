"""Local privacy-preserving baseline comparison for NEXUS LAN audits."""
from __future__ import annotations
import json, os, re, tempfile
from datetime import datetime, timezone
from pathlib import Path

BASELINE_DIR = Path.home() / ".cache" / "nexus-ai" / "security-baselines"
BASELINE_SCHEMA = 1

def _safe_target(target):
    if not re.fullmatch(r"(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}", str(target)):
        raise ValueError("Destino no válido para línea base.")
    parts=[int(x) for x in target.split(".")]
    if len(parts)!=4 or any(x>255 for x in parts): raise ValueError("Destino IPv4 no válido.")
    return target

def _snapshot(report):
    services={}
    for item in report.get("services") or []:
        port=str(item.get("port")); cert=item.get("certificate") or {}; tls=item.get("tls") or {}
        services[port]={
            "scheme":item.get("scheme"),"reachable":bool(item.get("reachable")),
            "http_status":item.get("http_status"),
            "headers":dict(sorted((item.get("headers") or {}).items())),
            "cookies":sorted([{"name":c.get("name"),"secure":bool(c.get("secure")),
                "httponly":bool(c.get("httponly")),"samesite":c.get("samesite")}
                for c in item.get("cookies") or []],key=lambda c:c["name"] or ""),
            "tls_status":tls.get("status"),"certificate_sha256":cert.get("sha256_fingerprint"),
            "certificate_not_after":cert.get("not_after"),"certificate_subject":cert.get("subject"),
            "certificate_issuer":cert.get("issuer")}
    scan=report.get("scan") or {}
    return {"schema_version":BASELINE_SCHEMA,"target":report["target"],
        "captured_at":report.get("generated_at") or datetime.now(timezone.utc).isoformat(),
        "open_ports":sorted(int(p["port"]) for p in scan.get("open_ports") or []),"services":services}

def _path(target): return BASELINE_DIR / (_safe_target(target).replace(".","_")+".json")

def _load(path):
    try:
        data=json.loads(path.read_text(encoding="utf-8"))
        return data if data.get("schema_version")==BASELINE_SCHEMA and isinstance(data.get("open_ports"),list) else None
    except (OSError,ValueError,TypeError,json.JSONDecodeError): return None

def _save(path,data):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=".nexus-baseline-",suffix=".tmp",dir=str(path.parent))
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(data,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        try: os.chmod(path,0o600)
        except OSError: pass
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def compare_and_store_baseline(report):
    if not isinstance(report,dict) or not report.get("ok"): raise ValueError("Se necesita un informe NEXUS válido.")
    target=_safe_target(report.get("target","")); current=_snapshot(report); path=_path(target); previous=_load(path)
    if previous is None:
        _save(path,current)
        return {"status":"baseline_created","baseline_created":True,"compared":False,
            "message":"Primera auditoría guardada como línea base; la siguiente permitirá detectar cambios.",
            "changes":[],"confidence":"not_comparable"}
    changes=[]
    old_ports,new_ports=set(previous.get("open_ports",[])),set(current["open_ports"])
    for port in sorted(new_ports-old_ports):
        changes.append({"code":"new_open_port","severity":"medium","confidence":"observed","classification":"surface_change",
            "target":str(port),"evidence":"El puerto TCP "+str(port)+" ahora aparece abierto.",
            "recommendation":"Identificar el servicio y confirmar si debe estar expuesto."})
    for port in sorted(old_ports-new_ports):
        changes.append({"code":"port_no_longer_open","severity":"info","confidence":"observed","classification":"surface_change",
            "target":str(port),"evidence":"El puerto TCP "+str(port)+" ya no aparece abierto.",
            "recommendation":"Confirmar si el cierre corresponde a un cambio previsto."})
    old_services,new_services=previous.get("services",{}),current["services"]
    for port in sorted(set(old_services)|set(new_services),key=lambda x:int(x)):
        old,new=old_services.get(port),new_services.get(port)
        if old is None or new is None: continue
        if old.get("certificate_sha256")!=new.get("certificate_sha256"):
            changes.append({"code":"tls_certificate_changed","severity":"medium","confidence":"observed",
                "classification":"certificate_change","target":port,
                "evidence":"La huella SHA-256 del certificado TLS ha cambiado.",
                "previous":old.get("certificate_sha256"),"current":new.get("certificate_sha256"),
                "recommendation":"Verificar el cambio con el administrador o fabricante antes de confiar en el nuevo certificado."})
        for key,label in (("headers","cabeceras HTTP"),("cookies","atributos de cookies"),("tls_status","estado TLS"),
            ("http_status","estado HTTP"),("certificate_not_after","fecha de expiración"),("certificate_subject","sujeto del certificado"),
            ("certificate_issuer","emisor del certificado")):
            if old.get(key)!=new.get(key):
                changes.append({"code":"configuration_changed","severity":"low","confidence":"observed",
                    "classification":"configuration_change","target":port,
                    "evidence":"Han cambiado "+label+" en el puerto "+port+".",
                    "recommendation":"Revisar si la variación estaba prevista y documentar el cambio."})
    _save(path,current)
    return {"status":"changes_detected" if changes else "no_changes","baseline_created":False,"compared":True,
        "previous_captured_at":previous.get("captured_at"),"current_captured_at":current["captured_at"],
        "change_count":len(changes),"changes":changes,"confidence":"observed",
        "note":"Las diferencias observadas no demuestran por sí solas una vulnerabilidad.","storage":"local_private_file"}
