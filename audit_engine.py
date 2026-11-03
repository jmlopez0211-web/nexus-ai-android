"""Low-impact HTTP security posture checks for explicitly authorized public sites.

This module performs a single GET per redirect hop, does not crawl, mutate forms,
submit payloads, authenticate, or download response bodies.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests

USER_AGENT = "NEXUS-IA-Defensive-Audit/2.0"
TIMEOUT = (3.05, 8)
MAX_REDIRECTS = 3


class AuditInputError(ValueError):
    pass


def _validate_public_http_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 2048:
        raise AuditInputError("Introduce una URL válida (máximo 2048 caracteres).")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AuditInputError("Solo se admiten direcciones completas http:// o https://.")
    if parts.username or parts.password:
        raise AuditInputError("No incluyas credenciales dentro de la URL.")
    host = parts.hostname.rstrip(".")
    if host.lower() in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise AuditInputError("El análisis remoto no admite destinos locales o privados.")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                               type=socket.SOCK_STREAM)
            }
        except (OSError, ValueError):
            raise AuditInputError("No se pudo resolver el dominio.")
    if not addresses or any(not address.is_global for address in addresses):
        raise AuditInputError("Por seguridad, el servidor solo analiza dominios públicos.")
    return parts.geturl()


def _set_cookie_headers(response):
    raw = getattr(response, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None and hasattr(headers, "getlist"):
        return headers.getlist("Set-Cookie")
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def _finding(code, title, severity, detail, recommendation):
    return {
        "code": code,
        "title": title,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
    }


def inspect_response(response, url):
    headers = response.headers
    findings = []
    https = urlsplit(url).scheme == "https"

    checks = [
        ("Content-Security-Policy", "CSP", "Cabecera Content-Security-Policy ausente",
         "medium", "Define una política CSP restrictiva y ajústala a los recursos legítimos.",
         "Content-Security-Policy"),
        ("X-Content-Type-Options", "XCTO", "Protección contra MIME sniffing ausente",
         "low", "Configura X-Content-Type-Options: nosniff.",
         "X-Content-Type-Options"),
        ("Referrer-Policy", "REFERRER", "Política de referencia ausente",
         "low", "Configura una política como strict-origin-when-cross-origin.",
         "Referrer-Policy"),
        ("Permissions-Policy", "PERMISSIONS", "Permissions-Policy ausente",
         "low", "Limita explícitamente las funciones del navegador que no necesita el sitio.",
         "Permissions-Policy"),
    ]
    for header, code, title, severity, recommendation, _ in checks:
        if not headers.get(header):
            findings.append(_finding(code, title, severity,
                                     f"No se recibió la cabecera {header}.", recommendation))

    if https and not headers.get("Strict-Transport-Security"):
        findings.append(_finding(
            "HSTS", "HSTS ausente", "medium",
            "La respuesta HTTPS no incluye Strict-Transport-Security.",
            "Configura HSTS después de confirmar que todo el sitio funciona por HTTPS."
        ))
    if not headers.get("X-Frame-Options") and "frame-ancestors" not in headers.get("Content-Security-Policy", "").lower():
        findings.append(_finding(
            "CLICKJACKING", "Protección anti-iframe no detectada", "medium",
            "No se detectó X-Frame-Options ni frame-ancestors en CSP.",
            "Restringe la incrustación con CSP frame-ancestors o X-Frame-Options."
        ))

    cookie_count = 0
    for cookie in _set_cookie_headers(response):
        cookie_count += 1
        attributes = {
            part.strip().split("=", 1)[0].lower()
            for part in cookie.split(";")[1:]
            if part.strip()
        }
        if "secure" not in attributes:
            findings.append(_finding("COOKIE_SECURE", "Cookie sin atributo Secure", "medium",
                                     "Una cookie de respuesta no declara Secure.",
                                     "Añade Secure a las cookies transmitidas exclusivamente por HTTPS."))
        if "httponly" not in attributes:
            findings.append(_finding("COOKIE_HTTPONLY", "Cookie sin atributo HttpOnly", "low",
                                     "Una cookie de respuesta no declara HttpOnly.",
                                     "Añade HttpOnly cuando JavaScript no necesite leer la cookie."))
        if "samesite" not in attributes:
            findings.append(_finding("COOKIE_SAMESITE", "Cookie sin atributo SameSite", "low",
                                     "Una cookie de respuesta no declara SameSite.",
                                     "Define SameSite=Lax o Strict según el flujo de autenticación."))

    server_header = headers.get("Server")
    powered_by = headers.get("X-Powered-By")
    if server_header or powered_by:
        findings.append(_finding(
            "BANNER", "Información tecnológica expuesta", "info",
            "La respuesta revela cabeceras de servidor o plataforma.",
            "Valora reducir las cabeceras de identificación si no son necesarias."
        ))

    return {
        "url": url,
        "status_code": response.status_code,
        "https": https,
        "server_header_present": bool(server_header),
        "powered_by_header_present": bool(powered_by),
        "cookie_count": cookie_count,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high": sum(x["severity"] == "high" for x in findings),
            "medium": sum(x["severity"] == "medium" for x in findings),
            "low": sum(x["severity"] == "low" for x in findings),
            "info": sum(x["severity"] == "info" for x in findings),
        },
        "limitations": [
            "Comprobación HTTP superficial de una URL; no es un análisis de vulnerabilidades completo.",
            "No se rastrean enlaces ni se prueban formularios, credenciales o cargas de explotación.",
            "Los resultados son indicios de configuración y requieren validación manual."
        ],
    }


def audit_url(url: str) -> dict:
    """Inspect a single public URL with safe redirect validation and bounded requests."""
    current = _validate_public_http_url(url)
    history = []
    for hop in range(MAX_REDIRECTS + 1):
        # Revalidate DNS and destination on every hop; do not follow redirects automatically.
        current = _validate_public_http_url(current)
        response = requests.get(
            current,
            headers={"User-Agent": USER_AGENT, "Range": "bytes=0-0"},
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        history.append({"url": current, "status_code": response.status_code})
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise AuditInputError("El servidor devolvió una redirección sin destino.")
            if hop == MAX_REDIRECTS:
                raise AuditInputError("Se alcanzó el límite de redirecciones.")
            current = urljoin(current, location)
            continue
        try:
            result = inspect_response(response, current)
        finally:
            response.close()
        result["redirect_chain"] = history
        return result
    raise AuditInputError("No se pudo completar la comprobación.")
