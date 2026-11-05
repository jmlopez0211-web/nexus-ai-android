"""Low-impact HTTP security posture checks for explicitly authorized public sites.

This module performs a single GET per redirect hop, does not crawl, mutate forms,
submit payloads, authenticate, or download response bodies.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

USER_AGENT = "NEXUS-IA-Defensive-Audit/2.0"
TIMEOUT = (3.05, 8)
MAX_REDIRECTS = 3


class AuditInputError(ValueError):
    pass


def _resolve_public_http_target(url: str):
    """Validate a public URL and return its DNS answers for IP-pinned requests."""
    if not isinstance(url, str) or len(url) > 2048:
        raise AuditInputError("Introduce una URL válida (máximo 2048 caracteres).")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AuditInputError("Solo se admiten direcciones completas http:// o https://.")
    if parts.username or parts.password:
        raise AuditInputError("No incluyas credenciales dentro de la URL.")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise AuditInputError("El puerto de la URL no es válido.") from exc
    host = parts.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise AuditInputError("El análisis remoto no admite destinos locales o privados.")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        except (OSError, ValueError):
            raise AuditInputError("No se pudo resolver el dominio.")
    if not addresses or any(not address.is_global for address in addresses):
        raise AuditInputError("Por seguridad, el servidor solo analiza dominios públicos.")
    normalized = parts._replace(fragment="").geturl()
    ordered = sorted(addresses, key=lambda address: (address.version != 4, address.compressed))
    return normalized, tuple(ordered)


def _validate_public_http_url(url: str) -> str:
    """Compatibility wrapper used by validation tests and redirect checks."""
    return _resolve_public_http_target(url)[0]


class _PinnedIPAdapter(HTTPAdapter):
    """Connect to the IP validated by DNS while retaining the original Host and TLS name."""

    def __init__(self, hostname: str, ip_address: str, port: int):
        super().__init__(max_retries=0)
        self.hostname = hostname
        self.ip_address = ip_address
        self.port = port

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        # The audit intentionally does not route through environment-configured proxies.
        if proxies and any(proxies.values()):
            raise AuditInputError("No se permiten proxies en la auditoría HTTP defensiva.")
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(
            request, verify, cert
        )
        host_params["host"] = self.ip_address
        host_params["port"] = self.port
        if request.url.lower().startswith("https://"):
            pool_kwargs["assert_hostname"] = self.hostname
            pool_kwargs["server_hostname"] = self.hostname
        return self.poolmanager.connection_from_host(
            **host_params, pool_kwargs=pool_kwargs
        )

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
    """Inspect a single public URL, pinning each validated DNS answer to prevent rebinding."""
    current = url
    history = []
    for hop in range(MAX_REDIRECTS + 1):
        current, addresses = _resolve_public_http_target(current)
        parts = urlsplit(current)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        chosen_ip = addresses[0].compressed
        session = requests.Session()
        session.trust_env = False
        session.mount(
            parts.scheme + "://",
            _PinnedIPAdapter(parts.hostname, chosen_ip, port),
        )
        response = None
        try:
            host_header = parts.netloc
            response = session.get(
                current,
                headers={
                    "User-Agent": USER_AGENT,
                    "Range": "bytes=0-0",
                    "Host": host_header,
                },
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
                verify=True,
            )
            history.append({"url": current, "status_code": response.status_code})
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    raise AuditInputError("El servidor devolvió una redirección sin destino.")
                if hop == MAX_REDIRECTS:
                    raise AuditInputError("Se alcanzó el límite de redirecciones.")
                current = urljoin(current, location)
                continue
            result = inspect_response(response, current)
            result["redirect_chain"] = history
            return result
        finally:
            if response is not None:
                response.close()
            session.close()
    raise AuditInputError("No se pudo completar la comprobación.")
