"""NEXUS defensive LAN security report builder.

Inspects only one explicitly authorized RFC1918 IPv4 host. HTTP checks use
unauthenticated GET / requests, do not follow redirects, and never retain
cookie values or response bodies. TLS metadata fallback is inspection-only:
it does not send credentials and is clearly marked as unverified.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone

HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}
SAFE_HEADERS = (
    "Server",
    "Content-Type",
    "Cache-Control",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
)
USER_AGENT = "NEXUS-Defensive-LAN-Audit/1.0"
HTTP_TIMEOUT_SECONDS = 2.5


def validate_private_ipv4(value: str) -> str:
    """Accept a literal RFC1918 IPv4 address only; no DNS or public targets."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError("Introduce una dirección IPv4 privada válida.") from exc
    private_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if address.version != 4 or not any(address in network for network in private_ranges):
        raise ValueError("La auditoría detallada solo admite una IPv4 privada RFC1918.")
    return str(address)


def _cookie_metadata(raw_headers):
    """Return cookie names and flags only; never return cookie values."""
    cookies = []
    for raw in raw_headers or ():
        first = str(raw).split(";", 1)[0]
        name = first.split("=", 1)[0].strip()[:80]
        if not name:
            continue
        attributes = {
            part.strip().split("=", 1)[0].lower()
            for part in str(raw).split(";")[1:]
            if part.strip()
        }
        same_site = None
        for part in str(raw).split(";")[1:]:
            if part.strip().lower().startswith("samesite="):
                same_site = part.split("=", 1)[1].strip()[:30]
        cookies.append({
            "name": name,
            "secure": "secure" in attributes,
            "httponly": "httponly" in attributes,
            "samesite": same_site,
        })
    return cookies


def _certificate_metadata(der_bytes):
    metadata = {
        "sha256_fingerprint": hashlib.sha256(der_bytes).hexdigest().upper(),
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "signature_algorithm": None,
        "public_key_algorithm": None,
        "public_key_bits": None,
        "subject_alt_name_present": None,
        "inspection_tool": None,
    }
    openssl = shutil.which("openssl")
    if not openssl:
        metadata["inspection_note"] = "OpenSSL no está disponible; solo se calculó la huella SHA-256."
        return metadata
    try:
        result = subprocess.run(
            [openssl, "x509", "-inform", "DER", "-noout", "-subject", "-issuer",
             "-dates", "-fingerprint", "-sha256", "-text"],
            input=der_bytes,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        metadata["inspection_note"] = "No se pudo completar la lectura local del certificado."
        return metadata
    output = result.stdout.decode("utf-8", "replace")
    if result.returncode != 0:
        metadata["inspection_note"] = "OpenSSL no pudo decodificar el certificado."
        return metadata
    metadata["inspection_tool"] = "openssl"
    for line in output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("subject="):
            metadata["subject"] = stripped.split("=", 1)[1].strip()[:500]
        elif lower.startswith("issuer="):
            metadata["issuer"] = stripped.split("=", 1)[1].strip()[:500]
        elif lower.startswith("notbefore="):
            metadata["not_before"] = stripped.split("=", 1)[1].strip()
        elif lower.startswith("notafter="):
            metadata["not_after"] = stripped.split("=", 1)[1].strip()
        elif "signature algorithm:" in lower and metadata["signature_algorithm"] is None:
            metadata["signature_algorithm"] = stripped.split(":", 1)[1].strip()
        elif "public key algorithm:" in lower:
            metadata["public_key_algorithm"] = stripped.split(":", 1)[1].strip()
        elif lower.startswith("public-key:") or lower.startswith("rsa public-key:"):
            match = re.search(r"\((\d+)\s+bit\)", stripped, re.I)
            if match:
                metadata["public_key_bits"] = int(match.group(1))
    metadata["subject_alt_name_present"] = "X509v3 Subject Alternative Name" in output
    return metadata


def _verify_tls(target, port):
    connection = http.client.HTTPSConnection(
        target, port=port, timeout=HTTP_TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )
    try:
        connection.connect()
        protocol = connection.sock.version() if connection.sock else None
        cipher = connection.sock.cipher() if connection.sock else None
        return {"status": "verified", "protocol": protocol,
                "cipher": cipher[0] if cipher else None}
    except ssl.SSLCertVerificationError as exc:
        return {"status": "failed", "reason": type(exc).__name__}
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}
    finally:
        connection.close()


def inspect_http_service(target: str, port: int, timeout=HTTP_TIMEOUT_SECONDS) -> dict:
    """Read unauthenticated response metadata from /; no body or secrets retained."""
    target = validate_private_ipv4(target)
    if port not in HTTP_PORTS | HTTPS_PORTS:
        raise ValueError("Puerto web fuera de la lista permitida.")
    scheme = "https" if port in HTTPS_PORTS else "http"
    tls = None
    connection = None
    certificate = None
    try:
        if scheme == "https":
            tls = _verify_tls(target, port)
            context = ssl._create_unverified_context()
            connection = http.client.HTTPSConnection(
                target, port=port, timeout=timeout, context=context
            )
        else:
            connection = http.client.HTTPConnection(target, port=port, timeout=timeout)
        connection.connect()
        if scheme == "https" and connection.sock:
            try:
                der = connection.sock.getpeercert(binary_form=True)
                if der:
                    certificate = _certificate_metadata(der)
                cipher = connection.sock.cipher()
                tls["inspection_protocol"] = connection.sock.version()
                tls["inspection_cipher"] = cipher[0] if cipher else None
            except (OSError, ssl.SSLError):
                certificate = None
        connection.request(
            "GET", "/",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers = {}
        for name in SAFE_HEADERS:
            value = response.getheader(name)
            if value is not None:
                headers[name.lower()] = str(value)[:1000]
        raw_cookies = response.headers.get_all("Set-Cookie", [])
        return {
            "port": port,
            "scheme": scheme,
            "reachable": True,
            "http_status": response.status,
            "reason": str(response.reason)[:100],
            "headers": headers,
            "cookies": _cookie_metadata(raw_cookies),
            "tls": tls,
            "certificate": certificate,
            "request": {"method": "GET", "path": "/", "authenticated": False,
                        "redirects_followed": False, "response_body_read": False},
        }
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
        return {
            "port": port, "scheme": scheme, "reachable": False,
            "error_type": type(exc).__name__, "headers": {}, "cookies": [],
            "tls": tls, "certificate": certificate,
            "request": {"method": "GET", "path": "/", "authenticated": False,
                        "redirects_followed": False, "response_body_read": False},
        }
    finally:
        if connection is not None:
            connection.close()


def _finding(code, severity, classification, title, evidence, recommendation):
    return {
        "code": code,
        "severity": severity,
        "classification": classification,
        "confidence": "observed",
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "confirmed_vulnerability": False,
    }


def build_findings(services):
    findings = []
    controls = []
    for service in services:
        if not service.get("reachable"):
            findings.append(_finding(
                "web_metadata_unavailable", "info", "incomplete_check",
                "No se pudo leer la respuesta web",
                "El puerto TCP respondió, pero la consulta HTTP limitada no obtuvo metadatos.",
                "Revisar manualmente el servicio; no interpretar la falta de respuesta como vulnerabilidad.",
            ))
            continue
        port = service["port"]
        scheme = service["scheme"]
        headers = service.get("headers") or {}
        if scheme == "http":
            findings.append(_finding(
                "http_service_available", "medium", "configuration_observation",
                "Servicio HTTP sin cifrado accesible",
                "El servicio HTTP respondió en el puerto " + str(port) +
                " con estado " + str(service.get("http_status")) + ".",
                "Si el panel permite configurarlo, redirigir HTTP a HTTPS o desactivar la administración HTTP.",
            ))
            for cookie in service.get("cookies", []):
                if not cookie.get("secure"):
                    findings.append(_finding(
                        "cookie_without_secure_on_http", "medium", "configuration_observation",
                        "Cookie observada sin atributo Secure",
                        "La respuesta HTTP estableció la cookie " + cookie["name"] +
                        " sin atributo Secure. El valor de la cookie no se ha guardado.",
                        "Evitar la gestión por HTTP y configurar cookies Secure cuando el firmware lo permita.",
                    ))
        if scheme == "https":
            tls = service.get("tls") or {}
            if tls.get("status") == "failed":
                findings.append(_finding(
                    "tls_trust_not_validated", "medium", "trust_validation",
                    "La cadena TLS no se valida con el almacén local",
                    "La validación estándar falló (" + str(tls.get("reason") or "error de certificado") +
                    "). La inspección posterior solo obtuvo metadatos sin validar la confianza.",
                    "Usar un certificado emitido por una CA de confianza para los clientes previstos o aceptar el aviso solo tras verificar la huella por un canal fiable.",
                ))
            certificate = service.get("certificate") or {}
            if certificate and certificate.get("subject_alt_name_present") is False:
                findings.append(_finding(
                    "certificate_missing_san", "low", "certificate_observation",
                    "El certificado no anuncia Subject Alternative Name",
                    "La lectura X.509 no encontró la extensión SAN.",
                    "Solicitar al fabricante/operador un certificado con SAN que incluya la dirección o nombre de administración.",
                ))
            if headers.get("strict-transport-security"):
                controls.append({"target": str(port), "control": "HSTS",
                                 "evidence": headers["strict-transport-security"]})
        for header, label in (
            ("x-frame-options", "X-Frame-Options"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("content-security-policy", "Content-Security-Policy"),
        ):
            if headers.get(header):
                controls.append({"target": str(port), "control": label,
                                 "evidence": headers[header]})
    return findings, controls


def build_security_report(target: str, scan_result: dict, port_map: dict) -> dict:
    """Combine the existing bounded TCP inventory with defensive HTTP/TLS evidence."""
    target = validate_private_ipv4(target)
    if not isinstance(scan_result, dict) or scan_result.get("target") != target:
        raise ValueError("El inventario TCP no corresponde al destino solicitado.")
    open_ports = scan_result.get("open_ports", [])
    services = []
    for item in open_ports:
        try:
            port = int(item.get("port"))
        except (AttributeError, TypeError, ValueError):
            continue
        if port in HTTP_PORTS | HTTPS_PORTS:
            services.append(inspect_http_service(target, port))
    findings, controls = build_findings(services)
    counts = {level: sum(1 for item in findings if item["severity"] == level)
              for level in ("high", "medium", "low", "info")}
    return {
        "ok": True,
        "schema_version": "1.0",
        "application": "NEXUS AI",
        "report_type": "defensive_single_host_security_audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scope": "Una única IPv4 privada; puertos TCP de la lista NEXUS y metadatos HTTP/TLS en /.",
        "scan": scan_result,
        "services": services,
        "security_controls_observed": controls,
        "findings": findings,
        "summary": {
            "open_tcp_ports": scan_result.get("open_count", 0),
            "ports_checked": scan_result.get("scanned_ports", 0),
            "web_services_inspected": len(services),
            "findings_by_severity": counts,
            "confirmed_vulnerabilities": 0,
        },
        "limitations": [
            "Solo se comprueba la lista TCP configurada; no se recorre la subred.",
            "Los nombres de servicio asociados a puertos son indicativos, no una identificación de versión.",
            "Solo se solicita GET / sin credenciales; no se siguen redirecciones ni se lee el cuerpo.",
            "Los valores de Set-Cookie nunca se almacenan; solo se conservan nombres y atributos.",
            "La inspección TLS sin validar se utiliza exclusivamente para obtener metadatos públicos del certificado cuando falla la validación estándar.",
            "No se explotan vulnerabilidades ni se prueban contraseñas.",
        ],
        "safety": {
            "single_private_ipv4": True,
            "authenticated_request_to_target": False,
            "credentials_sent": False,
            "cookie_values_stored": False,
            "response_body_stored": False,
            "redirects_followed": False,
            "configuration_changed": False,
        },
    }
