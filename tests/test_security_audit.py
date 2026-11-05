import http.client
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

import nexus_security_audit as audit


class SecurityAuditTests(unittest.TestCase):
    def test_accepts_only_private_ipv4_literals(self):
        self.assertEqual(audit.validate_private_ipv4("192.168.1.1"), "192.168.1.1")
        for target in ("example.com", "8.8.8.8", "127.0.0.1", "::1"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                audit.validate_private_ipv4(target)

    def test_cookie_metadata_never_contains_cookie_values(self):
        cookies = audit._cookie_metadata([
            "SID=very-secret-session-value; Path=/; HttpOnly",
            "PREF=private-value; Secure; HttpOnly; SameSite=Lax",
        ])
        self.assertEqual(cookies[0], {
            "name": "SID", "secure": False, "httponly": True, "samesite": None
        })
        self.assertTrue(cookies[1]["secure"])
        self.assertEqual(cookies[1]["samesite"], "Lax")
        self.assertNotIn("very-secret-session-value", str(cookies))
        self.assertNotIn("private-value", str(cookies))

    def test_http_inspection_uses_unauthenticated_get_and_keeps_safe_headers_only(self):
        headers = Message()
        headers.add_header("Set-Cookie", "SID=secret-value; Path=/; HttpOnly")
        response = SimpleNamespace(
            status=200, reason="OK", headers=headers,
            getheader=lambda name: {
                "Server": "ZTE",
                "X-Frame-Options": "SAMEORIGIN",
                "Set-Cookie": "SID=secret-value; Path=/; HttpOnly",
            }.get(name),
        )

        class FakeConnection:
            def __init__(self, *args, **kwargs):
                self.request_args = None
            def connect(self):
                return None
            def request(self, method, path, headers):
                self.request_args = (method, path, headers)
            def getresponse(self):
                return response
            def close(self):
                return None

        with patch.object(audit.http.client, "HTTPConnection", FakeConnection):
            result = audit.inspect_http_service("192.168.1.1", 80)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["request"]["method"], "GET")
        self.assertFalse(result["request"]["authenticated"])
        self.assertFalse(result["request"]["response_body_read"])
        self.assertEqual(result["headers"]["server"], "ZTE")
        self.assertNotIn("set-cookie", result["headers"])
        self.assertNotIn("secret-value", str(result))
        self.assertFalse(result["cookies"][0]["secure"])

    def test_https_inspection_marks_untrusted_tls_and_records_public_certificate_metadata(self):
        class FakeSocket:
            def getpeercert(self, binary_form=False):
                return b"fake-der" if binary_form else {}
            def cipher(self):
                return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
            def version(self):
                return "TLSv1.3"

        headers = Message()

        class FakeResponse:
            status = 200
            reason = "OK"
            def __init__(self):
                self.headers = headers
            def getheader(self, name):
                return {"Strict-Transport-Security": "max-age=31536000"}.get(name)

        class FakeConnection:
            def __init__(self, *args, **kwargs):
                self.sock = FakeSocket()
            def connect(self):
                return None
            def request(self, *args, **kwargs):
                return None
            def getresponse(self):
                return FakeResponse()
            def close(self):
                return None

        certificate = {
            "sha256_fingerprint": "AA",
            "subject_alt_name_present": False,
            "not_after": "2031-07-10",
        }
        with patch.object(audit, "_verify_tls", return_value={
                "status": "failed", "reason": "SSLCertVerificationError"}), \
             patch.object(audit.http.client, "HTTPSConnection", FakeConnection), \
             patch.object(audit, "_certificate_metadata", return_value=certificate):
            result = audit.inspect_http_service("192.168.1.1", 443)
        self.assertEqual(result["tls"]["status"], "failed")
        self.assertEqual(result["certificate"]["sha256_fingerprint"], "AA")
        findings, controls = audit.build_findings([result])
        codes = {item["code"] for item in findings}
        self.assertIn("tls_trust_not_validated", codes)
        self.assertIn("certificate_missing_san", codes)
        self.assertTrue(any(item["control"] == "HSTS" for item in controls))
        self.assertTrue(all(item["confirmed_vulnerability"] is False for item in findings))

    def test_report_requires_matching_private_target_and_states_scope(self):
        scan = {
            "target": "192.168.1.1",
            "open_count": 1,
            "scanned_ports": 20,
            "open_ports": [{"port": 80, "service": "HTTP"}],
        }
        with patch.object(audit, "inspect_http_service", return_value={
            "port": 80, "scheme": "http", "reachable": True,
            "http_status": 200, "headers": {}, "cookies": [], "tls": None,
        }):
            report = audit.build_security_report("192.168.1.1", scan, {80: "HTTP"})
        self.assertTrue(report["ok"])
        self.assertEqual(report["summary"]["open_tcp_ports"], 1)
        self.assertEqual(report["summary"]["confirmed_vulnerabilities"], 0)
        self.assertFalse(report["safety"]["credentials_sent"])
        self.assertFalse(report["safety"]["cookie_values_stored"])
        with self.assertRaises(ValueError):
            audit.build_security_report("192.168.1.2", scan, {80: "HTTP"})


if __name__ == "__main__":
    unittest.main()
