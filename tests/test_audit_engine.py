import unittest
from unittest.mock import Mock, patch

from audit_engine import AuditInputError, _validate_public_http_url, inspect_response


class AuditEngineTests(unittest.TestCase):
    def test_rejects_localhost(self):
        with self.assertRaises(AuditInputError):
            _validate_public_http_url("http://localhost/admin")

    def test_rejects_private_ip(self):
        with self.assertRaises(AuditInputError):
            _validate_public_http_url("http://192.168.1.1/")

    @patch("audit_engine.socket.getaddrinfo")
    def test_rejects_domain_resolving_private(self, resolver):
        resolver.return_value = [(None, None, None, None, ("10.0.0.2", 0))]
        with self.assertRaises(AuditInputError):
            _validate_public_http_url("https://example.test/")

    def test_reports_missing_security_headers(self):
        response = Mock()
        response.headers = {"Server": "example"}
        response.status_code = 200
        response.raw.headers.getlist.return_value = []
        result = inspect_response(response, "https://example.com/")
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("CSP", codes)
        self.assertIn("HSTS", codes)
        self.assertIn("BANNER", codes)
        self.assertGreater(result["summary"]["total"], 0)

    def test_cookie_flags(self):
        response = Mock()
        response.headers = {"Content-Security-Policy": "default-src 'self'",
                            "Strict-Transport-Security": "max-age=31536000",
                            "X-Frame-Options": "DENY",
                            "X-Content-Type-Options": "nosniff",
                            "Referrer-Policy": "no-referrer",
                            "Permissions-Policy": "camera=()"}
        response.status_code = 200
        response.raw.headers.getlist.return_value = ["session=abc; Path=/"]
        result = inspect_response(response, "https://example.com/")
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("COOKIE_SECURE", codes)
        self.assertIn("COOKIE_HTTPONLY", codes)
        self.assertIn("COOKIE_SAMESITE", codes)


if __name__ == "__main__":
    unittest.main()
