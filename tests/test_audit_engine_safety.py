import unittest
from unittest.mock import Mock, patch

import audit_engine


class AuditEngineSafetyTests(unittest.TestCase):
    def test_rejects_local_and_non_global_destinations(self):
        for url in (
            "http://127.0.0.1/",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://localhost/",
            "http://router.local/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(audit_engine.AuditInputError):
                    audit_engine._validate_public_http_url(url)

    def test_rejects_domain_resolving_to_private_address(self):
        fake_address = [(None, None, None, None, ("192.168.1.25", 0))]
        with patch.object(audit_engine.socket, "getaddrinfo", return_value=fake_address):
            with self.assertRaises(audit_engine.AuditInputError):
                audit_engine._validate_public_http_url("https://example.org/")

    def test_redirect_to_private_address_is_blocked_before_second_request(self):
        redirect = Mock()
        redirect.status_code = 302
        redirect.headers = {"Location": "http://127.0.0.1:8080/admin"}
        redirect.close = Mock()
        public_address = [(None, None, None, None, ("93.184.216.34", 0))]
        with patch.object(audit_engine.socket, "getaddrinfo", return_value=public_address), \
             patch.object(audit_engine.requests, "get", return_value=redirect) as request:
            with self.assertRaises(audit_engine.AuditInputError):
                audit_engine.audit_url("https://example.org/")
        request.assert_called_once()
        redirect.close.assert_called_once()

    def test_accepts_public_ip_literal_without_dns_resolution(self):
        self.assertEqual(
            audit_engine._validate_public_http_url("https://8.8.8.8/health"),
            "https://8.8.8.8/health",
        )


if __name__ == "__main__":
    unittest.main()
