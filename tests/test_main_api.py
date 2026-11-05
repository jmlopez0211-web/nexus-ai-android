import os
import unittest
from unittest.mock import patch

from main import app


class NexusApiTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_health_does_not_claim_ai_is_connected_from_key_presence(self):
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["ai_configured"])
        self.assertIsNone(response.get_json()["ai_connected"])

    def test_web_audit_requires_authorization(self):
        response = self.client.post("/api/audit/web", json={"url": "https://example.org/"})
        self.assertEqual(response.status_code, 403)

    def test_web_audit_requires_url(self):
        response = self.client.post("/api/audit/web", json={"authorized": True})
        self.assertEqual(response.status_code, 400)

    @patch("main.audit_url")
    def test_web_audit_returns_auditor_result(self, audit):
        audit.return_value = {
            "url": "https://example.org/",
            "status_code": 200,
            "findings": [],
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        response = self.client.post(
            "/api/audit/web",
            json={"url": "https://example.org/", "authorized": True},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["audit_type"], "single_url_http_posture")
        audit.assert_called_once_with("https://example.org/")


    def test_ai_request_uses_bounded_provider_timeout_and_no_automatic_retries(self):
        from unittest.mock import Mock
        fake_client = Mock()
        fake_client.chat.completions.create.return_value.choices = [
            Mock(message=Mock(content="NEXUS listo"))
        ]
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}), \
             patch("main.Groq", return_value=fake_client) as groq:
            response = self.client.post("/api/ask", json={"tarea": "Comprueba el estado"})
        self.assertEqual(response.status_code, 200)
        groq.assert_called_once_with(api_key="test-key", timeout=30.0, max_retries=0)
        fake_client.chat.completions.create.assert_called_once()


if __name__ == "__main__":
    unittest.main()
