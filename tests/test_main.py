import os
import unittest
from unittest.mock import Mock, patch

import main


class MainApiTests(unittest.TestCase):
    def setUp(self):
        main.app.config.update(TESTING=True)
        self.client = main.app.test_client()

    def test_health_is_available_without_exposing_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["ok"])
        self.assertFalse(data["ai_configured"])
        self.assertNotIn("GROQ_API_KEY", str(data))

    def test_ask_rejects_missing_key(self):
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.post("/api/ask", json={"tarea": "Hola"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("GROQ_API_KEY", response.get_json()["error"])

    def test_ask_rejects_empty_and_oversized_input(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-secret"}):
            empty = self.client.post("/api/ask", json={"tarea": "  "})
            oversized = self.client.post("/api/ask", json={"tarea": "x" * 12001})
        self.assertEqual(empty.status_code, 400)
        self.assertEqual(oversized.status_code, 413)

    @patch("main.Groq")
    def test_ask_returns_model_answer(self, groq_class):
        message = Mock()
        message.content = "Respuesta de prueba"
        completion = Mock()
        completion.choices = [Mock(message=message)]
        client = Mock()
        client.chat.completions.create.return_value = completion
        groq_class.return_value = client

        with patch.dict(os.environ, {"GROQ_API_KEY": "test-secret"}):
            response = self.client.post("/api/ask", json={"tarea": "Explica WPA3"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["respuesta"], "Respuesta de prueba")
        groq_class.assert_called_once_with(api_key="test-secret")
        client.chat.completions.create.assert_called_once()

    @patch("main.Groq")
    def test_ask_handles_upstream_failure_without_leaking_details(self, groq_class):
        groq_class.return_value.chat.completions.create.side_effect = RuntimeError(
            "private provider diagnostic"
        )
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-secret"}):
            response = self.client.post("/api/ask", json={"tarea": "Hola"})
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("private provider diagnostic", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
