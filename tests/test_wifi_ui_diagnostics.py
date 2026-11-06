import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WifiUiDiagnosticsTests(unittest.TestCase):
    def test_browser_timeout_exceeds_bridge_api_timeout(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn("AbortSignal.timeout(32000)", html)
        self.assertNotIn("AbortSignal.timeout(18000)", html)

    def test_empty_result_explains_authentication_and_android_scan_separately(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn("HTTP "+response.status", html)
        self.assertIn("Termux:API ha devuelto 0 redes", html)
        self.assertIn("respuesta no vacía nueva", html)
        self.assertIn("antigüedad Android", html)

    def test_diagnostic_is_rendered_as_text_not_html(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn("diagnostic.textContent=", html)
        self.assertNotIn("diagnostic.innerHTML=", html)


if __name__ == "__main__":
    unittest.main()
