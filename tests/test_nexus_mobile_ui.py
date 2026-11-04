import pathlib
import unittest


class NexusMobileUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = pathlib.Path(__file__).resolve().parents[1].joinpath("índice.html").read_text(encoding="utf-8")

    def test_light_mobile_theme_is_enabled(self):
        self.assertIn("color-scheme:light", self.html)
        self.assertIn("NEXUS IA mobile refresh", self.html)
        self.assertIn("@media(max-width:560px)", self.html)

    def test_bridge_token_is_session_scoped_and_sent_as_bearer(self):
        self.assertIn("WIFI_BRIDGE_TOKEN_SESSION_KEY", self.html)
        self.assertIn("safeStorageSet(sessionStorage,WIFI_BRIDGE_TOKEN_SESSION_KEY,token)", self.html)
        self.assertIn('Authorization:"Bearer "+token', self.html)
        self.assertIn("El token no se envía a Render", self.html)

    def test_saving_bridge_verifies_authentication_before_persisting_token(self):
        save_handler = self.html.split('document.getElementById("save-wifi-bridge")', 1)[1].split(
            'document.getElementById("clear-wifi-token")', 1
        )[0]
        self.assertIn('fetch(value+"/api/status"', save_handler)
        self.assertIn("response.status===401", save_handler)
        self.assertIn("response.status===403", save_handler)
        self.assertIn("Conexión NO verificada", save_handler)
        self.assertIn("persistBridgeToken(token)", save_handler)

    def test_wifi_scan_distinguishes_cached_and_empty_results(self):
        self.assertIn("Inventario local recuperado de caché", self.html)
        self.assertIn("última lectura válida de esta sesión", self.html)
        self.assertIn("termux-wifi-scaninfo", self.html)

    def test_bridge_token_is_persisted_and_shared_across_actions(self):
        self.assertIn('const WIFI_BRIDGE_TOKEN_KEY = "nexus_wifi_bridge_token"', self.html)
        self.assertIn("function getBridgeToken()", self.html)
        self.assertIn("function persistBridgeToken(token)", self.html)
        self.assertIn('token=getBridgeToken();', self.html)
        self.assertIn("safeStorageSet(sessionStorage,WIFI_BRIDGE_URL_KEY,value)", self.html)


if __name__ == "__main__":
    unittest.main()
