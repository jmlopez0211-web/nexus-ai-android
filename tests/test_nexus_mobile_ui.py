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

    def test_bridge_token_is_persisted_and_sent_as_bearer(self):
        self.assertIn('const WIFI_BRIDGE_TOKEN_KEY = "nexus_wifi_bridge_token"', self.html)
        self.assertIn("function getBridgeToken()", self.html)
        self.assertIn("function persistBridgeToken(token)", self.html)
        self.assertIn("safeStorageSet(localStorage,WIFI_BRIDGE_TOKEN_KEY,token)", self.html)
        self.assertIn("nexusWifiTokenField.addEventListener(\"input\"", self.html)
        self.assertIn("persistBridgeToken(token)", self.html)
        self.assertIn('Authorization:"Bearer "+token', self.html)
        self.assertIn("El token no se envía a Render", self.html)

    def test_save_persists_credentials_before_network_verification(self):
        save_handler = self.html.split('document.getElementById("save-wifi-bridge")', 1)[1].split(
            'document.getElementById("clear-wifi-token")', 1
        )[0]
        persist_at = save_handler.index("tokenStorage=persistBridgeToken(token)")
        fetch_at = save_handler.index('fetch(value+"/api/status"')
        self.assertLess(persist_at, fetch_at)
        self.assertIn("response.status===401", save_handler)
        self.assertIn("response.status===403", save_handler)
        self.assertIn("GUARDADO, PERO SIN CONEXIÓN", save_handler)
        self.assertIn("Token y dirección guardados", save_handler)

    def test_bridge_token_persists_until_user_forgets_it(self):
        self.assertIn('const WIFI_BRIDGE_TOKEN_KEY = "nexus_wifi_bridge_token"', self.html)
        self.assertIn("safeStorageSet(localStorage,WIFI_BRIDGE_TOKEN_KEY,token)", self.html)
        self.assertIn("safeStorageGet(localStorage,WIFI_BRIDGE_TOKEN_KEY)", self.html)
        self.assertIn("safeStorageRemove(localStorage,WIFI_BRIDGE_TOKEN_KEY)", self.html)
        self.assertIn("Token local (se guarda en este navegador", self.html)

    def test_bridge_url_validation_regex_is_well_formed(self):
        self.assertIn(r'if(!/^https?:\/\//i.test(value))', self.html)
        self.assertNotIn(r'if(!/^https?:\\/\\//i.test(value))', self.html)

    def test_wifi_scan_distinguishes_cached_and_empty_results(self):
        self.assertIn("Inventario local de respaldo", self.html)
        self.assertIn("last_nonempty_api_response_at", self.html)
        self.assertIn("scan_age_seconds", self.html)
        self.assertIn("Se conserva el inventario de esta sesión", self.html)
        self.assertIn("termux-wifi-scaninfo", self.html)

    def test_all_bridge_actions_use_the_shared_token_reader(self):
        self.assertIn("function getBridgeToken()", self.html)
        self.assertIn('const target=document.getElementById("nexus-scan-target").value.trim(),token=getBridgeToken();', self.html)
        scan_handler = self.html.split("async function scanNexusPorts()", 1)[1]
        self.assertNotIn('token=document.getElementById("nexus-wifi-token").value.trim()', scan_handler)
        self.assertIn("function persistBridgeToken(token)", self.html)

    def test_storage_failures_fall_back_to_session_without_aborting_page_init(self):
        self.assertIn("function safeStorageGet(storage,key)", self.html)
        self.assertIn("safeStorageSet(sessionStorage,WIFI_BRIDGE_URL_KEY,value)", self.html)
        self.assertIn("solo durante esta sesión", self.html)


if __name__ == "__main__":
    unittest.main()
