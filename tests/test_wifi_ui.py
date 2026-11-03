import pathlib
import unittest


class WifiUiFeatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = pathlib.Path(__file__).resolve().parents[1].joinpath("índice.html").read_text(encoding="utf-8")

    def test_passive_wireless_audit_is_available(self):
        self.assertIn('id="wireless-audit-panel"', self.html)
        self.assertIn("function runWirelessAudit()", self.html)
        self.assertIn("classifyWifiSecurity(network)", self.html)
        self.assertIn("WEP anunciado (obsoleto e inseguro)", self.html)
        self.assertIn("Modo mixto WPA3/WPA2 anunciado", self.html)
        self.assertIn("Cifrado no identificable", self.html)
        self.assertIn("Red abierta (sin cifrado anunciado)", self.html)
        self.assertIn("export-wireless-audit", self.html)

    def test_offline_passphrase_check_is_available(self):
        self.assertIn("async function checkOwnWifiPassphrase()", self.html)
        self.assertIn('id="wifi-dictionary-file"', self.html)
        self.assertIn("file.size>5*1024*1024", self.html)
        self.assertIn("COMMON_WIFI_PASSWORDS", self.html)
        self.assertIn("lista integrada de claves habituales", self.html)
        self.assertIn("no se ha contactado con el router", self.html)
        self.assertIn('input.value=""', self.html)

    def test_frontend_documents_safe_scope(self):
        self.assertIn("no se capturan handshakes", self.html.lower())
        self.assertIn("no se realizan ataques de diccionario", self.html.lower())
        self.assertIn("async function askNexus()", self.html)
        self.assertNotIn("async async function askNexus()", self.html)


if __name__ == "__main__":
    unittest.main()
