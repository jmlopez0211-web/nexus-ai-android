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
        self.assertIn("export-wireless-audit", self.html)

    def test_offline_passphrase_check_is_available(self):
        self.assertIn("async function checkOwnWifiPassphrase()", self.html)
        self.assertIn('id="wifi-dictionary-file"', self.html)
        self.assertIn("file.size>5*1024*1024", self.html)
        self.assertIn('input.value=""', self.html)

    def test_frontend_documents_safe_scope(self):
        self.assertIn("no se capturan handshakes", self.html.lower())
        self.assertIn("no se realizan ataques de diccionario", self.html.lower())


if __name__ == "__main__":
    unittest.main()
