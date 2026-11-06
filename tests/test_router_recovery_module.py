import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class RouterRecoveryModuleTests(unittest.TestCase):
    def test_wifi_panel_loads_router_recovery_module(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn('id="nexus-router-recovery"', html)
        self.assertIn('<script src="/router-recovery.js" defer></script>', html)
        worker = (ROOT / "service-worker.js").read_text(encoding="utf-8")
        self.assertIn('"/router-recovery.js"', worker)
        self.assertIn('nexus-shell-v5', worker)

    def test_recovery_module_never_requests_or_exports_credentials(self):
        source = (ROOT / "router-recovery.js").read_text(encoding="utf-8")
        self.assertIn('password_requested: false', source)
        self.assertIn('password_stored: false', source)
        self.assertIn('password_exported: false', source)
        self.assertIn('hidden_credentials_extracted: false', source)
        self.assertNotIn('type = "password"', source)
        self.assertIn('Restablecimiento de fábrica (último recurso)', source)
        self.assertIn('confirm', source.lower())

    def test_recovery_report_has_provider_model_and_limitations(self):
        source = (ROOT / "router-recovery.js").read_text(encoding="utf-8")
        for field in ('provider:', 'manufacturer:', 'model:', 'steps,', 'limitations:'):
            with self.subTest(field=field):
                self.assertIn(field, source)


if __name__ == "__main__":
    unittest.main()
