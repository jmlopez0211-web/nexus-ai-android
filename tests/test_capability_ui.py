import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class CapabilityDiagnosticUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "índice.html").read_text(encoding="utf-8")

    def test_existing_python_engine_controls_are_preserved(self):
        self.assertIn('id="check-python-engine"', self.html)
        self.assertIn('id="export-python-engine"', self.html)
        self.assertIn("async function checkPythonEngine()", self.html)
        self.assertIn("async function launchPythonModule(", self.html)

    def test_hardware_diagnostic_and_export_controls_exist(self):
        self.assertIn('id="check-hardware-capabilities"', self.html)
        self.assertIn('id="export-hardware-capabilities"', self.html)
        self.assertIn('id="hardware-capability-status"', self.html)
        self.assertIn('id="hardware-capability-results"', self.html)
        self.assertIn('"/api/capabilities"', self.html)
        self.assertIn("nexus-hardware-capabilities.json", self.html)

    def test_ui_reports_proot_monitor_and_injection_without_claiming_them_available(self):
        self.assertIn("Root dentro de Proot", self.html)
        self.assertIn("Root Android", self.html)
        self.assertIn("Grupos efectivos", self.html)
        self.assertIn("Dispositivo ", self.html)
        self.assertIn("Modo monitor", self.html)
        self.assertIn("Inyección de paquetes", self.html)
        self.assertIn("no demuestra que pueda activarse", self.html)
        self.assertIn("permanece desconocida", self.html)


if __name__ == "__main__":
    unittest.main()
