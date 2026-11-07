import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class FrontendIntegrityTests(unittest.TestCase):
    def test_all_inline_javascript_blocks_parse(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js no está disponible en este entorno")
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        blocks = re.findall(r"<script\b[^>]*>(.*?)</script>", html, flags=re.IGNORECASE | re.DOTALL)
        self.assertTrue(blocks, "No se encontraron bloques JavaScript")
        for index, source in enumerate(blocks, start=1):
            if not source.strip():
                continue
            with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as script:
                script.write(source)
                script.flush()
                result = subprocess.run(
                    [node, "--check", script.name],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            self.assertEqual(
                result.returncode,
                0,
                f"Bloque JavaScript {index} inválido:\n{result.stderr}",
            )

    def test_manifest_is_valid_and_service_worker_does_not_cache_api(self):
        manifest = json.loads((ROOT / "manifest.webmanifest").read_text(encoding="utf-8"))
        self.assertTrue(manifest.get("name"))
        self.assertTrue(manifest.get("start_url"))
        worker = (ROOT / "service-worker.js").read_text(encoding="utf-8")
        self.assertIn('if (url.pathname.startsWith("/api/")) return;', worker)
        self.assertIn('const CACHE_NAME = "nexus-shell-v5";', worker)
        self.assertIn('"/runtime-center.js"', worker)

    def test_runtime_center_javascript_parses(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js no está disponible en este entorno")
        script = ROOT / "runtime-center.js"
        result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn('<script src="/runtime-center.js" defer></script>', html)



    def test_termux_autostart_scripts_have_valid_bash_syntax(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("Bash no está disponible en este entorno")
        scripts = [
            ROOT / "nexus_bridge_supervisor.sh",
            ROOT / "install_termux_autostart.sh",
            ROOT / "nexus_bridge_stop.sh",
            ROOT / "nexus_bridge_start.sh",
            ROOT / "termux-boot" / "00-nexus-bridge",
        ]
        for script in scripts:
            result = subprocess.run([bash, "-n", str(script)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, f"{script.name}: {result.stderr}")

    def test_termux_supervisor_and_boot_installation_are_integrated(self):
        supervisor = (ROOT / "nexus_bridge_supervisor.sh").read_text(encoding="utf-8")
        installer = (ROOT / "install_termux_autostart.sh").read_text(encoding="utf-8")
        bridge = (ROOT / "nexus_bridge_termux.py").read_text(encoding="utf-8")
        self.assertIn("FAILURES", supervisor)
        self.assertIn("health check", supervisor.lower())
        self.assertIn("nexus-bridge", installer)
        self.assertIn("/api/bridge/control", bridge)
        self.assertIn("supervisor_active", bridge)
        self.assertIn("bridge-supervisor.lock", supervisor)
        self.assertIn("Atomic singleton guard", supervisor)
        starter = (ROOT / "nexus_bridge_start.sh").read_text(encoding="utf-8")
        self.assertIn('nohup bash "$APP_DIR/nexus_bridge_supervisor.sh"', starter)

    def test_baseline_change_tracking_and_professional_report_are_integrated(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn('id="compare-local-audit"', html)
        self.assertIn('"/api/audit/compare"', html)
        self.assertIn("change_tracking", html)
        self.assertIn("const changes =", html)
        self.assertIn("Comparación con línea base", html)

    def test_detailed_local_security_audit_and_report_exports_are_integrated(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn('id="audit-local-host"', html)
        self.assertIn('id="export-local-audit-json"', html)
        self.assertIn('id="export-local-audit-html"', html)
        self.assertIn('id="print-local-audit"', html)
        self.assertIn('"/api/audit"', html)
        self.assertIn("buildLocalAuditHtml", html)
        self.assertIn("El valor no se ha almacenado", html)
        self.assertIn("no sigue redirecciones", html)

if __name__ == "__main__":
    unittest.main()
