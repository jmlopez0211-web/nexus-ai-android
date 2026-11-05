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
        self.assertIn('const CACHE_NAME = "nexus-shell-v2";', worker)


if __name__ == "__main__":
    unittest.main()
