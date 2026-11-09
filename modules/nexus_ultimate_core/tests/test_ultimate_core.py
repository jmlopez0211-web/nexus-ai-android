import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ultimate_core import UltimateCore


class UltimateCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = Path(self.temp.name) / "config.json"
        self.config.write_text(json.dumps({
            "settings": {
                "logs_enabled": False,
                "report_directory": "reports",
                "log_directory": "logs",
                "bridge_host": "127.0.0.1",
                "bridge_port": 8766
            },
            "paths": {"nmap": "nmap"}
        }), encoding="utf-8")
        self.core = UltimateCore(self.config)

    def tearDown(self):
        self.temp.cleanup()

    def test_catalog_has_three_modules(self):
        self.assertEqual(set(self.core.modules), {"nmap", "termux_api", "system_check"})

    def test_unknown_module_is_rejected(self):
        self.assertEqual(self.core.execute("unknown")["status"], "error")

    def test_nmap_requires_explicit_authorization(self):
        with patch("ultimate_core.subprocess.run") as runner:
            result = self.core.run_nmap("127.0.0.1")
        self.assertEqual(result["status"], "blocked")
        runner.assert_not_called()

    def test_public_and_dns_targets_are_rejected(self):
        self.assertEqual(self.core.run_nmap("8.8.8.8", authorization_confirmed=True)["status"], "error")
        self.assertEqual(self.core.run_nmap("example.com", authorization_confirmed=True)["status"], "error")

    def test_nmap_missing_binary_is_reported(self):
        with patch("ultimate_core.shutil.which", return_value=None):
            result = self.core.run_nmap("127.0.0.1", authorization_confirmed=True)
        self.assertEqual(result["status"], "unavailable")

    def test_nmap_xml_parser_extracts_open_port(self):
        xml = """<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/></port></ports>
        </host></nmaprun>"""
        result = self.core.parse_nmap_xml(xml)
        self.assertEqual(result[0]["open_ports"][0]["port"], 22)
        self.assertEqual(result[0]["open_ports"][0]["service"]["name"], "ssh")

    def test_termux_api_only_accepts_registered_actions(self):
        self.assertEqual(self.core.run_termux_api("something-else")["status"], "error")

    def test_system_check_returns_python_and_bridge_state(self):
        result = self.core.run_system_check()
        self.assertEqual(result["status"], "success")
        self.assertIn("python_version", result["environment"])
        self.assertIn("nmap", result["tools"])

    def test_compatibility_alias(self):
        from ultimate_core import NexusCore
        self.assertIs(NexusCore, UltimateCore)


if __name__ == "__main__":
    unittest.main()
