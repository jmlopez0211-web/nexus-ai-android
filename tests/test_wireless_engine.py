import unittest
from unittest.mock import patch, Mock
import nexus_wireless_engine as engine

class WirelessEngineInventoryTests(unittest.TestCase):
    def test_catalog_contains_requested_tools(self):
        report = engine.inventory_tools()
        self.assertEqual({item["name"] for item in report["tools"]}, {"Wacker", "hostapd-mana", "Wifite2", "EAPHammer"})

    def test_inventory_is_read_only(self):
        report = engine.inventory_tools()
        self.assertEqual(report["mode"], "runtime_diagnostic_read_only")
        self.assertFalse(report["safety"]["tools_executed"])
        self.assertFalse(report["safety"]["tools_installed"])
        self.assertFalse(report["safety"]["credential_capture"])
        self.assertFalse(report["safety"]["password_attempts"])
        self.assertTrue(all(item["execution"] == "deshabilitada" for item in report["tools"]))

    def test_environment_has_explicit_hardware_unknowns(self):
        environment = engine.inspect_environment()
        self.assertIn("python_version", environment)
        self.assertIn("machine", environment)
        self.assertIsNone(environment["monitor_mode_supported"])
        self.assertIsNone(environment["packet_injection_supported"])

    def test_wifi_api_parses_scan_without_exposing_network_details(self):
        mock = Mock(returncode=0, stdout='[{"ssid":"private-name","bssid":"00:11:22:33:44:55"},{"ssid":"other"}]', stderr="")
        with patch.object(engine.shutil, "which", return_value="/usr/bin/termux-wifi-scaninfo"), patch.object(engine.subprocess, "run", return_value=mock):
            result = engine._wifi_api_check()
        self.assertTrue(result["ok"])
        self.assertEqual(result["network_count"], 2)
        self.assertNotIn("private-name", str(result))

    def test_empty_wifi_scan_is_valid_api_response(self):
        mock = Mock(returncode=0, stdout="[]", stderr="")
        with patch.object(engine.shutil, "which", return_value="/usr/bin/termux-wifi-scaninfo"), patch.object(engine.subprocess, "run", return_value=mock):
            result = engine._wifi_api_check()
        self.assertTrue(result["ok"])
        self.assertEqual(result["network_count"], 0)

    def test_python_self_test(self):
        checks = engine._python_self_test()
        self.assertTrue(checks)
        self.assertTrue(all(item["ok"] for item in checks))

if __name__ == "__main__":
    unittest.main()
