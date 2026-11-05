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


    def test_empty_scan_uses_recent_bridge_cache(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch, Mock
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory) / ".cache" / "nexus-ai"
            cache_dir.mkdir(parents=True)
            (cache_dir / "wifi-inventory.json").write_text(
                json.dumps({"saved_at": 1000, "networks": [{"ssid": "hidden"}]}),
                encoding="utf-8",
            )
            mock = Mock(returncode=0, stdout="[]", stderr="")
            with patch.object(engine.Path, "home", return_value=Path(directory)), \
                 patch.object(engine.time, "time", return_value=1100), \
                 patch.object(engine.shutil, "which", return_value="/usr/bin/termux-wifi-scaninfo"), \
                 patch.object(engine.subprocess, "run", return_value=mock):
                result = engine._wifi_api_check()
        self.assertTrue(result["ok"])
        self.assertEqual(result["network_count"], 1)
        self.assertEqual(result["source"], "cache")
        self.assertNotIn("hidden", str(result))

    def test_python_self_test(self):
        checks = engine._python_self_test()
        self.assertTrue(checks)
        self.assertTrue(all(item["ok"] for item in checks))

    def test_scan_timestamp_age_is_calculated_without_exposing_network_identity(self):
        clock_id = getattr(engine.time, "CLOCK_BOOTTIME", None)
        if clock_id is None:
            self.skipTest("CLOCK_BOOTTIME is not available on this platform")
        with patch.object(engine.time, "clock_gettime", return_value=120.0):
            age = engine._latest_wifi_scan_age_seconds([
                {"ssid": "private-network", "timestamp": 115000000}
            ])
        self.assertEqual(age, 5)

    def test_wifi_report_explains_that_termux_api_reads_latest_android_results(self):
        mock = Mock(returncode=0, stdout='[{"ssid":"private-name","timestamp":115000000}]', stderr="")
        clock_id = getattr(engine.time, "CLOCK_BOOTTIME", None)
        with patch.object(engine.shutil, "which", return_value="/usr/bin/termux-wifi-scaninfo"), \
             patch.object(engine.subprocess, "run", return_value=mock), \
             patch.object(engine.time, "clock_gettime", return_value=120.0):
            result = engine._wifi_api_check()
        self.assertEqual(result["source"], "live")
        self.assertEqual(result["scan_age_seconds"], 5)
        self.assertEqual(result["scan_api_mode"], "latest_android_results_only")
        self.assertNotIn("private-name", str(result))

if __name__ == "__main__":
    unittest.main()
