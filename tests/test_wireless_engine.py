import unittest

import nexus_wireless_engine as engine


class WirelessEngineInventoryTests(unittest.TestCase):
    def test_catalog_contains_requested_tools(self):
        report = engine.inventory_tools()
        names = {item["name"] for item in report["tools"]}
        self.assertEqual(names, {"Wacker", "hostapd-mana", "Wifite2", "EAPHammer"})

    def test_inventory_is_read_only(self):
        report = engine.inventory_tools()
        self.assertEqual(report["mode"], "read_only_inventory")
        self.assertFalse(report["safety"]["tools_executed"])
        self.assertFalse(report["safety"]["tools_installed"])
        self.assertFalse(report["safety"]["credential_capture"])
        self.assertFalse(report["safety"]["password_attempts"])
        for item in report["tools"]:
            self.assertEqual(item["execution"], "deshabilitada")

    def test_environment_has_explicit_hardware_unknowns(self):
        environment = engine.inspect_environment()
        self.assertIn("python_version", environment)
        self.assertIn("machine", environment)
        self.assertIsNone(environment["monitor_mode_supported"])
        self.assertIsNone(environment["packet_injection_supported"])


if __name__ == "__main__":
    unittest.main()
