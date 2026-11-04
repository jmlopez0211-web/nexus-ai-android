import unittest
from unittest.mock import patch

import nexus_wireless_engine as engine


class SafeModuleLaunchTests(unittest.TestCase):
    def test_requested_modules_start_in_read_only_mode(self):
        fake_wifi = {
            "available": True, "ok": True, "network_count": 2,
            "source": "live", "message": "Termux API disponible",
        }
        with patch.object(engine, "_wifi_api_check", return_value=fake_wifi):
            for module_id in ("wacker", "hostapd_mana", "wifite2", "eaphammer"):
                with self.subTest(module_id=module_id):
                    result = engine.run_tool_module(module_id)
                    self.assertTrue(result["started"])
                    self.assertEqual(result["mode"], "read_only_python_diagnostic")
                    self.assertFalse(result["external_tool"]["executed"])
                    self.assertTrue(result["limitations"])

    def test_unknown_module_is_rejected(self):
        with self.assertRaises(ValueError):
            engine.run_tool_module("unknown")


if __name__ == "__main__":
    unittest.main()
