import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

with patch.dict(os.environ, {"NEXUS_BRIDGE_TOKEN": "unit-test-token"}):
    import nexus_bridge_termux as bridge


class WifiCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_path = bridge.WIFI_CACHE_FILE
        bridge.WIFI_CACHE_FILE = os.path.join(self.temp_dir.name, "wifi-inventory.json")

    def tearDown(self):
        bridge.WIFI_CACHE_FILE = self.original_path
        self.temp_dir.cleanup()

    def test_cache_round_trip(self):
        sample = [{"ssid": "LAB-TEST", "rssi": -42, "capabilities": "[WPA2-PSK]"}]
        saved_at = bridge.save_wifi_cache(sample)
        loaded, loaded_at = bridge.load_wifi_cache()
        self.assertEqual(loaded, sample)
        self.assertEqual(loaded_at, saved_at)

    def test_expired_cache_is_ignored(self):
        with open(bridge.WIFI_CACHE_FILE, "w", encoding="utf-8") as cache_file:
            json.dump({"saved_at": time.time() - bridge.WIFI_CACHE_TTL_SECONDS - 1,
                       "networks": [{"ssid": "STALE"}]}, cache_file)
        loaded, loaded_at = bridge.load_wifi_cache()
        self.assertEqual(loaded, [])
        self.assertEqual(loaded_at, 0.0)


if __name__ == "__main__":
    unittest.main()
