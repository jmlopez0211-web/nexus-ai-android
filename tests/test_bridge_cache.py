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
        self.original_cache = bridge.WIFI_CACHE
        self.original_saved_at = bridge.WIFI_CACHE_SAVED_AT
        bridge.WIFI_CACHE = []
        bridge.WIFI_CACHE_SAVED_AT = 0.0
        bridge.WIFI_CACHE_FILE = os.path.join(self.temp_dir.name, "wifi-inventory.json")

    def tearDown(self):
        bridge.WIFI_CACHE_FILE = self.original_path
        bridge.WIFI_CACHE = self.original_cache
        bridge.WIFI_CACHE_SAVED_AT = self.original_saved_at
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

    def test_normalization_preserves_android_scan_timestamp_and_radio_metadata(self):
        raw = [{
            "ssid": "LAB-TEST", "bssid": "00:11:22:33:44:55", "rssi": -48,
            "frequency_mhz": 5180, "timestamp": 115000000,
            "center_frequency_mhz": 5210, "operator_name": "Lab"
        }]
        normalized = bridge.normalize_wifi_networks(raw)
        self.assertEqual(normalized[0]["timestamp"], 115000000)
        self.assertEqual(normalized[0]["center_frequency_mhz"], 5210)
        self.assertEqual(normalized[0]["operator_name"], "Lab")

    def test_live_inventory_updates_cache_and_returns_source_metadata(self):
        sample = [{"ssid": "LAB-TEST", "timestamp": 115000000}]
        with patch.object(bridge, "save_wifi_cache", return_value=1000.0):
            inventory, cached, saved_at, cache_age = bridge.resolve_wifi_inventory(sample, now=1000.0)
        self.assertEqual(inventory, sample)
        self.assertFalse(cached)
        self.assertEqual(saved_at, 1000.0)
        self.assertEqual(cache_age, 0)

    def test_empty_result_uses_recent_cache_without_claiming_live_data(self):
        sample = [{"ssid": "LAB-TEST", "timestamp": 115000000}]
        bridge.WIFI_CACHE = sample
        bridge.WIFI_CACHE_SAVED_AT = 950.0
        inventory, cached, saved_at, cache_age = bridge.resolve_wifi_inventory([], now=1000.0)
        self.assertEqual(inventory, sample)
        self.assertTrue(cached)
        self.assertEqual(saved_at, 950.0)
        self.assertEqual(cache_age, 50)

    def test_android_scan_timestamp_is_reported_as_an_age(self):
        sample = [{"timestamp": 115000000}]
        clock_id = getattr(bridge.time, "CLOCK_BOOTTIME", None)
        if clock_id is None:
            self.skipTest("CLOCK_BOOTTIME is not available on this platform")
        with patch.object(bridge.time, "clock_gettime", return_value=120.0):
            self.assertEqual(bridge.latest_wifi_scan_age_seconds(sample), 5)

    def test_missing_scan_timestamp_is_unknown_not_zero(self):
        self.assertIsNone(bridge.latest_wifi_scan_age_seconds([{"ssid": "NO-TIMESTAMP"}]))


if __name__ == "__main__":
    unittest.main()
