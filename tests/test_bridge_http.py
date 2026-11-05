import json
import os
import pathlib
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace
from unittest.mock import patch

from http.server import ThreadingHTTPServer

import nexus_bridge_termux as bridge


class BridgeHttpContractTests(unittest.TestCase):
    def setUp(self):
        self.origin = "https://nexus-ai-android-3.onrender.com"
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_cache_file = bridge.WIFI_CACHE_FILE
        self.old_cache = bridge.WIFI_CACHE
        self.old_saved_at = bridge.WIFI_CACHE_SAVED_AT
        bridge.WIFI_CACHE_FILE = str(pathlib.Path(self.temp_dir.name) / "wifi.json")
        bridge.WIFI_CACHE = []
        bridge.WIFI_CACHE_SAVED_AT = 0.0
        self.patches = [
            patch.object(bridge, "TOKEN", "unit-test-token"),
            patch.object(bridge, "ALLOWED_ORIGINS", {self.origin}),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        bridge.WIFI_CACHE_FILE = self.old_cache_file
        bridge.WIFI_CACHE = self.old_cache
        bridge.WIFI_CACHE_SAVED_AT = self.old_saved_at
        self.temp_dir.cleanup()

    def request(self, path, token="unit-test-token", origin=None, method="GET"):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if origin is not None:
            headers["Origin"] = origin
        request = urllib.request.Request(self.url + path, headers=headers, method=method)
        return urllib.request.urlopen(request, timeout=3)

    def test_status_requires_token_and_returns_cors_for_allowed_origin(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request("/api/status", token="wrong", origin=self.origin)
        self.assertEqual(error.exception.code, 401)
        self.assertEqual(error.exception.headers.get("Access-Control-Allow-Origin"), self.origin)

        with self.request("/api/status", origin=self.origin) as response:
            payload = json.loads(response.read())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["wifi_data_mode"], "latest_android_scan_results")

    def test_preflight_allows_authorization_and_private_network(self):
        with self.request("/api/wifi", token=None, origin=self.origin, method="OPTIONS") as response:
            self.assertEqual(response.status, 204)
            self.assertEqual(response.headers.get("Access-Control-Allow-Private-Network"), "true")
            self.assertIn("Authorization", response.headers.get("Access-Control-Allow-Headers", ""))

    def test_wifi_endpoint_returns_source_age_and_preserves_android_timestamp(self):
        raw = '[{"ssid":"LAB","bssid":"00:11:22:33:44:55","rssi":-45,"frequency_mhz":5180,"timestamp":115000000}]'
        fake_result = SimpleNamespace(returncode=0, stdout=raw, stderr="")
        with patch.object(bridge, "_termux_wifi_command", return_value="/usr/bin/termux-wifi-scaninfo"), \
             patch("subprocess.run", return_value=fake_result), \
             patch.object(bridge.time, "clock_gettime", return_value=120.0):
            with self.request("/api/wifi", origin=self.origin) as response:
                payload = json.loads(response.read())
        self.assertEqual(payload["mode"], "live")
        self.assertFalse(payload["cached"])
        self.assertEqual(payload["source"], "termux_api")
        self.assertEqual(payload["scan_age_seconds"], 5)
        self.assertEqual(payload["networks"][0]["timestamp"], 115000000)


if __name__ == "__main__":
    unittest.main()
