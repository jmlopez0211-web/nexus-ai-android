import unittest
from unittest.mock import patch

import nexus_android_wifi_diagnostics as diag


class AndroidWifiDiagnosticsTests(unittest.TestCase):
    def test_report_contains_hardware_android_and_termux_sections(self):
        with patch.object(diag, "inspect_hardware", return_value={
            "interface": "wlan0", "available": True, "state": "up",
            "driver": "wlan_driver", "module": "wlan_module",
            "chipset_ids": {"vendor": "0x1234"}, "device_path": None,
            "diagnosis": "visible"
        }), patch.object(diag, "_android_services", return_value={
            "wifi_service": {"available": True, "query_ok": True, "state": "enabled", "error": None},
            "termux_package": {"available": True, "query_ok": True,
                               "location_or_nearby_permissions_seen": [],
                               "permission_state": "not_confirmed"},
            "note": "restricted"
        }), patch.object(diag, "_scan_api", return_value={
            "scaninfo": {"available": True, "ok": True, "network_count": 2,
                         "result": "networks_found", "error": None, "stderr": ""},
            "connectioninfo": {"available": True, "ok": True, "error": None},
            "behavior": "latest only"
        }), patch.object(diag, "_android_properties", return_value={
            "ro.product.model": "Samsung"
        }):
            report = diag.diagnose_wifi_driver()
        self.assertTrue(report["ok"])
        self.assertEqual(report["hardware"]["driver"], "wlan_driver")
        self.assertEqual(report["termux_api"]["scaninfo"]["network_count"], 2)
        self.assertEqual(report["device"]["model"], "Samsung")
        self.assertEqual(report["mode"], "read_only")

    def test_empty_scan_is_reported_as_android_result_not_driver_failure(self):
        with patch.object(diag, "inspect_hardware", return_value={
            "interface": "wlan0", "available": True, "state": "up",
            "driver": "driver_x", "module": "module_x", "chipset_ids": {},
            "device_path": None, "diagnosis": "visible"
        }), patch.object(diag, "_android_services", return_value={
            "wifi_service": {"available": True, "query_ok": True, "state": "enabled", "error": None},
            "termux_package": {"available": True, "query_ok": True,
                               "location_or_nearby_permissions_seen": [],
                               "permission_state": "granted"}, "note": ""
        }), patch.object(diag, "_scan_api", return_value={
            "scaninfo": {"available": True, "ok": True, "network_count": 0,
                         "result": "empty_android_result", "error": None, "stderr": ""},
            "connectioninfo": {"available": True, "ok": True, "error": None}, "behavior": ""
        }), patch.object(diag, "_android_properties", return_value={}):
            report = diag.diagnose_wifi_driver()
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("ANDROID_SCAN_RESULTS_EMPTY", codes)
        self.assertNotIn("WIFI_DRIVER_NOT_IDENTIFIED", codes)

    def test_scan_report_never_contains_network_identity(self):
        with patch.object(diag, "_run", side_effect=[
            {"available": True, "ok": True, "returncode": 0,
             "stdout": '[{"ssid":"PRIVATE_WIFI","bssid":"aa:bb:cc:dd:ee:ff"}]',
             "stderr": "", "error": None},
            {"available": True, "ok": True, "returncode": 0,
             "stdout": '{"ssid":"PRIVATE_WIFI","ip":"192.168.1.5"}',
             "stderr": "", "error": None}
        ]):
            result = diag._scan_api()
        self.assertEqual(result["scaninfo"]["network_count"], 1)
        self.assertNotIn("PRIVATE_WIFI", str(result))
        self.assertNotIn("192.168.1.5", str(result))

    def test_missing_termux_api_is_explicit(self):
        with patch.object(diag, "_run", return_value={
            "available": False, "ok": False, "returncode": None,
            "stdout": "", "stderr": "", "error": "comando_no_disponible"
        }):
            result = diag._scan_api()
        self.assertFalse(result["scaninfo"]["available"])
        self.assertEqual(result["scaninfo"]["result"], "scan_unavailable_or_failed")


if __name__ == "__main__":
    unittest.main()
