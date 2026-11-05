import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import nexus_capability_diagnostic as diag


class PrivilegeDiagnosticTests(unittest.TestCase):
    def test_proot_uid_zero_is_not_reported_as_android_root(self):
        with patch.object(diag.os, "getuid", return_value=0), \
             patch.object(diag.os, "geteuid", return_value=0), \
             patch.object(diag.os, "getgroups", return_value=[0]), \
             patch.object(diag, "_read_text", return_value="CapEff:\t0000000000003000\n"):
            result = diag.inspect_privileges("ubuntu_proot")
        self.assertTrue(result["root_in_proot"])
        self.assertEqual(result["android_root"], "not_inferred_from_proot")
        self.assertTrue(result["capabilities"]["cap_net_admin"])
        self.assertTrue(result["capabilities"]["cap_net_raw"])

    def test_termux_nonzero_uid_does_not_claim_android_root(self):
        with patch.object(diag.os, "getuid", return_value=10234), \
             patch.object(diag.os, "geteuid", return_value=10234), \
             patch.object(diag.os, "getgroups", return_value=[]), \
             patch.object(diag, "_read_text", return_value=""):
            result = diag.inspect_privileges("termux")
        self.assertFalse(result["root_in_proot"])
        self.assertEqual(result["android_root"], "not_root")


class DevicePermissionTests(unittest.TestCase):
    def test_existing_device_node_reports_filesystem_access_bits(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            item = Path(directory) / "rfkill"
            item.write_text("test", encoding="utf-8")
            with patch.object(diag, "DEVICE_PERMISSION_PATHS", (str(item),)):
                result = diag._device_permissions()
        self.assertTrue(result[0]["exists"])
        self.assertIn("readable", result[0])
        self.assertIn("writable", result[0])
        self.assertIn("mode", result[0])

    def test_missing_device_node_is_not_claimed_available(self):
        with patch.object(diag, "DEVICE_PERMISSION_PATHS", ("/path/that/does/not/exist/nexus",)):
            result = diag._device_permissions()
        self.assertFalse(result[0]["exists"])
        self.assertEqual(result[0]["status"], "not_present")




class ToolCatalogTests(unittest.TestCase):
    def test_initial_and_existing_wireless_tools_are_all_in_inventory(self):
        ids = {item["id"] for item in diag.TOOL_DEFINITIONS}
        self.assertTrue({
            "wacker", "hostapd_mana", "wifite2", "eaphammer",
            "aircrack_ng", "airmon_ng", "airodump_ng", "aireplay_ng",
            "iw", "ip", "termux_wifi_api",
        }.issubset(ids))


class ExecutableDiagnosticTests(unittest.TestCase):
    def test_missing_program_is_not_executable(self):
        definition = {"id": "iw", "commands": ("missing-tool",), "probe_args": ("--help",)}
        with patch.object(diag.shutil, "which", return_value=None):
            result = diag._probe_executable(definition)
        self.assertFalse(result["installed"])
        self.assertEqual(result["execution_probe"], "not_installed")

    def test_program_is_executable_only_after_safe_probe_responds(self):
        definition = {"id": "iw", "commands": ("iw",), "probe_args": ("--version",)}
        completed = SimpleNamespace(returncode=0, stdout="iw version 6.17", stderr="")
        with patch.object(diag.shutil, "which", return_value="/usr/bin/iw"), \
             patch.object(diag.os, "access", return_value=True), \
             patch.object(diag.subprocess, "run", return_value=completed) as run:
            result = diag._probe_executable(definition)
        self.assertTrue(result["installed"])
        self.assertTrue(result["executable_permission"])
        self.assertEqual(result["execution_probe"], "responded")
        run.assert_called_once()

    def test_probe_timeout_is_not_reported_as_executable_response(self):
        definition = {"id": "iw", "commands": ("iw",), "probe_args": ("--version",)}
        with patch.object(diag.shutil, "which", return_value="/usr/bin/iw"), \
             patch.object(diag.os, "access", return_value=True), \
             patch.object(diag.subprocess, "run", side_effect=diag.subprocess.TimeoutExpired("iw", 1)):
            result = diag._probe_executable(definition)
        self.assertEqual(result["execution_probe"], "timeout")

    def test_termux_wifi_probe_does_not_expose_network_names(self):
        definition = {"id": "termux_wifi_api", "commands": ("termux-wifi-scaninfo",), "probe_args": ()}
        completed = SimpleNamespace(returncode=0, stdout='[{"ssid":"PRIVATE-LAB","bssid":"00:11:22:33:44:55"}]', stderr="")
        with patch.object(diag.shutil, "which", return_value="/usr/bin/termux-wifi-scaninfo"), \
             patch.object(diag.os, "access", return_value=True), \
             patch.object(diag.subprocess, "run", return_value=completed):
            result = diag._probe_executable(definition)
        self.assertEqual(result["execution_probe"], "responded")
        self.assertEqual(result["network_count"], 1)
        self.assertFalse(result["network_identifiers_included"])
        self.assertNotIn("PRIVATE-LAB", str(result))
        self.assertNotIn("00:11:22:33:44:55", str(result))


class WirelessCapabilityTests(unittest.TestCase):
    def test_monitor_is_only_advertised_when_iw_reports_it(self):
        dev = SimpleNamespace(returncode=0, stdout="phy#0\n Interface wlan0\n", stderr="")
        phy = SimpleNamespace(returncode=0, stdout="Wiphy phy0\n\tSupported interface modes:\n\t\t * managed\n\t\t * monitor\nBand 1:\n", stderr="")
        with patch.object(diag.subprocess, "run", side_effect=[dev, phy]):
            result = diag._iw_probe("/usr/bin/iw")
        self.assertEqual(result["netlink"], "accessible")
        self.assertEqual(result["monitor_mode"]["status"], "advertised_not_functionally_verified")
        self.assertTrue(result["monitor_mode"]["driver_advertises"])

    def test_netlink_failure_blocks_monitor_conclusion(self):
        dev = SimpleNamespace(returncode=1, stdout="", stderr="Failed to connect to generic netlink.")
        phy = SimpleNamespace(returncode=1, stdout="", stderr="Failed to connect to generic netlink.")
        with patch.object(diag.subprocess, "run", side_effect=[dev, phy]):
            result = diag._iw_probe("/usr/bin/iw")
        self.assertEqual(result["netlink"], "blocked_or_unavailable")
        self.assertEqual(result["monitor_mode"]["status"], "blocked_or_unknown")

    def test_packet_injection_is_never_assumed_from_tool_presence(self):
        missing = {"installed": False, "executable_permission": False,
                   "execution_probe": "not_installed", "path": None}
        with patch.object(diag, "_probe_executable", return_value=missing), \
             patch.object(diag, "_interfaces", return_value=([], [])), \
             patch.object(diag, "_iw_probe", return_value={
                 "installed": False, "netlink": "unknown", "wireless_interfaces": [],
                 "phy_devices": [], "monitor_mode": {"status": "unknown", "evidence": "iw missing"}
             }), \
             patch.object(diag, "inspect_privileges", return_value={"effective_uid": 1}):
            result = diag.inspect_runtime()
        self.assertEqual(result["packet_injection"]["status"], "unknown")
        self.assertFalse(result["packet_injection"]["verified"])
        self.assertEqual(result["android_permissions"]["location_permission"], "not_directly_inspectable")
        self.assertEqual(result["android_permissions"]["other_android_permissions"], "not_enumerated")


class UbuntuProotTests(unittest.TestCase):
    def test_missing_proot_distro_is_reported(self):
        with patch.object(diag.shutil, "which", return_value=None):
            result = diag.inspect_ubuntu_proot()
        self.assertFalse(result["available"])
        self.assertEqual(result["status"], "proot_distro_not_found")

    def test_ubuntu_probe_parses_json_and_keeps_root_scoped_to_proot(self):
        payload = {"environment": "Ubuntu Proot", "tools": [],
                   "privileges": {"effective_uid": 0, "root_in_proot": True,
                                  "android_root": "not_inferred_from_proot"},
                   "hardware_access": {"status": "blocked_or_not_exposed"},
                   "monitor_mode": {"status": "blocked_or_unknown"},
                   "packet_injection": {"status": "unknown", "verified": False}}
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        with patch.object(diag.shutil, "which", return_value="/usr/bin/proot-distro"), \
             patch.object(diag.subprocess, "run", return_value=completed):
            result = diag.inspect_ubuntu_proot()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["privileges"]["root_in_proot"])
        self.assertEqual(result["privileges"]["android_root"], "not_inferred_from_proot")


    def test_report_combines_both_environments_and_never_claims_radio_changes(self):
        termux = {"context": "termux", "packet_injection": {"status": "unknown", "verified": False}}
        ubuntu = {"available": True, "status": "ok", "packet_injection": {"status": "unknown", "verified": False}}
        with patch.object(diag, "inspect_runtime", return_value=termux), \
             patch.object(diag, "inspect_ubuntu_proot", return_value=ubuntu):
            report = diag.build_capability_report()
        self.assertTrue(report["ok"])
        self.assertIn("termux", report["environments"])
        self.assertIn("ubuntu_proot", report["environments"])
        self.assertFalse(report["safety"]["interfaces_changed"])
        self.assertFalse(report["safety"]["frames_injected"])
        self.assertFalse(report["safety"]["privileges_escalated"])


if __name__ == "__main__":
    unittest.main()
