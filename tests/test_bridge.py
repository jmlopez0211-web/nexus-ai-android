import unittest
from unittest.mock import patch

import nexus_bridge_termux as bridge


class BridgeValidationTests(unittest.TestCase):
    def test_accepts_private_ipv4_ranges(self):
        for address in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            with self.subTest(address=address):
                self.assertEqual(bridge.validate_lan_target(address), address)

    def test_rejects_public_ipv4_and_ipv6(self):
        for address in ("8.8.8.8", "2001:4860:4860::8888", "not-an-ip"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    bridge.validate_lan_target(address)

    def test_scan_checks_only_the_defined_ports_and_reports_open_services(self):
        def fake_probe(target, port, timeout=bridge.CONNECT_TIMEOUT):
            return port in (53, 443)

        with patch.object(bridge, "probe_port", side_effect=fake_probe) as probe:
            result = bridge.scan_host("192.168.1.1")

        self.assertTrue(result["ok"])
        self.assertEqual(result["target"], "192.168.1.1")
        self.assertEqual(result["mode"], "single_host_tcp_connect")
        self.assertEqual(result["scanned_ports"], len(bridge.PORTS))
        self.assertEqual(result["open_ports"], [
            {"port": 53, "service": "DNS", "protocol": "tcp", "state": "open"},
            {"port": 443, "service": "HTTPS", "protocol": "tcp", "state": "open"},
        ])
        self.assertEqual(probe.call_count, len(bridge.PORTS))

    def test_scan_rejects_non_private_target_before_probing(self):
        with patch.object(bridge, "probe_port") as probe:
            with self.assertRaises(ValueError):
                bridge.scan_host("8.8.8.8")
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
