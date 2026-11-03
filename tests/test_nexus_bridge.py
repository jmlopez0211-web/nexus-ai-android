import unittest
from unittest.mock import patch

from nexus_bridge_termux import validate_lan_target, scan_host


class NexusBridgeTests(unittest.TestCase):
    def test_accepts_private_lan_ipv4(self):
        self.assertEqual(validate_lan_target("192.168.1.10"), "192.168.1.10")

    def test_rejects_public_target(self):
        with self.assertRaises(ValueError):
            validate_lan_target("8.8.8.8")

    def test_rejects_hostname(self):
        with self.assertRaises(ValueError):
            validate_lan_target("router.local")


    def test_rejects_documentation_network(self):
        with self.assertRaises(ValueError):
            validate_lan_target("192.0.2.10")

    def test_rejects_loopback(self):
        with self.assertRaises(ValueError):
            validate_lan_target("127.0.0.1")

    @patch("nexus_bridge_termux.probe_port")
    def test_reports_only_open_ports(self, probe):
        probe.side_effect = lambda target, port: port in (22, 443)
        result = scan_host("192.168.1.10")
        self.assertEqual(result["open_count"], 2)
        self.assertEqual([item["port"] for item in result["open_ports"]], [22, 443])
        self.assertEqual(result["mode"], "single_host_tcp_connect")


if __name__ == "__main__":
    unittest.main()
