import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from http.server import ThreadingHTTPServer

import nexus_bridge_termux as bridge


class DetailedAuditEndpointTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
        self.token_patch = patch.object(bridge, "TOKEN", "audit-test-token")
        self.token_patch.start()

    def tearDown(self):
        self.token_patch.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def post(self, payload):
        request = urllib.request.Request(
            self.url + "/api/audit",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": "Bearer audit-test-token",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        return urllib.request.urlopen(request, timeout=3)

    def test_detailed_audit_requires_explicit_authorization(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.post({"target": "192.168.1.1", "authorized": False})
        self.assertEqual(error.exception.code, 403)

    def test_detailed_audit_calls_existing_scan_and_returns_report(self):
        scan = {"target": "192.168.1.1", "open_count": 0, "scanned_ports": 20, "open_ports": []}
        report = {
            "ok": True,
            "report_type": "defensive_single_host_security_audit",
            "target": "192.168.1.1",
            "services": [],
        }
        with patch.object(bridge, "scan_host", return_value=scan) as scan_mock, \
             patch.object(bridge, "build_security_report", return_value=report) as report_mock:
            with self.post({"target": "192.168.1.1", "authorized": True}) as response:
                result = json.loads(response.read())
        self.assertEqual(result, report)
        scan_mock.assert_called_once_with("192.168.1.1")
        report_mock.assert_called_once_with("192.168.1.1", scan, bridge.PORTS)


if __name__ == "__main__":
    unittest.main()
