import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import nexus_r2su as r2su


class R2SUTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "r2su.sqlite3"
        self.patch = patch.object(r2su, "DB_PATH", self.db)
        self.patch.start()
        r2su.initialize()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_create_and_list_task(self):
        created = r2su.create_task("Diagnóstico", "runtime_diagnostics", interval_seconds=300)
        task = r2su.list_tasks()["tasks"][0]
        self.assertEqual(task["id"], created["task_id"])
        self.assertEqual(task["interval_seconds"], 300)
        self.assertTrue(task["enabled"])

    def test_rejects_unknown_task_and_arbitrary_params(self):
        with self.assertRaises(ValueError):
            r2su.create_task("shell", "shell", {"cmd": "id"})
        with self.assertRaises(ValueError):
            r2su.create_task("wifi", "wifi_inventory", {"command": "anything"})

    def test_lan_task_requires_confirmation_and_private_ipv4(self):
        with self.assertRaises(PermissionError):
            r2su.create_task("LAN", "lan_scan", {"target": "192.168.1.1"})
        with self.assertRaises(ValueError):
            r2su.create_task("LAN", "lan_scan", {"target": "8.8.8.8", "authorized": True})
        created = r2su.create_task("LAN", "lan_scan", {"target": "192.168.1.1", "authorized": True})
        self.assertEqual(created["task_id"], r2su.list_tasks()["tasks"][0]["id"])

    def test_run_persists_result_and_disables_one_shot(self):
        created = r2su.create_task("Diagnóstico", "runtime_diagnostics")
        with patch.object(r2su, "_execute", return_value={"ok": True, "status": "healthy"}):
            result = r2su.run_task(created["task_id"])
        self.assertTrue(result["ok"])
        listed = r2su.list_tasks(include_history=True)
        self.assertFalse(listed["tasks"][0]["enabled"])
        self.assertEqual(listed["history"][0]["result"]["data"]["status"], "healthy")

    def test_periodic_run_reschedules(self):
        created = r2su.create_task("WiFi", "wifi_inventory", interval_seconds=60)
        before = r2su.list_tasks()["tasks"][0]["next_run"]
        with patch.object(r2su, "_execute", return_value={"ok": True, "network_count": 4}):
            r2su.run_task(created["task_id"])
        after = r2su.list_tasks()["tasks"][0]["next_run"]
        self.assertNotEqual(before, after)

    def test_pause_resume_and_delete(self):
        created = r2su.create_task("WiFi", "wifi_inventory", interval_seconds=60)
        task_id = created["task_id"]
        self.assertFalse(r2su.set_task_enabled(task_id, False)["enabled"])
        self.assertTrue(r2su.set_task_enabled(task_id, True)["enabled"])
        self.assertTrue(r2su.delete_task(task_id)["deleted"])
        self.assertEqual(r2su.list_tasks()["tasks"], [])

    def test_rejects_invalid_interval_and_naive_datetime(self):
        with self.assertRaises(ValueError):
            r2su.create_task("Bad", "wifi_inventory", interval_seconds=10)
        with self.assertRaises(ValueError):
            r2su.create_task("Bad", "wifi_inventory", run_at="2030-01-01T10:00:00")

if __name__ == "__main__":
    unittest.main()
