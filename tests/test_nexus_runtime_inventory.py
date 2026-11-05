import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import nexus_runtime_inventory as runtime


class RuntimeInventoryTests(unittest.TestCase):
    def test_inventory_separates_categories(self):
        report = runtime.inventory()
        self.assertIn("runtimes", report)
        self.assertIn("sql_engines", report)
        self.assertIn("internal_modules", report)
        self.assertIn("tools", report)
        self.assertIn("python_modules", report)
        self.assertIn("python_packages", report)
        self.assertIn("proot_environments", report)
        self.assertIsInstance(report["python_packages"], list)
        self.assertIsInstance(report["proot_environments"], list)
        self.assertTrue(report["policy"]["inventory_read_only"])

    def test_sqlite_smoke_test_uses_memory_database(self):
        result = runtime.run_runtime_check("sqlite", confirmed=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["result"], "SQLITE_OK")

    def test_unknown_runtime_is_rejected(self):
        with self.assertRaises(ValueError):
            runtime.run_runtime_check("arbitrary-command", confirmed=True)

    def test_runtime_test_requires_confirmation(self):
        with self.assertRaises(PermissionError):
            runtime.run_runtime_check("python")

    def test_repair_requires_confirmation(self):
        with self.assertRaises(PermissionError):
            runtime.repair_owned_storage()

    def test_repair_only_touches_configured_owned_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = (Path(tmp) / "cache", Path(tmp) / "reports")
            with patch.object(runtime, "OWNED_DIRS", paths):
                result = runtime.repair_owned_storage(confirmed=True)
            self.assertTrue(result["ok"])
            self.assertTrue(all(path.is_dir() for path in paths))
            self.assertEqual(len(result["repaired"]), 2)


if __name__ == "__main__":
    unittest.main()
