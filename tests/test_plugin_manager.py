import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import nexus_plugin_manager as manager


class PluginManagerTests(unittest.TestCase):
    def test_lists_unapproved_plugin_without_enabling_it(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            modules = home / "modules"
            modules.mkdir()
            (modules / "sample.py").write_text("print('ok')", encoding="utf-8")
            (home / "registry.json").write_text(json.dumps([{
                "id": "sample", "name": "Sample", "entrypoint": "sample.py",
                "approved": False
            }]), encoding="utf-8")
            with patch.object(manager, "PLUGIN_HOME", home), patch.object(manager, "REGISTRY", home / "registry.json"):
                item = manager.list_plugins()[0]
                self.assertTrue(item["detected"])
                self.assertFalse(item["approved"])
                with self.assertRaises(PermissionError):
                    manager.launch_plugin("sample")

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            modules = home / "modules"
            modules.mkdir()
            (home / "registry.json").write_text(json.dumps([{
                "id": "escape", "entrypoint": "../outside.py", "approved": True
            }]), encoding="utf-8")
            with patch.object(manager, "PLUGIN_HOME", home), patch.object(manager, "REGISTRY", home / "registry.json"):
                with self.assertRaises(ValueError):
                    manager.launch_plugin("escape")


if __name__ == "__main__":
    unittest.main()
