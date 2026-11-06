import tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import nexus_audit_baseline as baseline

def report(ports,fingerprint="AA",headers=None):
 return {"ok":True,"target":"192.168.1.1","generated_at":"2026-11-05T10:00:00+00:00",
 "scan":{"open_ports":[{"port":p} for p in ports]},
 "services":[{"port":443,"scheme":"https","reachable":True,"http_status":200,
 "headers":headers or {"strict-transport-security":"max-age=10"},"cookies":[],"tls":{"status":"verified"},
 "certificate":{"sha256_fingerprint":fingerprint,"not_after":"2031-07-10","subject":"CN=router","issuer":"CN=CA"}}]}

class BaselineTests(unittest.TestCase):
 def test_first_scan_creates_baseline(self):
  with tempfile.TemporaryDirectory() as d,patch.object(baseline,"BASELINE_DIR",Path(d)):
   r=baseline.compare_and_store_baseline(report([80,443]))
   self.assertEqual(r["status"],"baseline_created");self.assertFalse(r["compared"])
 def test_detects_port_certificate_and_configuration_changes(self):
  with tempfile.TemporaryDirectory() as d,patch.object(baseline,"BASELINE_DIR",Path(d)):
   baseline.compare_and_store_baseline(report([80,443]))
   r=baseline.compare_and_store_baseline(report([80,443,8080],"BB",{"x-frame-options":"DENY"}))
   codes={x["code"] for x in r["changes"]}
   self.assertTrue({"new_open_port","tls_certificate_changed","configuration_changed"}<=codes)
 def test_cookie_values_not_saved_and_public_ip_rejected(self):
  with tempfile.TemporaryDirectory() as d,patch.object(baseline,"BASELINE_DIR",Path(d)):
   x=report([443]);x["services"][0]["cookies"]=[{"name":"SID","value":"secret"}]
   baseline.compare_and_store_baseline(x)
   self.assertNotIn("secret",next(Path(d).glob("*.json")).read_text())
   x["target"]="8.8.8.8"
   with self.assertRaises(ValueError): baseline.compare_and_store_baseline(x)

 def test_corrupt_baseline_is_preserved_and_not_replaced(self):
  with tempfile.TemporaryDirectory() as d,patch.object(baseline,"BASELINE_DIR",Path(d)):
   path=baseline._path("192.168.1.1")
   path.parent.mkdir(parents=True,exist_ok=True)
   original="{not valid json"
   path.write_text(original,encoding="utf-8")
   with self.assertRaisesRegex(ValueError,"dañada"):
    baseline.compare_and_store_baseline(report([80,443]))
   self.assertEqual(path.read_text(encoding="utf-8"),original)

 def test_incompatible_baseline_is_preserved(self):
  with tempfile.TemporaryDirectory() as d,patch.object(baseline,"BASELINE_DIR",Path(d)):
   path=baseline._path("192.168.1.1")
   path.parent.mkdir(parents=True,exist_ok=True)
   original='{"schema_version":999,"open_ports":[],"services":{}}'
   path.write_text(original,encoding="utf-8")
   with self.assertRaisesRegex(ValueError,"incompatible"):
    baseline.compare_and_store_baseline(report([80]))
   self.assertEqual(path.read_text(encoding="utf-8"),original)

if __name__=="__main__": unittest.main()
