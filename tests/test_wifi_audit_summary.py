import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WifiAuditSummaryTests(unittest.TestCase):
    def test_legacy_summary_counts_mixed_wpa1_and_tkip_capabilities(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn(r"if (/WEP|\[WPA-PSK|TKIP/.test(caps)) counts.legacy++;", html)

    def test_report_records_inventory_provenance_and_age(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        for field in (
            "inventory_mode:",
            "inventory_requested_at:",
            "last_nonempty_api_response_at:",
            "inventory_cache_age_seconds:",
            "android_scan_age_seconds:",
        ):
            with self.subTest(field=field):
                self.assertIn(field, html)


if __name__ == "__main__":
    unittest.main()
