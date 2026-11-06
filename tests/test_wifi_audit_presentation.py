import unittest
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / "índice.html"


class WifiAuditPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HTML.read_text(encoding="utf-8")

    def test_high_severity_has_distinct_high_visibility_style(self):
        self.assertIn(".finding.high{border-left-color:#c62828}", self.source)

    def test_audit_preserves_original_severity_class(self):
        self.assertIn(
            'const severityClass=["high","medium","low","info"].includes(f.severity)?f.severity:"info";',
            self.source,
        )
        self.assertNotIn(
            'box.className="finding "+(f.severity==="high"?"medium":f.severity==="medium"?"low":"info");',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
