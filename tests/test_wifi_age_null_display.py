import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WifiAgeNullDisplayTests(unittest.TestCase):
    def test_missing_scan_age_is_not_rendered_as_zero_seconds(self):
        html = (ROOT / "índice.html").read_text(encoding="utf-8")
        self.assertIn('if(seconds===null||seconds===undefined||seconds==="")return "no disponible";', html)


if __name__ == "__main__":
    unittest.main()
