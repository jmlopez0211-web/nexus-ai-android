import unittest
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / "índice.html"


class WifiResultsPlacementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = HTML.read_text(encoding="utf-8")

    def test_wifi_results_container_follows_wifi_status(self):
        status = self.source.index('<p id="nexus-wifi-status"')
        container = self.source.index('<div id="wifi-networks"')
        services = self.source.index('<h3>Servicios expuestos en tu red local</h3>')
        self.assertLess(status, container)
        self.assertLess(container, services)
        self.assertEqual(self.source.count('<div id="wifi-networks"'), 1)

    def test_wifi_results_stay_inside_wifi_center(self):
        center = self.source.index('<section id="wifi-center"')
        status = self.source.index('<p id="nexus-wifi-status"')
        container = self.source.index('<div id="wifi-networks"')
        center_end = self.source.index('</section>', container)
        self.assertLess(center, status)
        self.assertLess(container, center_end)


if __name__ == "__main__":
    unittest.main()
