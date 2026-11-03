import pathlib
import unittest


class NexusWifiPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = pathlib.Path(__file__).resolve().parents[1].joinpath("índice.html").read_text(encoding="utf-8")

    def test_wifi_cards_show_band_channel_and_security(self):
        self.assertIn('const band=frequency>=5925&&frequency<=7125?"6 GHz"', self.html)
        self.assertIn('Canal "+Math.round((frequency-5000)/5)', self.html)
        self.assertIn('security.textContent=audit.security', self.html)

    def test_wifi_cards_are_sorted_by_signal_and_accessible(self):
        self.assertIn("const orderedNetworks=[...networks].sort", self.html)
        self.assertIn('signalTrack.setAttribute("aria-label","Señal "+audit.signal)', self.html)

    def test_mobile_cards_use_readable_font_sizes(self):
        self.assertIn(".wifi-meta{font-size:14px", self.html)
        self.assertIn(".wifi-network-head strong{font-size:16px", self.html)


if __name__ == "__main__":
    unittest.main()
