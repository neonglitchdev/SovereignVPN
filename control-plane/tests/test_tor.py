"""Prove di tor.torrc (H52, primo pezzo): uscita solo dal paese scelto, tutto solo su 127.0.0.1, niente SOCKS."""
import re, unittest

from sovereignctl import tor, uscite


class Torrc(unittest.TestCase):
    def test_uscita_solo_dal_paese_scelto(self):
        t = tor.torrc("DE")
        self.assertIn("ExitNodes {de}\n", t)
        self.assertIn("StrictNodes 1\n", t)

    def test_tutto_su_127_0_0_1_e_niente_socks(self):
        t = tor.torrc("NL")
        porte = re.findall(r"^(\w+Port) (\S+)$", t, re.M)
        self.assertEqual(dict(porte), {"SocksPort": "0", "TransPort": "127.0.0.1:9040", "DNSPort": "127.0.0.1:5353"})
        self.assertNotIn("ControlPort", t)  # il controllo solo da socket locale

    def test_paese_non_valido_rifiutato(self):
        for p in ("de", "DEU", "", None, "D1", "{de},{us}"):
            with self.subTest(p=p), self.assertRaises(uscite.UscitaNonValida):
                tor.torrc(p)


if __name__ == "__main__":
    unittest.main()
