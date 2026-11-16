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



class Regole(unittest.TestCase):
    def test_tcp_dei_peer_alla_transport_e_niente_inoltro(self):
        r = tor.regole("10.71.0.0/24")
        self.assertIn('iifname "wg0" ip saddr 10.71.0.0/24 ip daddr != 10.71.0.1 meta l4proto tcp redirect to :9040', r)
        self.assertIn('iifname "wg0" drop', r)  # niente inoltro dei peer: l'UDP non esce dalla WAN
        self.assertIn("priority filter - 2", r)

    def test_subnet_non_valida_rifiutata(self):
        with self.assertRaises(ValueError):
            tor.regole("10.71.0.0/33")


class Immagine(unittest.TestCase):
    def test_stessa_base_pin_nata_di_unbound_e_mai_root(self):
        import pathlib
        ops = pathlib.Path(__file__).resolve().parents[2] / "ops"
        tor_df = (ops / "tor/Dockerfile").read_text()
        base_unbound = re.search(r"^FROM (\S+)$", (ops / "dns/unbound/Dockerfile").read_text(), re.M).group(1)
        self.assertRegex(base_unbound, r"@sha256:[0-9a-f]{64}$")  # per digest, mai un tag mobile
        self.assertIn(f"FROM {base_unbound}\n", tor_df)
        self.assertIn("\nUSER debian-tor\n", tor_df)  # Tor non gira come root
        self.assertIn('CMD ["tor", "-f", "/etc/tor/torrc"]', tor_df)

    def test_unita_come_quelle_del_dns(self):
        import pathlib
        u = (pathlib.Path(__file__).resolve().parents[2] / "ops/systemd/sovereignvpn-tor.service").read_text()
        self.assertIn("docker run --rm --pull never --name sovereignvpn-tor ", u)  # mai un'immagine da Docker Hub
        self.assertIn("--cap-drop ALL --security-opt no-new-privileges", u)
        self.assertIn("-v /etc/sovereignvpn/tor/torrc:/etc/tor/torrc:ro ", u)
        self.assertIn("\nPartOf=docker.service\n", u)
        self.assertIn("\nWantedBy=multi-user.target docker.service\n", u)
        self.assertIn("\nConditionPathExists=/etc/sovereignvpn/tor/torrc\n", u)

if __name__ == "__main__":
    unittest.main()
