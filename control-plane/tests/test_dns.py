"""Prove della configurazione di Unbound e della sua immagine (FR-DNS-003/004, cap. 6, ANC-0319). Il resolver vero,
DNSSEC positivo e negativo e i log vuoti, si prova sul runner (prova_dns_vero.sh).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import pathlib, re, unittest

from sovereignctl import dns
from test_preflight import esegui

DOCKERFILE = pathlib.Path(__file__).resolve().parents[2] / "ops/dns/unbound/Dockerfile"


def righe(**k):
    return [r.strip() for r in dns.unbound_conf(**k).splitlines()]


class Unbound(unittest.TestCase):
    def test_ricorsivo_dalle_radici_con_dnssec(self):
        r = righe()
        self.assertFalse(any(x.startswith(("forward-zone", "forward-addr", "stub-zone")) for x in r))
        for voce in ('trust-anchor-file: "/usr/share/dns/root.key"', "harden-dnssec-stripped: yes", "qname-minimisation: yes"):
            self.assertIn(voce, r)

    def test_nessuna_traccia_delle_query(self):
        r = righe()
        for voce in ("verbosity: 0", "log-queries: no", "log-replies: no", "log-servfail: no", "log-local-actions: no",
                     "use-syslog: no", 'logfile: ""', "statistics-interval: 0", "extended-statistics: no"):
            self.assertIn(voce, r)

    def test_solo_su_loopback(self):
        r = righe(porta=5399)
        self.assertEqual([x for x in r if x.startswith("interface:")], ["interface: 127.0.0.1@5399"])
        self.assertEqual([x for x in r if x.startswith("access-control:")],
                         ["access-control: 0.0.0.0/0 refuse", "access-control: 127.0.0.0/8 allow"])

    def test_il_comando_stampa_la_configurazione_e_rifiuta_le_porte_basse(self):
        codice, out, err = esegui(["dns", "plan"])
        self.assertEqual((codice, out), (0, dns.unbound_conf()), err)
        self.assertEqual(esegui(["dns", "plan", "--porta", "53"])[0], 2)

    def test_immagine_pin_nata_per_digest_e_solo_pacchetti_debian(self):
        testo = DOCKERFILE.read_text()
        basi = re.findall(r"^FROM\s+(\S+)", testo, flags=re.M)
        self.assertEqual(len(basi), 1)
        self.assertRegex(basi[0], r"^debian:[\w.-]+@sha256:[0-9a-f]{64}$")
        self.assertIn("apt-get install -y --no-install-recommends unbound dns-root-data", testo)


if __name__ == "__main__":
    unittest.main()
