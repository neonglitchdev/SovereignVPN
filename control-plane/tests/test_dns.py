"""Prove della configurazione di Unbound e della sua immagine (FR-DNS-003/004, cap. 6, ANC-0319). Il resolver vero,
DNSSEC positivo e negativo e i log vuoti, si prova sul runner (prova_dns_vero.sh).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import json, pathlib, re, unittest

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


class PiHole(unittest.TestCase):
    def test_solo_su_wg0_solo_unbound_nessuna_traccia(self):
        e = dns.pihole_env("wg0")
        self.assertEqual((e["FTLCONF_dns_listeningMode"], e["FTLCONF_dns_interface"]), ("BIND", "wg0"))
        self.assertEqual(e["FTLCONF_dns_upstreams"], "127.0.0.1#5335")
        self.assertEqual((e["FTLCONF_dns_queryLogging"], e["FTLCONF_database_maxDBdays"], e["FTLCONF_misc_privacylevel"]),
                         ("false", "0", "3"))
        self.assertTrue(e["FTLCONF_webserver_port"].startswith("127.0.0.1:"))
        self.assertEqual(e["WEBPASSWORD_FILE"], "pihole_webpasswd")
        self.assertNotIn("FTLCONF_webserver_api_password", e)  # mai la password nell'ambiente
        self.assertEqual([e[k] for k in ("FTLCONF_ntp_ipv4_active", "FTLCONF_ntp_ipv6_active", "FTLCONF_ntp_sync_active")],
                         ["false"] * 3)  # nessun server NTP su 0.0.0.0:123, nessuna sincronizzazione verso fuori

    def test_immagine_pin_nata_per_digest(self):
        self.assertRegex(dns.IMMAGINE_PIHOLE, r"^pihole/pihole:\d{4}\.\d{2}\.\d+@sha256:[0-9a-f]{64}$")

    def test_comando_e_interfaccia_validata(self):
        codice, out, err = esegui(["dns", "plan", "--servizio", "pihole", "--interfaccia", "wgdns0", "--json"])
        self.assertEqual(codice, 0, err)
        self.assertEqual(json.loads(out)["ambiente"]["FTLCONF_dns_interface"], "wgdns0")
        self.assertEqual(esegui(["dns", "plan", "--servizio", "pihole", "--interfaccia", "wg0;ip"])[0], 2)


class AvvioDns(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._t = tempfile.TemporaryDirectory(); self.cartella = pathlib.Path(self._t.name) / "dns"

    def tearDown(self):
        self._t.cleanup()

    def test_file_coi_permessi_e_password_generata_una_volta_sola_mai_stampata(self):
        import stat
        codice, out, err = esegui(["dns", "apply", "--cartella", str(self.cartella), "--json"])
        self.assertEqual(codice, 0, err)
        self.assertTrue(json.loads(out)["password_generata"])
        modi = {f.name: stat.S_IMODE(f.stat().st_mode) for f in self.cartella.iterdir()}
        self.assertEqual(modi, {"unbound.conf": 0o644, "pihole.env": 0o600, "pihole-web.secret": 0o600})
        self.assertEqual(stat.S_IMODE(self.cartella.stat().st_mode), 0o700)
        self.assertEqual((self.cartella / "unbound.conf").read_text(), dns.unbound_conf())
        self.assertEqual((self.cartella / "pihole.env").read_text(), "".join(f"{k}={v}\n" for k, v in dns.pihole_env().items()))
        segreto = (self.cartella / "pihole-web.secret").read_text().strip()
        self.assertGreaterEqual(len(segreto), 24)
        self.assertNotIn(segreto, out + err)
        codice, out, _ = esegui(["dns", "apply", "--cartella", str(self.cartella), "--json"])
        self.assertEqual((codice, json.loads(out)["password_generata"]), (0, False))
        self.assertEqual((self.cartella / "pihole-web.secret").read_text().strip(), segreto)

    def test_interfaccia_validata(self):
        self.assertEqual(esegui(["dns", "apply", "--cartella", str(self.cartella), "--interfaccia", "wg0 ; x"])[0], 2)
        self.assertFalse(self.cartella.exists())

    def test_unita_coerenti_col_codice_e_con_l_installer(self):
        ops = pathlib.Path(__file__).resolve().parents[2] / "ops"
        pihole = (ops / "systemd/sovereignvpn-pihole.service").read_text()
        unbound = (ops / "systemd/sovereignvpn-unbound.service").read_text()
        self.assertIn(dns.IMMAGINE_PIHOLE, pihole)
        for f in ("pihole.env", "pihole-web.secret"):
            self.assertIn(f"{dns.CARTELLA_DNS}/{f}", pihole)
        self.assertIn(f"{dns.CARTELLA_DNS}/unbound.conf:/etc/unbound/unbound.conf:ro", unbound)
        self.assertIn("After=docker.service sovereignvpn-unbound.service sovereignvpn-reconcile.service", pihole)
        etichetta = re.search(r"(sovereignvpn-unbound:[\w.]+)", unbound).group(1)
        self.assertIn(f"docker build -q -t {etichetta} ", (ops / "install.sh").read_text())


if __name__ == "__main__":
    unittest.main()
