"""Prove di `sovereignctl audit run` (ANC-0307, ANC-0398; T-016, T-030) [H42], con i comandi dell'host sostituiti come
in test_stato. Uso, da control-plane/: python3 -m unittest discover -s tests"""
import json, os, pathlib, sqlite3, unittest
from unittest import mock

from sovereignctl import audit, dns, stato
from test_configurazione import ESEMPIO
from test_preflight import esegui
import test_stato  # il modulo, non la classe: importata, unittest ne rifarebbe girare le prove
from test_stato import PRIVATA, SS_PULITO

TABELLA = ('table inet sovereignvpn {\n chain prerouting {\n  iifname "wg0" reject with icmpv6 admin-prohibited\n }\n'
           ' chain forward {\n  iifname "wg0" oifname "wg0" drop\n  iifname "wg0" meta l4proto { tcp, udp } th dport 53 drop\n'
           '  iifname "wg0" tcp dport 853 reject with tcp reset\n }\n}\n')
ULA = 'udp UNCONN 0 0 [fdd3:5205:9303::a42:1]:53 [::]:* users:(("pihole-FTL",pid=20,fd=7))\n'


class Audit(unittest.TestCase):
    """Un host installato e in ordine (lo stesso di test_stato, piu' il DNS applicato): poi un guasto alla volta."""
    leggi, status, esiti = test_stato.Status.leggi, test_stato.Status.status, test_stato.Status.esiti

    def setUp(self):
        test_stato.Status.setUp(self)
        t = pathlib.Path(self._t.name)
        self.etc, self.var, self.cartella_dns = t / "etc", t / "var", t / "dns"
        for d in (self.etc, self.var, self.var / "export", self.var / "backup", self.cartella_dns):
            d.mkdir(mode=0o700)
        (self.etc / "server.toml").write_text("x"); (self.etc / "server.toml").chmod(0o600)
        (self.var / "export/uno.conf").write_text("x"); (self.var / "export/uno.conf").chmod(0o600)
        (self.cartella_dns / "unbound.conf").write_text(dns.unbound_conf())
        (self.cartella_dns / "pihole.env").write_text("".join(f"{k}={v}\n" for k, v in dns.pihole_env().items()))
        self.manifest.write_text(json.dumps({"sovereignvpn": "14.0.0", "id_installazione": "1b7ed7d3-cea5-4e7e-a687-144f2355a190",
                                             "immagini": [{"nome": "pihole/pihole", "digest": "sha256:" + "a" * 64}]}))
        self.risposte.update({("nft", "list", "table", "inet", "sovereignvpn"): (0, TABELLA),
                              ("ss", "-H", "-lnt"): (0, "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8081 0.0.0.0:*\n"),
                              ("ss", "-H", "-lntup"): (0, SS_PULITO + ULA),
                              ("ip", "-j", "addr", "show", "dev", "wg0"): (0, json.dumps([{"addr_info": [{"family": "inet", "local": "10.66.0.1"},
                                                                                                         {"family": "inet6", "local": "fdd3:5205:9303::a42:1"}]}])),
                              ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"): (0, "sovereignvpn-unbound\t\nsovereignvpn-pihole\t\n")})
        self.altre = [mock.patch.object(audit, "ETC", str(self.etc)), mock.patch.object(audit, "VAR", str(self.var)),
                      mock.patch.object(audit.profilo, "CARTELLA", str(self.var / "export")),
                      mock.patch.object(audit.backup, "CARTELLA", str(self.var / "backup")),
                      mock.patch.object(stato.dns, "CARTELLA_DNS", str(self.cartella_dns)),
                      mock.patch.object(stato, "_dns_risponde", lambda i, p: True)]
        for p in self.altre:
            p.start()
        self.tabella["regole"] = None

    def tearDown(self):
        for p in self.altre:
            p.stop()
        test_stato.Status.tearDown(self)

    def audit(self, config=ESEMPIO):
        codice, out, err = esegui(["audit", "run", "--config", str(config), "--db", self.db, "--json"])
        return codice, (json.loads(out) if out else None), out + err

    def stati(self, r):
        return {x["id"]: x["stato"] for x in r["controlli"]}

    def test_host_in_ordine_nessun_fail_e_forma_di_ANC_0307(self):
        codice, r, testo = self.audit()
        self.assertEqual(codice, 0, testo)
        self.assertGreaterEqual(r["controlli_eseguiti"], 24)  # T-030
        ids = [x["id"] for x in r["controlli"]]
        self.assertEqual(ids, [f"AUD-{n:02d}" for n in range(1, len(ids) + 1)])  # stabili e in ordine
        for x in r["controlli"]:
            self.assertEqual(set(x), {"id", "severita", "requisito", "nome", "stato", "evidenza", "rimedio", "timestamp"})
            self.assertIn(x["stato"], audit.STATI)
            if x["stato"] == "FAIL":
                self.assertTrue(x["rimedio"], x["id"])
        self.assertEqual(r["FAIL"], 0, [x for x in r["controlli"] if x["stato"] == "FAIL"])
        self.assertEqual([self.stati(r)[f"AUD-{n}"] for n in (25, 26, 27, 28)], ["SKIPPED"] * 4)  # opzionali spenti
        self.assertEqual(self.stati(r)["AUD-23"], "WARN")  # niente backup_recipient nell'esempio: avviso, non guasto
        self.assertEqual(r["PASS"] + r["WARN"] + r["FAIL"] + r["SKIPPED"], r["controlli_eseguiti"])
        self.assertNotIn(PRIVATA, testo)

    def test_T016_porta_dns_esposta_fail_p0_codice_3(self):
        self.risposte[("ss", "-H", "-lntup")] = (0, SS_PULITO + ULA + 'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("pihole-FTL",pid=20,fd=9))\n')
        codice, r, _ = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-10"]), (3, "FAIL"))

    def test_firewall_in_recupero_fail(self):
        self.risposte[("nft", "list", "table", "inet", "sovereignvpn")] = (0, TABELLA.replace(" chain forward {\n", ' chain forward {\n  iifname "wg0" drop\n'))
        codice, r, _ = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-17"]), (3, "FAIL"))

    def test_tabella_illeggibile_recupero_non_verificabile(self):
        self.risposte[("nft", "list", "table", "inet", "sovereignvpn")] = (1, "")
        codice, r, _ = self.audit()
        self.assertEqual([self.stati(r)[i] for i in ("AUD-13", "AUD-14", "AUD-15", "AUD-17")], ["FAIL", "FAIL", "FAIL", "SKIPPED"])
        self.assertEqual(codice, 3)

    def test_amministrazione_solo_loopback_e_vpn(self):
        self.risposte[("ss", "-H", "-lnt")] = (0, "LISTEN 0 128 127.0.0.1:8443 0.0.0.0:*\nLISTEN 0 128 10.66.0.1:8443 0.0.0.0:*\n")
        self.assertEqual(self.stati(self.audit()[1])["AUD-19"], "PASS")
        self.risposte[("ss", "-H", "-lnt")] = (0, "LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*\n")
        codice, r, _ = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-19"]), (3, "FAIL"))

    def test_peer_scaduto_ancora_attivo(self):
        db = sqlite3.connect(self.db); db.execute("UPDATE peer SET scade = '2000-01-01T00:00:00Z' WHERE nome = 'uno'"); db.commit(); db.close()
        codice, r, testo = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-20"]), (3, "FAIL"))
        self.assertIn("1 peer col TTL passato", testo)
        self.assertNotIn("uno", [x["evidenza"] for x in r["controlli"] if x["id"] == "AUD-20"][0])  # conteggi, mai nomi

    def test_file_leggibile_da_altri_fail_il_manifest_no(self):
        (self.var / "manifest.json").write_text("{}"); (self.var / "manifest.json").chmod(0o644)
        self.assertEqual(self.stati(self.audit()[1])["AUD-11"], "PASS")
        (self.etc / "server.toml").chmod(0o644)
        codice, r, _ = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-11"]), (3, "FAIL"))

    def test_ssh_aperto_a_tutti_e_un_avviso(self):
        config = pathlib.Path(self._t.name) / "largo.toml"
        config.write_text(ESEMPIO.read_text().replace('admin_ssh_sources = ["198.51.100.0/24"]', 'admin_ssh_sources = ["0.0.0.0/0"]'))
        codice, r, _ = self.audit(config)
        self.assertEqual((codice, self.stati(r)["AUD-12"]), (0, "WARN"))

    def test_solo_un_fail_p1_esce_con_1(self):
        self.risposte[("systemctl", "is-enabled", *stato.UNITA)] = (1, "disabled\ndisabled\n")
        codice, r, _ = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-07"]), (1, "FAIL"))

    def test_dns_non_applicato_skipped_che_non_vale_pass(self):
        completo = self.audit()[1]
        for f in ("unbound.conf", "pihole.env"):
            (self.cartella_dns / f).unlink()
        codice, r, _ = self.audit()
        self.assertEqual(codice, 0)
        dns_ids = ("AUD-08", "AUD-09", "AUD-10", "AUD-30", "AUD-31")
        self.assertEqual([self.stati(r)[i] for i in dns_ids], ["SKIPPED"] * 5)
        self.assertEqual([self.stati(completo)[i] for i in dns_ids], ["PASS"] * 5)
        self.assertEqual((completo["PASS"] - r["PASS"], r["SKIPPED"] - completo["SKIPPED"]), (5, 5))  # SKIPPED non vale PASS

    def test_registro_corrotto_fail_senza_crash(self):
        pathlib.Path(self.db).write_bytes(os.urandom(4096))
        codice, r, _ = self.audit()
        self.assertEqual(codice, 3)
        self.assertEqual([self.stati(r)[i] for i in ("AUD-04", "AUD-20", "AUD-21")], ["FAIL", "SKIPPED", "FAIL"])

    def test_log_di_pihole_acceso_fail(self):
        p = self.cartella_dns / "pihole.env"
        p.write_text(p.read_text().replace("FTLCONF_dns_queryLogging=false", "FTLCONF_dns_queryLogging=true"))
        codice, r, _ = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-30"]), (3, "FAIL"))

    def test_nft_assente_fail_senza_crash(self):
        with mock.patch.object(stato.firewall, "leggi", side_effect=FileNotFoundError(2, "No such file or directory", "nft")):
            codice, r, _ = self.audit()
        self.assertEqual((codice, self.stati(r)["AUD-05"]), (3, "FAIL"))

    def test_riproducibile(self):
        a, b = self.audit()[1], self.audit()[1]
        senza_ora = lambda r: [{k: v for k, v in x.items() if k != "timestamp"} for x in r["controlli"]]
        self.assertEqual(senza_ora(a), senza_ora(b))


class Vincoli(unittest.TestCase):
    """[H44] I vincoli dei container letti da docker inspect, contro quelli dichiarati in dns."""
    CONFORME = {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": ["CAP_SETUID", "CAP_SETGID"], "SecurityOpt": ["no-new-privileges"]}

    PIHOLE = {"ReadonlyRootfs": False, "CapDrop": ["ALL"], "SecurityOpt": None,
              "CapAdd": ["CAP_CHOWN", "CAP_SETUID", "CAP_SETGID", "CAP_NET_BIND_SERVICE", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETFCAP"]}

    def ispeziona(self, hc, pihole=None):
        """hc per Unbound (e per ogni nome, se pihole e' None), pihole per sovereignvpn-pihole."""
        def leggi(*a, **k):
            scelto = pihole if pihole is not None and a[-1] == "sovereignvpn-pihole" else hc
            return (0, json.dumps(scelto)) if scelto is not None else (1, "")
        return mock.patch.object(stato, "_leggi", leggi)

    def test_conforme_senza_vincoli_e_con_una_capability_in_piu(self):
        with self.ispeziona(self.CONFORME):
            self.assertEqual(audit.vincoli_mancanti("sovereignvpn-unbound", dns.VINCOLI_UNBOUND), [])
        with self.ispeziona({"ReadonlyRootfs": False, "CapDrop": None, "CapAdd": None, "SecurityOpt": None}):
            self.assertEqual(audit.vincoli_mancanti("x", dns.VINCOLI_UNBOUND), ["read-only", "cap-drop ALL", "security-opt no-new-privileges"])
        with self.ispeziona({**self.CONFORME, "CapAdd": ["CAP_SETUID", "CAP_SETGID", "CAP_NET_ADMIN"]}):
            self.assertEqual(audit.vincoli_mancanti("x", dns.VINCOLI_UNBOUND), ["cap-add NET_ADMIN in piu'"])
        with self.ispeziona(None):
            self.assertIsNone(audit.vincoli_mancanti("x", dns.VINCOLI_UNBOUND))

    def test_il_controllo_dell_audit(self):
        with self.ispeziona(self.CONFORME, self.PIHOLE):
            self.assertEqual(audit._vincoli()[0], "PASS")
        with self.ispeziona(self.CONFORME, {**self.PIHOLE, "CapAdd": self.PIHOLE["CapAdd"] + ["CAP_NET_RAW"]}):
            self.assertIn("sovereignvpn-pihole: cap-add NET_RAW in piu'", audit._vincoli()[1])
        with self.ispeziona(self.CONFORME, {**self.PIHOLE, "CapDrop": None}):
            self.assertIn("sovereignvpn-pihole: cap-drop ALL", audit._vincoli()[1])
        with self.ispeziona({**self.CONFORME, "ReadonlyRootfs": False}, self.PIHOLE):
            stato_, evidenza, rimedio = audit._vincoli()
            self.assertEqual(stato_, "FAIL"); self.assertIn("read-only", evidenza); self.assertTrue(rimedio)
        with self.ispeziona(None):
            self.assertEqual(audit._vincoli()[0], "SKIPPED")


class CodiceDiUscita(unittest.TestCase):
    def test_tabella(self):
        c = lambda *coppie: [{"stato": s, "severita": v} for s, v in coppie]
        self.assertEqual(audit.codice_di_uscita(c(("PASS", "P0"), ("WARN", "P0"), ("SKIPPED", "P0"))), 0)
        self.assertEqual(audit.codice_di_uscita(c(("PASS", "P0"), ("FAIL", "P1"))), 1)
        self.assertEqual(audit.codice_di_uscita(c(("FAIL", "P1"), ("FAIL", "P0"))), 3)
        self.assertEqual(audit.codice_di_uscita([]), 0)


if __name__ == "__main__":
    unittest.main()
