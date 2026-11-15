"""Prove di `sovereignctl status` (ANC-0254, NFR-AVL-002) con ip, wg, nft, sysctl e systemctl sostituiti.
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, contextlib, hashlib, json, os, pathlib, sqlite3, tempfile, unittest
from unittest import mock

from sovereignctl import VERSIONE, configurazione, firewall, peer, stato
from test_configurazione import ESEMPIO
from test_preflight import esegui

PUB = base64.b64encode(b"p" * 32).decode()
PRIVATA = base64.b64encode(b"s" * 32).decode()
SS_PULITO = ('udp UNCONN 0 0 127.0.0.1:5335 0.0.0.0:* users:(("unbound",pid=10,fd=3))\n'
             'udp UNCONN 0 0 10.66.0.1:53 0.0.0.0:* users:(("pihole-FTL",pid=20,fd=4))\n'
             'tcp LISTEN 0 128 127.0.0.1:8081 0.0.0.0:* users:(("pihole-FTL",pid=20,fd=6))\n'
             'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n')


class Status(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); t = pathlib.Path(self._t.name)
        self.chiave, self.manifest, self.db = t / "wg-server.key", t / "manifest.json", str(t / "registro.sqlite3")
        self.chiave.write_text(PRIVATA + "\n"); self.chiave.chmod(0o600)
        self.manifest.write_text(json.dumps({"sovereignvpn": VERSIONE, "id_installazione": "1b7ed7d3-cea5-4e7e-a687-144f2355a190"}))
        a = peer.Archivio(self.db)
        self.attivi = []
        for nome in ("uno", "due", "tre"):
            p = a.aggiungi(nome, base64.b64encode(os.urandom(32)).decode(), "10.66.0.0/24")
            self.attivi.append((p["chiave_pubblica"], stato.runtime.ammessi(p["indirizzo"], configurazione.SUBNET6)))
        a.db.execute("UPDATE peer SET stato = 'ACTIVE', saga = 'APPLIED'")
        a.db.execute("UPDATE peer SET stato = 'REVOKED' WHERE nome = 'tre'")
        a.db.close()
        self.revocato = self.attivi.pop()
        self.vivi = dict(self.attivi)
        self.risposte = {("ip", "-j", "link", "show", "wg0"): (0, '[{"ifname": "wg0", "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]}]'),
                         ("wg", "show", "wg0", "listen-port"): (0, "51820\n"),
                         ("wg", "show", "wg0", "public-key"): (0, PUB + "\n"),
                         ("wg", "pubkey"): (0, PUB + "\n"),
                         ("systemctl", "is-enabled", *stato.UNITA): (0, "enabled\nenabled\n")}
        self.tabella = {"tabella": "inet sovereignvpn", "catene": {"input": "drop", "forward": "drop", "postrouting": "accept"},
                        "regole": 17, "verificato": True}
        self.patch = [mock.patch.object(stato.bootstrap, "MANIFEST", str(self.manifest)),
                      mock.patch.object(stato.runtime, "CHIAVE_SERVER", str(self.chiave)),
                      mock.patch.object(stato, "_leggi", self.leggi),
                      mock.patch.object(stato.runtime, "leggi_runtime", lambda i: dict(self.vivi)),
                      mock.patch.object(stato.firewall, "leggi", lambda: dict(self.tabella)),
                      mock.patch.object(stato.host, "leggi", lambda: dict(stato.host.VALORI))]
        for p in self.patch:
            p.start()

    def tearDown(self):
        for p in self.patch:
            p.stop()
        self._t.cleanup()

    def leggi(self, *argomenti, ingresso=None):
        if argomenti == ("wg", "pubkey"):
            self.assertEqual(ingresso, PRIVATA)  # la chiave passa solo da stdin
        return self.risposte.get(argomenti, (1, ""))

    def status(self, config=ESEMPIO):
        codice, out, err = esegui(["status", "--config", str(config), "--db", self.db, "--json"])
        return codice, (json.loads(out) if out else None), out + err

    def esiti(self, r):
        return {c["nome"]: c["esito"] for c in r["controlli"]}

    def test_tutto_ok_sette_controlli_e_nessun_segreto(self):
        codice, r, testo = self.status()
        self.assertEqual(codice, 0, testo)
        self.assertEqual((r["superati"], r["controlli_eseguiti"]), (7, 7))
        self.assertEqual(list(self.esiti(r)), ["release", "chiave del server", "wg0", "peer", "firewall", "sysctl", "avvio"])
        self.assertIn("DNS", r["non_consegnati"][0])
        for segreto in [PRIVATA, PUB, *self.vivi, *self.vivi.values(), self.revocato[0], "uno", "due", "tre"]:
            self.assertNotIn(segreto, testo)

    def test_firewall_assente_e_guasto(self):
        with mock.patch.object(stato.firewall, "leggi", side_effect=RuntimeError("tabella sovereignvpn non leggibile")):
            codice, r, _ = self.status()
        self.assertEqual(codice, 1)
        self.assertEqual([n for n, e in self.esiti(r).items() if e != "OK"], ["firewall"])

    def test_una_regola_tolta_a_mano_si_vede(self):
        cfg = configurazione.leggi(ESEMPIO)
        dichiarate = firewall.regole_dichiarate(firewall.componi(cfg["subnet"], "wg0", cfg["wg_port"], "ens3", cfg["admin_port"],
                                                                cfg["ssh_port"], cfg["admin_ssh_sources"]))
        config = pathlib.Path(self._t.name) / "server.toml"
        config.write_text('wan_interface = "ens3"\n' + ESEMPIO.read_text())
        self.tabella["regole"] = dichiarate
        self.assertEqual(self.status(config)[0], 0)
        self.tabella["regole"] = dichiarate - 1
        codice, r, _ = self.status(config)
        self.assertEqual(codice, 1)
        self.assertEqual(self.esiti(r)["firewall"], "GUASTO")
        self.assertIn(f"{dichiarate - 1} regole su {dichiarate} dichiarate", json.dumps(r))

    def test_registro_illeggibile_guasto_senza_crash(self):
        """[H41] Col registro corrotto lo status dice GUASTO peer e firewall, non cade con un traceback."""
        config = pathlib.Path(self._t.name) / "server.toml"
        config.write_text('wan_interface = "ens3"\n' + ESEMPIO.read_text())
        pathlib.Path(self.db).write_bytes(os.urandom(4096))
        codice, r, _ = self.status(config)
        self.assertEqual(codice, 1)
        self.assertEqual((self.esiti(r)["peer"], self.esiti(r)["firewall"]), ("GUASTO", "GUASTO"))

    def test_peer_revocato_ancora_nel_runtime(self):
        self.vivi[self.revocato[0]] = self.revocato[1]
        codice, r, _ = self.status()
        self.assertEqual(codice, 1)
        self.assertEqual([n for n, e in self.esiti(r).items() if e != "OK"], ["peer"])

    def test_porta_diversa_dalla_configurazione(self):
        self.risposte[("wg", "show", "wg0", "listen-port")] = (0, "51821\n")
        codice, r, _ = self.status()
        self.assertEqual((codice, self.esiti(r)["wg0"]), (1, "GUASTO"))

    def test_unita_non_abilitate(self):
        self.risposte[("systemctl", "is-enabled", *stato.UNITA)] = (1, "enabled\ndisabled\n")
        codice, r, _ = self.status()
        self.assertEqual((codice, self.esiti(r)["avvio"]), (1, "GUASTO"))

    def test_chiave_leggibile_da_altri_esce_con_3(self):
        self.chiave.chmod(0o644)
        self.assertEqual(self.status()[0], 3)

    def test_col_dns_applicato_contano_unbound_e_pihole(self):
        (pathlib.Path(self._t.name) / "dns").mkdir()
        (pathlib.Path(self._t.name) / "dns/unbound.conf").write_text("server:\n")
        risposte = {("127.0.0.1", 5335): True, ("10.66.0.1", 53): True}
        self.risposte[("ss", "-H", "-lntup")] = (0, SS_PULITO + 'udp UNCONN 0 0 [fdd3:5205:9303::a42:1]:53 [::]:* users:(("pihole-FTL",pid=20,fd=7))\n')  # [H38] BIND anche sull'ULA di wg0
        with mock.patch.object(stato.dns, "CARTELLA_DNS", str(pathlib.Path(self._t.name) / "dns")), \
                mock.patch.object(stato, "_dns_risponde", lambda i, p: risposte[(i, p)]):
            codice, r, testo = self.status()
            self.assertEqual((codice, r["superati"], r["controlli_eseguiti"], r["non_consegnati"]), (0, 10, 10, []), testo)
            risposte[("10.66.0.1", 53)] = False
            codice, r, _ = self.status()
            self.assertEqual(codice, 1)
            self.assertEqual([n for n, e in self.esiti(r).items() if e != "OK"], ["pihole"])
            risposte[("10.66.0.1", 53)] = True
            self.risposte[("ss", "-H", "-lntup")] = (0, SS_PULITO + 'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("pihole-FTL",pid=20,fd=9))\n')
            codice, r, _ = self.status()
        self.assertEqual(codice, 1)
        self.assertEqual([n for n, e in self.esiti(r).items() if e != "OK"], ["porte"])
        self.assertIn("pihole-FTL 0.0.0.0:53", json.dumps(r))

    def test_pihole_sull_ula_del_server_e_dichiarato_su_un_altra_no(self):
        """[H38] BIND apre la 53 su ogni indirizzo di wg0, anche sull'ULA del server: dichiarato. Un'altra ULA no."""
        altra = 'udp UNCONN 0 0 [fdd3:5205:9303::a42:9]:53 [::]:* users:(("pihole-FTL",pid=20,fd=8))\n'
        self.risposte[("ss", "-H", "-lntup")] = (0, SS_PULITO + 'udp UNCONN 0 0 [fdd3:5205:9303::a42:1]:53 [::]:* users:(("pihole-FTL",pid=20,fd=7))\n')
        self.assertEqual(stato.porte_fuori_inventario("10.66.0.1", "fdd3:5205:9303::a42:1"), [])
        self.risposte[("ss", "-H", "-lntup")] = (0, SS_PULITO + 'udp UNCONN 0 0 [fdd3:5205:9303::a42:1]:53 [::]:* users:(("pihole-FTL",pid=20,fd=7))\n' + altra)
        self.assertEqual(stato.porte_fuori_inventario("10.66.0.1", "fdd3:5205:9303::a42:1"), ["pihole-FTL [fdd3:5205:9303::a42:9]:53"])

    def test_solo_letture(self):
        prima = hashlib.sha256(pathlib.Path(self.db).read_bytes()).hexdigest()
        self.status()
        self.assertEqual(hashlib.sha256(pathlib.Path(self.db).read_bytes()).hexdigest(), prima)
        assente = os.path.join(self._t.name, "nessuno.sqlite3")
        codice, out, _ = esegui(["status", "--config", str(ESEMPIO), "--db", assente, "--json"])
        self.assertEqual(codice, 1)
        self.assertEqual({c["nome"]: c["esito"] for c in json.loads(out)["controlli"]}["peer"], "GUASTO")
        self.assertFalse(os.path.exists(assente))



class Permessi(unittest.TestCase):
    """ANC-0255: da utente normale status cadeva con un traceback (server.toml e wg-server.key sono 0600 di root, visto
    sulla VM il 15/11): un permesso negato e' un errore di sistema, codice 1, col file e il rimedio, mai un traceback."""
    def test_permesso_negato_e_un_messaggio_non_un_traceback(self):
        for bersaglio, file in ((configurazione, "/etc/sovereignvpn/server.toml"), (stato, "/etc/sovereignvpn/wg-server.key")):
            errore = PermissionError(13, "Permission denied", file)
            with self.subTest(file=file), (mock.patch.object(configurazione, "leggi", side_effect=errore) if bersaglio is configurazione
                                           else mock.patch.object(stato, "controlla", side_effect=errore)):
                with mock.patch.object(configurazione, "leggi", return_value={}) if bersaglio is stato else contextlib.nullcontext():
                    codice, out, err = esegui(["status", "--config", "/etc/sovereignvpn/server.toml"])
                self.assertEqual(codice, 1)
                self.assertIn(file, err); self.assertIn("serve root", err); self.assertNotIn("Traceback", err + out)


class DomandaDns(unittest.TestCase):
    """La domanda vera di status, contro un server UDP finto: risposta buona si', SERVFAIL no, nessun server no."""
    def server(self, rcode):
        import socket, threading
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); porta = s.getsockname()[1]
        def rispondi():
            d, a = s.recvfrom(512); s.sendto(d[:2] + bytes([0x81, 0x80 | rcode]) + d[4:], a); s.close()
        threading.Thread(target=rispondi, daemon=True).start()
        return porta

    def test_solo_una_risposta_buona_vale(self):
        self.assertTrue(stato._dns_risponde("127.0.0.1", self.server(0)))
        self.assertFalse(stato._dns_risponde("127.0.0.1", self.server(2)))  # SERVFAIL
        self.assertFalse(stato._dns_risponde("127.0.0.1", 9, attesa=0.5))  # nessuno ascolta

if __name__ == "__main__":
    unittest.main()
