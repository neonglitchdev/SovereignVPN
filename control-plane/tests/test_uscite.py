"""Prove delle uscite per paese (FR-NET-008) [H48]: file del provider letti e rifiutati, pool su disco, scelta,
rotazione e failover, ordine dei comandi sull'host (kill switch per primo), CLI senza chiavi a schermo."""
import base64, contextlib, fcntl, io, json, os, pathlib, stat, tempfile, unittest
from unittest import mock

from sovereignctl import __main__ as cli, firewall, profilo, uscite

BUONA = """[Interface]
PrivateKey = cHJpdmF0YXByaXZhdGFwcml2YXRhcHJpdmF0YXByaXY=  # gitleaks:allow (chiave finta della prova, T-025)
Address = 10.64.12.7/32, fc00:bbbb::7/128
DNS = 10.64.0.1
[Peer]
PublicKey = cHViYmxpY2FwdWJibGljYXB1YmJsaWNhcHViYmxpY2E=
Endpoint = 185.1.2.3:51820
AllowedIPs = 0.0.0.0/0, ::/0
"""
PRIVATA = "cHJpdmF0YXByaXZhdGFwcml2YXRhcHJpdmF0YXByaXY="
ESEMPIO = str(pathlib.Path(__file__).resolve().parents[2] / "config" / "examples" / "server.toml")  # subnet 10.66.0.0/24


def altra(n):
    """Un'altra uscita valida: chiave pubblica ed endpoint diversi."""
    return BUONA.replace("185.1.2.3", f"185.1.2.{10 + n}").replace("cHViYmxpY2Fw", f"cHViYmxpY{n}Fw")


class Federazione(unittest.TestCase):
    """[H50] Un altro server SovereignVPN come uscita: il profilo di un suo dispositivo e' gia' un file d'uscita."""
    CHIAVE_A = "c2VydmVyYXNlcnZlcmFzZXJ2ZXJhc2VydmVyYXNlcnY="
    PUB_B = base64.b64encode(b"chiave-pubblica-del-server-b-32b").decode()

    def profilo_di_a(self, subnet_a, privata=PRIVATA):
        cfg_a = {"endpoint": "203.0.113.10", "subnet": subnet_a, "subnet6": "fdd3:5205:9303::/64"}
        p = {"id": "nodo-b", "nome": "Nodo B", "indirizzo": str(next(__import__("ipaddress").ip_network(subnet_a).hosts()) + 6),
             "rotte": None, "scade": None}
        testo = profilo.componi(p, cfg_a, self.CHIAVE_A)
        return testo.replace(profilo.SEGNAPOSTO, privata) if privata else testo

    def finto_wg(self, chiamate):
        def wg(*a, ingresso=None, tollera=False):
            chiamate.append(a[:2])
            return 0, (PRIVATA if a[1] == "genkey" else self.PUB_B) + "\n"
        return wg

    def test_exit_key_nasce_una_volta_0600(self):
        c, chiamate = os.path.join(tempfile.mkdtemp(), "uscite"), []
        with mock.patch.object(uscite, "_cmd", self.finto_wg(chiamate)):
            self.assertEqual(uscite.chiave_uscita(c), self.PUB_B)
            self.assertEqual(uscite.chiave_uscita(c), self.PUB_B)
        self.assertEqual(chiamate, [("wg", "genkey"), ("wg", "pubkey"), ("wg", "pubkey")])  # una sola genkey
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(c, uscite.CHIAVE_USCITA)).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(c).st_mode), 0o700)

    def test_profilo_col_segnaposto_prende_la_chiave_del_server(self):
        c = os.path.join(tempfile.mkdtemp(), "uscite")
        with mock.patch.object(uscite, "_cmd", self.finto_wg([])):
            uscite.chiave_uscita(c)
        s = uscite.importa(self.profilo_di_a("10.77.0.0/24", privata=None), "DE", cartella=c, subnet="10.66.0.0/24")
        salvato = pathlib.Path(c, s["id"] + ".conf").read_text()
        self.assertIn(f"PrivateKey = {PRIVATA}", salvato)
        self.assertNotIn(f"PrivateKey = {profilo.SEGNAPOSTO}", salvato)

    def test_segnaposto_senza_chiave_del_server_rifiutato(self):
        c = tempfile.mkdtemp()
        with self.assertRaises(uscite.UscitaNonValida) as e:
            uscite.importa(self.profilo_di_a("10.77.0.0/24", privata=None), "DE", cartella=c, subnet="10.66.0.0/24")
        self.assertIn("exit key", str(e.exception))
        self.assertEqual(uscite.pool(c), [])

    def test_exit_key_dalla_cli_stampa_la_pubblica_e_mai_la_privata(self):
        c, out = os.path.join(tempfile.mkdtemp(), "uscite"), io.StringIO()
        with mock.patch.object(uscite, "_cmd", self.finto_wg([])), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["exit", "key", "--cartella", c, "--config", ESEMPIO, "--json"]), 0)
        self.assertEqual(json.loads(out.getvalue()), {"chiave_pubblica": self.PUB_B})
        self.assertNotIn(PRIVATA, out.getvalue())

    def test_il_profilo_di_un_altro_server_e_un_uscita(self):
        c = tempfile.mkdtemp()
        s = uscite.importa(self.profilo_di_a("10.77.0.0/24"), "DE", cartella=c, subnet="10.66.0.0/24")
        self.assertEqual((s["endpoint"], s["indirizzi"], s["chiave_pubblica"]), ("203.0.113.10:51820", ["10.77.0.7/32"], self.CHIAVE_A))

    def test_stessa_rete_dei_peer_rifiutata(self):
        c = tempfile.mkdtemp()
        with self.assertRaises(uscite.UscitaNonValida) as e:
            uscite.importa(self.profilo_di_a("10.66.0.0/24"), "DE", cartella=c, subnet="10.66.0.0/24")
        self.assertIn("stessa rete", str(e.exception))
        self.assertEqual(uscite.pool(c), [])  # niente nel pool, niente file
        self.assertEqual([x for x in os.listdir(c) if x.endswith(".conf")], [])
        with self.assertRaises(uscite.UscitaNonValida):  # anche una rete piu' larga che la contiene
            uscite.importa(BUONA.replace("10.64.12.7/32", "10.0.0.2/8"), "DE", cartella=c, subnet="10.66.0.0/24")


class Pool(unittest.TestCase):
    def test_uscita_buona_con_la_bandierina(self):
        u = uscite.leggi(BUONA, "DE")
        self.assertEqual((u["paese"], u["bandierina"], u["endpoint"]), ("DE", "\U0001F1E9\U0001F1EA", "185.1.2.3:51820"))
        self.assertEqual(u["indirizzi"], ["10.64.12.7/32"])  # l'IPv6 dei peer e' bloccato: wgx0 solo IPv4
        self.assertNotIn("PrivateKey", repr(u))  # la chiave privata non esce dal file

    def test_chiavi_non_valide_rifiutate_senza_ripeterle(self):
        pubblica = "cHViYmxpY2FwdWJibGljYXB1YmJsaWNhcHViYmxpY2E="
        for vecchio, nuovo in ((PRIVATA, "cortissima"), (pubblica, "cHViYmxpY2E="), (PRIVATA, profilo.SEGNAPOSTO),
                               (pubblica, pubblica[:-2] + "F=")):  # base64 non canonico: bit di riempimento a 1
            with self.subTest(nuovo=nuovo), self.assertRaises(uscite.UscitaNonValida) as e:
                uscite.leggi(BUONA.replace(vecchio, nuovo), "DE")
            self.assertIn("non e' una chiave WireGuard", str(e.exception))
            self.assertNotIn(nuovo, str(e.exception).replace(profilo.SEGNAPOSTO, ""))

    def test_script_rifiutati(self):
        for script in ("PostUp", "PreUp", "PostDown", "PreDown", "SaveConfig", "Table", "FwMark"):
            with self.subTest(script=script), self.assertRaises(uscite.UscitaNonValida) as e:
                uscite.leggi(BUONA.replace("DNS = 10.64.0.1", f"{script} = curl x | sh"), "DE")
            self.assertNotIn("curl", str(e.exception))  # il valore non si ripete

    def test_paese_campi_e_uscita_completa(self):
        for testo, paese in ((BUONA, "de"), (BUONA, "ITA"), (BUONA.replace("0.0.0.0/0, ", ""), "IT"),
                             (BUONA.replace("Endpoint = 185.1.2.3:51820\n", ""), "IT"),
                             (BUONA + "[Peer]\nPublicKey = x\n", "IT"), (BUONA.replace("MTU", "X") + "Pippo = 1\n", "IT"),
                             (BUONA.replace("185.1.2.3:51820", "de1.provider.example:51820"), "DE"),  # niente DNS al riavvio
                             (BUONA.replace("185.1.2.3:51820", "[2001:db8::1]:51820"), "DE"),
                             (BUONA.replace("185.1.2.3:51820", "185.1.2.3:0"), "DE"),
                             (BUONA.replace("10.64.12.7/32, ", ""), "DE"),  # solo IPv6
                             (BUONA.replace("DNS = 10.64.0.1", "MTU = 9000"), "DE")):
            with self.subTest(paese=paese, testo=testo[-40:]), self.assertRaises(uscite.UscitaNonValida):
                uscite.leggi(testo, paese)


class Illeggibile(unittest.TestCase):
    """status e reconcile leggono lo stato delle uscite anche da utente normale: sul server /var/lib/sovereignvpn e'
    0700 di root, e un PermissionError faceva cadere status, audit e reconcile (CI della #45, banco dei mutanti)."""
    @unittest.skipIf(os.geteuid() == 0, "da root la cartella si legge comunque: il caso esiste solo da utente normale")
    def test_cartella_illeggibile_vale_nessuna_uscita(self):
        base = tempfile.mkdtemp()
        c = os.path.join(base, "uscite")
        uscite.importa(BUONA, "DE", cartella=c); uscite.scegli("DE", c)
        os.chmod(base, 0o000)
        try:
            self.assertEqual((uscite.stato(c)["attiva"], uscite.pool(c)), (None, []))
            self.assertEqual(uscite.ripristina({"subnet": "10.66.0.0/24"}, cartella=c), "nessuna uscita scelta")
        finally:
            os.chmod(base, 0o700)


class Disco(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.c = os.path.join(self.d, "uscite")

    def test_import_file_0600_cartella_0700_pool_senza_chiave(self):
        s1 = uscite.importa(BUONA, "DE", cartella=self.c)
        s2 = uscite.importa(altra(1), "DE", "Francoforte 2", cartella=self.c)
        self.assertEqual((s1["id"], s2["id"], s2["nome"]), ("de-1", "de-2", "Francoforte 2"))
        self.assertEqual(stat.S_IMODE(os.stat(self.c).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.c, "de-1.conf")).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.c, "pool.json")).st_mode), 0o600)
        self.assertNotIn(PRIVATA, pathlib.Path(self.c, "pool.json").read_text())
        with self.assertRaises(uscite.UscitaNonValida):
            uscite.importa(BUONA, "DE", cartella=self.c)  # la stessa uscita due volte
        with self.assertRaises(uscite.UscitaNonValida):
            uscite.importa(altra(2), "DE", "x; rm -rf /", cartella=self.c)

    def test_scelta_per_paese_per_uscita_e_off(self):
        for i, (testo, paese) in enumerate(((BUONA, "DE"), (altra(1), "DE"), (altra(2), "JP"))):
            uscite.importa(testo, paese, cartella=self.c)
        st = uscite.scegli("DE", self.c, adesso=100)
        self.assertEqual((st["scelta"], st["attiva"], st["ultimo_cambio"]), ("DE", "de-1", 100))
        st = uscite.scegli("de-2", self.c, adesso=200)
        self.assertEqual((st["scelta"], st["attiva"]), ("de-2", "de-2"))
        st = uscite.scegli("DE", self.c, adesso=300)  # stesso paese: l'uscita in uso resta, niente cambio d'IP
        self.assertEqual((st["attiva"], st["ultimo_cambio"]), ("de-2", 200))
        with self.assertRaises(uscite.UscitaNonValida):
            uscite.scegli("FR", self.c)  # nessuna uscita francese nel pool
        with self.assertRaises(uscite.UscitaNonValida):
            uscite.scegli("de-9", self.c)
        with self.assertRaises(uscite.UscitaNonValida):
            uscite.togli("de-2", self.c)  # in uso
        uscite.togli("jp-1", self.c)
        self.assertFalse(os.path.exists(os.path.join(self.c, "jp-1.conf")))
        self.assertEqual(uscite.scegli("off", self.c)["attiva"], None)
        with self.assertRaises(uscite.UscitaNonValida):
            uscite.imposta_rotazione(-1, self.c)
        self.assertEqual(uscite.imposta_rotazione(15, self.c)["rotazione_minuti"], 15)

    def test_lucchetto_esclusivo(self):
        with uscite.lucchetto(self.c):
            fd = os.open(os.path.join(self.c, ".lucchetto"), os.O_WRONLY)
            try:
                with self.assertRaises(BlockingIOError):  # un secondo scrittore aspetta
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        fd = os.open(os.path.join(self.c, ".lucchetto"), os.O_WRONLY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # rilasciato all'uscita
        os.close(fd)


class Rotazione(unittest.TestCase):
    SCHEDE = [{"id": i, "paese": i[:2].upper()} for i in ("de-1", "de-2", "de-10", "jp-1")]

    def st(self, **k):
        return {"scelta": "DE", "attiva": "de-1", "rotazione_minuti": 0, "ultimo_cambio": 1000, **k}

    def test_rotazione_allo_scadere_in_ordine(self):
        self.assertEqual(uscite.da_cambiare(self.st(rotazione_minuti=5), self.SCHEDE, 1000 + 299, 10), (None, None))
        self.assertEqual(uscite.da_cambiare(self.st(rotazione_minuti=5), self.SCHEDE, 1000 + 300, 10)[0], "de-2")
        self.assertEqual(uscite.da_cambiare(self.st(rotazione_minuti=5, attiva="de-2"), self.SCHEDE, 2000, 10)[0], "de-10")
        self.assertEqual(uscite.da_cambiare(self.st(rotazione_minuti=5, attiva="de-10"), self.SCHEDE, 2000, 10)[0], "de-1")

    def test_failover_senza_handshake_e_mai_con_l_uscita_viva(self):
        self.assertEqual(uscite.da_cambiare(self.st(), self.SCHEDE, 1000 + 179, None), (None, None))  # appena scelta
        nuova, motivo = uscite.da_cambiare(self.st(), self.SCHEDE, 1000 + 180, None)
        self.assertEqual(nuova, "de-2"); self.assertIn("failover", motivo)
        self.assertEqual(uscite.da_cambiare(self.st(), self.SCHEDE, 5000, 30), (None, None))  # handshake fresco
        self.assertEqual(uscite.da_cambiare(self.st(), self.SCHEDE, 5000, 400)[0], "de-2")

    def test_niente_da_ruotare_con_una_sola_uscita(self):
        self.assertEqual(uscite.da_cambiare(self.st(scelta="JP", attiva="jp-1", rotazione_minuti=1), self.SCHEDE, 9999, None), (None, None))
        self.assertEqual(uscite.da_cambiare(self.st(scelta="de-1", rotazione_minuti=1), self.SCHEDE, 9999, None), (None, None))
        self.assertEqual(uscite.da_cambiare(self.st(attiva=None), self.SCHEDE, 9999, None), (None, None))


class Host(unittest.TestCase):
    CFG = {"subnet": "10.66.0.0/24"}

    def setUp(self):
        self.c = os.path.join(tempfile.mkdtemp(), "uscite")
        uscite.importa(BUONA, "DE", cartella=self.c)
        self.fatti = []

    def finto(self, guasto=None):
        def cmd(*a, ingresso=None, tollera=False):
            self.fatti.append((" ".join(a), ingresso))
            if guasto and guasto in " ".join(a) and not tollera:
                raise RuntimeError(f"{a[0]} non riuscito")
            return (1, "") if tollera else (0, "")
        return contextlib.ExitStack(), cmd

    def applica(self, guasto=None):
        _, cmd = self.finto(guasto)
        with mock.patch.object(uscite, "_cmd", cmd), \
             mock.patch.object(firewall, "applica_tabella", lambda r: self.fatti.append(("nft kill switch", r))):
            return uscite.applica(self.CFG, cartella=self.c)

    def test_ordine_kill_switch_rotte_regole_poi_wgx0(self):
        uscite.scegli("DE", self.c)
        esito = self.applica()
        self.assertTrue(esito["salita"])
        comandi = [c for c, _ in self.fatti]
        self.assertEqual(comandi[0], "nft kill switch")
        self.assertIn('iifname "wg0" oifname != "wgx0" drop', self.fatti[0][1])
        i = {nome: next(n for n, c in enumerate(comandi) if c.startswith(pref)) for nome, pref in (
            ("unreachable", "ip route replace unreachable default"), ("ritorno", "ip route replace 10.66.0.0/24 dev wg0 table 51888"),
            ("mark", "ip rule add fwmark 0x5e48 lookup main priority 5198"), ("peer", "ip rule add iif wg0 lookup 51888 priority 5199"),
            ("setconf", "wg setconf wgx0 /dev/stdin"), ("default", "ip route replace default dev wgx0 table 51888"))}
        self.assertLess(i["unreachable"], i["default"]); self.assertLess(i["ritorno"], i["peer"])
        self.assertLess(i["mark"], i["peer"]); self.assertLess(i["peer"], i["setconf"])
        conf = self.fatti[i["setconf"]][1]
        self.assertIn("FwMark = 0x5e48", conf); self.assertIn("AllowedIPs = 0.0.0.0/0\n", conf)
        self.assertNotIn("::/0", conf); self.assertIn("PersistentKeepalive = 25", conf)
        self.assertIn("ip address add 10.64.12.7/32 dev wgx0", comandi)
        self.assertNotIn(PRIVATA, json.dumps(esito))

    def test_wgx0_che_non_sale_lascia_il_kill_switch(self):
        uscite.scegli("DE", self.c)
        esito = self.applica(guasto="wg setconf")
        self.assertFalse(esito["salita"]); self.assertIn("kill switch attivo", esito["dettaglio"])
        comandi = [c for c, _ in self.fatti]
        self.assertEqual(comandi[0], "nft kill switch")
        caduta = next(n for n, c in enumerate(comandi) if c.startswith("wg setconf"))
        self.assertFalse([c for c in comandi[caduta:] if c.startswith(("nft delete", "ip rule del", "ip route flush"))])  # niente smontato
        self.assertIn("ip rule add iif wg0 lookup 51888 priority 5199", comandi[:caduta])
        self.assertNotIn("ip route replace default dev wgx0 table 51888", comandi)

    def test_kill_switch_che_non_va_ferma_tutto(self):
        uscite.scegli("DE", self.c)
        with mock.patch.object(firewall, "applica_tabella", side_effect=RuntimeError("nft rifiuta")), \
             mock.patch.object(uscite, "_cmd", self.finto()[1]):
            with self.assertRaises(RuntimeError):
                uscite.applica(self.CFG, cartella=self.c)
        self.assertFalse([c for c, _ in self.fatti if "wgx0" in c])  # niente uscita senza kill switch

    def test_off_toglie_tutto_e_reconcile_senza_scelta_non_tocca_niente(self):
        self.assertEqual(uscite.ripristina(self.CFG, cartella=self.c), "nessuna uscita scelta")
        uscite.scegli("DE", self.c); uscite.scegli("off", self.c)
        self.applica()
        comandi = [c for c, _ in self.fatti]
        for atteso in ("ip rule del fwmark 0x5e48 lookup main priority 5198", "ip rule del iif wg0 lookup 51888 priority 5199", "ip route flush table 51888",
                       "ip link del wgx0", "nft delete table inet sovereignvpn_uscita"):
            self.assertIn(atteso, comandi)

    def test_tick_ruota_salva_e_applica(self):
        uscite.importa(altra(1), "DE", cartella=self.c)
        uscite.scegli("DE", self.c, adesso=0); uscite.imposta_rotazione(1, self.c)
        with mock.patch.object(uscite, "eta_handshake", lambda *a: 5), mock.patch.object(uscite, "viva", lambda: True), \
             mock.patch.object(uscite, "applica", lambda *a, **k: {"salita": True}) as _:
            self.assertEqual(uscite.tick(self.CFG, cartella=self.c, adesso=59)["cambio"], None)
            esito = uscite.tick(self.CFG, cartella=self.c, adesso=60)
        self.assertEqual(esito["cambio"], "de-2"); self.assertEqual(uscite.stato(self.c)["attiva"], "de-2")
        with mock.patch.object(uscite, "eta_handshake", lambda *a: 5), mock.patch.object(uscite, "viva", lambda: False), \
             mock.patch.object(uscite, "applica", lambda *a, **k: {"salita": True}):
            self.assertIn("riparazione", uscite.tick(self.CFG, cartella=self.c, adesso=61)["motivo"])


class Cli(unittest.TestCase):
    def test_import_e_list_in_json_senza_chiavi(self):
        c = os.path.join(tempfile.mkdtemp(), "uscite")
        f = os.path.join(os.path.dirname(c), "de.conf")
        pathlib.Path(f).write_text(BUONA)
        nella_rete = os.path.join(os.path.dirname(c), "stessa-rete.conf")
        pathlib.Path(nella_rete).write_text(altra(3).replace("10.64.12.7/32", "10.66.0.9/32"))
        for argomenti, codice in ((["exit", "import", f, "--paese", "DE", "--cartella", c, "--config", ESEMPIO], 0),
                                  (["exit", "import", f, "--paese", "DE", "--cartella", c, "--config", ESEMPIO], 2),
                                  (["exit", "import", nella_rete, "--paese", "DE", "--cartella", c, "--config", ESEMPIO], 2),
                                  (["exit", "list", "--json", "--cartella", c], 0)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(argomenti), codice, argomenti)
            self.assertNotIn(PRIVATA, out.getvalue())
        r = json.loads(out.getvalue())
        self.assertIsNone(r["handshake_secondi"])  # nessuna uscita attiva: wg non si interroga
        self.assertEqual(r["paesi"], [{"paese": "DE", "bandierina": "\U0001F1E9\U0001F1EA", "uscite": 1}])
        self.assertEqual((r["uscite"][0]["id"], r["uscite"][0]["attiva"]), ("de-1", False))


class Firewall(unittest.TestCase):
    def test_la_tabella_principale_lascia_passare_e_maschera_wgx0(self):
        r = firewall.componi("10.66.0.0/24", "wg0", 51820, "ens3", ssh_sorgenti=["198.51.100.10/32"])
        self.assertIn('iifname "wg0" ip saddr 10.66.0.0/24 oifname "wgx0" accept', r)
        self.assertIn('ip saddr 10.66.0.0/24 oifname "wgx0" masquerade', r)
        self.assertIn('iifname "wg0" oifname "wgx0" tcp flags syn / syn,rst tcp option maxseg size set rt mtu', r)


if __name__ == "__main__":
    unittest.main()
