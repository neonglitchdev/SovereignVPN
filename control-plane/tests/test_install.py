"""Prove dell'installer (Slice A, ANC-0346) e delle regole degli script che toccano l'host (ANC-0342).
Installa in una --radice temporanea: il sistema vero non si tocca. Uso, da control-plane/: python3 -m unittest discover -s tests"""
import json, os, pathlib, stat, subprocess, tempfile, unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "ops" / "install.sh"


def lancia(*argomenti):
    r = subprocess.run(["bash", str(SCRIPT), *argomenti], capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def albero(radice):
    return sorted(str(p.relative_to(radice)) + (f" {oct(p.stat().st_mode & 0o777)}" if p.is_dir() else "")
                  for p in pathlib.Path(radice).rglob("*"))


class Installer(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(prefix="radice-")
        self.radice = self._t.name

    def tearDown(self):
        self._t.cleanup()

    def test_regole_di_ANC_0342_nello_script(self):
        testo = SCRIPT.read_text()
        for regola in ("set -Eeuo pipefail", "IFS=$'\\n\\t'", "trap pulizia EXIT", "trap 'echo", "--dry-run", "LUCCHETTO"):
            with self.subTest(regola=regola):
                self.assertIn(regola, testo)

    def test_dry_run_mostra_il_piano_e_non_tocca_niente(self):
        prima = albero(self.radice)
        codice, out, err = lancia("--radice", self.radice, "--dry-run")
        self.assertEqual(codice, 0, err)
        self.assertIn("nessuna mutazione", out)
        self.assertIn("4. scrivere il comando", out)
        self.assertEqual(albero(self.radice), prima)

    def test_installa_permessi_e_comando_che_funziona(self):
        codice, out, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 0, err)
        r = pathlib.Path(self.radice)
        self.assertTrue((r / "opt/sovereignvpn/sovereignctl/__main__.py").is_file())
        for d in ("etc/sovereignvpn", "var/lib/sovereignvpn"):
            self.assertEqual(stat.S_IMODE((r / d).stat().st_mode), 0o700, d)
        comando = r / "usr/local/bin/sovereignctl"
        self.assertTrue(os.access(comando, os.X_OK))
        uscita = subprocess.run([str(comando), "init", "--check", "--json"], capture_output=True, text=True, timeout=60)
        self.assertIn(uscita.returncode, (0, 1), uscita.stderr)
        self.assertEqual(json.loads(uscita.stdout)["mutazioni_eseguite"], 0)
        self.assertNotEqual(albero(self.radice), [])  # controllo negativo del confronto usato dal dry-run

    def test_idempotente_e_senza_avanzi(self):
        self.assertEqual(lancia("--radice", self.radice)[0], 0)
        self.assertEqual(lancia("--radice", self.radice)[0], 0)  # dalla seconda c'e' anche la release precedente
        primo = albero(self.radice)
        codice, _, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 0, err)
        self.assertEqual(albero(self.radice), primo)
        avanzi = [p for p in primo if any(x in p for x in (".nuovo", ".vecchio", ".scambio", ".lock", "__pycache__"))]
        self.assertEqual(avanzi, [])

    def test_unita_di_avvio_installata_e_coerente(self):
        codice, _, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 0, err)
        r = pathlib.Path(self.radice)
        unita = r / "etc/systemd/system/sovereignvpn-reconcile.service"
        self.assertEqual(stat.S_IMODE(unita.stat().st_mode), 0o644)
        voci = dict(x.split("=", 1) for x in unita.read_text().splitlines() if "=" in x and not x.startswith("#"))
        comando = voci["ExecStart"].split()
        self.assertEqual(comando, ["/usr/local/bin/sovereignctl", "reconcile", "--config", "/etc/sovereignvpn/server.toml"])
        aiuto = subprocess.run([str(r / comando[0].lstrip("/")), "reconcile", "--help"], capture_output=True, text=True, timeout=60)
        self.assertEqual(aiuto.returncode, 0, aiuto.stderr)  # il comando installato conosce `reconcile`
        self.assertEqual(voci["ConditionPathExists"], "/var/lib/sovereignvpn/manifest.json")  # solo dopo init --apply
        self.assertIn("network-pre.target", voci["Before"])  # il firewall prima che salga la rete
        self.assertIn("5. installare le unita'", lancia("--radice", self.radice, "--dry-run")[1])

    def test_scadenze_ogni_minuto_anche_dopo_un_riavvio(self):
        codice, _, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 0, err)
        r = pathlib.Path(self.radice) / "etc/systemd/system"
        for nome in ("sovereignvpn-expire.service", "sovereignvpn-expire.timer"):
            self.assertEqual(stat.S_IMODE((r / nome).stat().st_mode), 0o644, nome)
        servizio = (r / "sovereignvpn-expire.service").read_text().splitlines()
        self.assertEqual([x.split("=", 1)[1] for x in servizio if x.startswith("ExecStart=")],
                         ["/usr/local/bin/sovereignctl peer expire-sweep",
                          "/usr/local/bin/sovereignctl reconcile --config /etc/sovereignvpn/server.toml"])
        aiuto = subprocess.run([str(pathlib.Path(self.radice) / "usr/local/bin/sovereignctl"), "peer", "expire-sweep", "--help"],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(aiuto.returncode, 0, aiuto.stderr)  # il comando installato conosce `peer expire-sweep`
        timer = (r / "sovereignvpn-expire.timer").read_text().splitlines()
        for voce in ("OnCalendar=minutely", "Persistent=true", "WantedBy=timers.target"):
            self.assertIn(voce, timer)

    def test_rollback_alla_release_precedente_e_ritorno(self):
        opt = pathlib.Path(self.radice) / "opt/sovereignvpn"
        self.assertEqual(lancia("--radice", self.radice, "--rollback")[0], 1)  # senza una precedente: niente
        self.assertEqual(lancia("--radice", self.radice)[0], 0)
        (opt / "sovereignctl/marca-release-1").write_text("1")
        self.assertEqual(lancia("--radice", self.radice)[0], 0)
        self.assertEqual(((opt / "sovereignctl/marca-release-1").exists(), (opt / "sovereignctl.precedente/marca-release-1").exists()),
                         (False, True))
        prima = albero(self.radice)
        codice, out, _ = lancia("--radice", self.radice, "--rollback", "--dry-run")
        self.assertEqual((codice, albero(self.radice)), (0, prima))
        codice, _, err = lancia("--radice", self.radice, "--rollback")
        self.assertEqual(codice, 0, err)
        self.assertTrue((opt / "sovereignctl/marca-release-1").exists())
        self.assertFalse((opt / "sovereignctl.precedente/marca-release-1").exists())
        uscita = subprocess.run([str(pathlib.Path(self.radice) / "usr/local/bin/sovereignctl"), "init", "--check", "--json"],
                                capture_output=True, text=True, timeout=60)
        self.assertIn(uscita.returncode, (0, 1), uscita.stderr)  # il comando gira con la release di prima
        self.assertEqual(lancia("--radice", self.radice, "--rollback")[0], 0)  # un secondo rollback rimette la piu' nuova
        self.assertFalse((opt / "sovereignctl/marca-release-1").exists())

    def dati_ed_estranei(self):
        """Dati persistenti del prodotto e file di altri, accanto: l'uninstall deve distinguerli."""
        r = pathlib.Path(self.radice)
        file = {"etc/sovereignvpn/server.toml": "schema_version = 1\n", "etc/sovereignvpn/wg-server.key": "chiave\n",
                "var/lib/sovereignvpn/registro.sqlite3": "registro", "var/lib/sovereignvpn/backup/b.age": "cifrato",
                "etc/sysctl.d/90-sovereignvpn.conf": "net.ipv4.ip_forward = 1\n",
                "etc/systemd/system/altro.service": "[Unit]\n", "usr/local/bin/altro": "#!/bin/sh\n",
                "opt/altro/file": "x", "etc/sysctl.d/10-altro.conf": "vm.swappiness = 10\n"}
        for nome, testo in file.items():
            (r / nome).parent.mkdir(parents=True, exist_ok=True)
            (r / nome).write_text(testo)
        return r

    ESTRANEI = ("etc/systemd/system/altro.service", "usr/local/bin/altro", "opt/altro/file", "etc/sysctl.d/10-altro.conf")
    DATI = ("etc/sovereignvpn/server.toml", "etc/sovereignvpn/wg-server.key", "var/lib/sovereignvpn/registro.sqlite3",
            "var/lib/sovereignvpn/backup/b.age")

    def test_uninstall_toglie_il_prodotto_e_conserva_i_dati(self):
        """FR-OPS-007 [H40]: senza scelta esplicita i dati restano; i file di altri non si toccano."""
        self.assertEqual(lancia("--radice", self.radice)[0], 0)
        self.assertEqual(lancia("--radice", self.radice)[0], 0)  # anche la release precedente
        r = self.dati_ed_estranei()
        codice, out, err = lancia("--radice", self.radice, "--uninstall")
        self.assertEqual(codice, 0, err)
        for tolto in ("opt/sovereignvpn", "usr/local/bin/sovereignctl", "etc/systemd/system/sovereignvpn-reconcile.service",
                      "etc/systemd/system/sovereignvpn-expire.timer", "etc/sysctl.d/90-sovereignvpn.conf"):
            self.assertFalse((r / tolto).exists(), tolto)
        for resta in self.DATI + self.ESTRANEI:
            self.assertTrue((r / resta).is_file(), resta)
        self.assertEqual((r / "etc/sovereignvpn/wg-server.key").read_text(), "chiave\n")
        self.assertIn("Dati conservati", out)
        self.assertFalse((r / "opt/.sovereignvpn-install.lock").exists())

    def test_uninstall_a_secco_non_tocca_niente(self):
        self.assertEqual(lancia("--radice", self.radice)[0], 0)
        self.dati_ed_estranei()
        prima = albero(self.radice)
        codice, out, err = lancia("--radice", self.radice, "--uninstall", "--dry-run")
        self.assertEqual(codice, 0, err)
        self.assertIn("conservare i dati", out)
        self.assertEqual(albero(self.radice), prima)

    def test_eliminare_i_dati_vuole_la_conferma(self):
        self.assertEqual(lancia("--radice", self.radice)[0], 0)
        r = self.dati_ed_estranei()
        prima = albero(self.radice)
        codice, _, err = lancia("--radice", self.radice, "--uninstall", "--elimina-dati")
        self.assertEqual(codice, 2)
        self.assertIn("--conferma", err)
        self.assertEqual(albero(self.radice), prima)  # rifiutato prima di toccare qualunque cosa
        codice, out, err = lancia("--radice", self.radice, "--uninstall", "--elimina-dati", "--conferma")
        self.assertEqual(codice, 0, err)
        for tolto in ("etc/sovereignvpn", "var/lib/sovereignvpn", "opt/sovereignvpn"):
            self.assertFalse((r / tolto).exists(), tolto)
        for resta in self.ESTRANEI:
            self.assertTrue((r / resta).is_file(), resta)

    def test_uninstall_fermato_dal_lucchetto(self):
        self.assertEqual(lancia("--radice", self.radice)[0], 0)
        (pathlib.Path(self.radice) / "opt/.sovereignvpn-install.lock").mkdir()
        prima = albero(self.radice)
        codice, _, err = lancia("--radice", self.radice, "--uninstall")
        self.assertEqual(codice, 1)
        self.assertIn("lucchetto", err)
        self.assertEqual(albero(self.radice), prima)

    def test_combinazioni_dell_uninstall_non_valide(self):
        for argomenti in (["--elimina-dati", "--conferma"], ["--conferma"], ["--uninstall", "--rollback"]):
            with self.subTest(argomenti=argomenti):
                self.assertEqual(lancia("--radice", self.radice, *argomenti)[0], 2)

    def test_input_non_valido_esce_con_2(self):
        for argomenti, voce in ((["--colore"], "--colore"), (["--radice"], "--radice"),
                                (["--radice", "/non/esiste/davvero"], "--radice")):
            with self.subTest(argomenti=argomenti):
                codice, _, err = lancia(*argomenti)
                self.assertEqual(codice, 2)
                self.assertIn(voce, err)

    def test_lucchetto_orfano_si_toglie_quello_vivo_no(self):
        lucchetto = os.path.join(self.radice, "opt", ".sovereignvpn-install.lock")
        morto = subprocess.Popen(["true"]); morto.wait()  # un PID che non c'e' piu'
        os.makedirs(lucchetto); pathlib.Path(lucchetto, "pid").write_text(f"{morto.pid}\n")
        codice, _, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 0, err)
        self.assertIn("lucchetto orfano tolto", err)
        self.assertFalse(os.path.exists(lucchetto))  # e quello nuovo, preso e lasciato, non resta
        self.assertFalse([n for n in os.listdir(os.path.join(self.radice, "opt")) if ".orfano." in n])
        os.makedirs(lucchetto); pathlib.Path(lucchetto, "pid").write_text(f"{os.getpid()}\n")  # vivo: questo processo
        prima = albero(self.radice)
        codice, _, err = lancia("--radice", self.radice, "--uninstall")
        self.assertEqual(codice, 1)
        self.assertIn("un'altra installazione", err)
        self.assertEqual(albero(self.radice), prima)

    def test_lucchetto_ferma_la_seconda_installazione(self):
        os.makedirs(os.path.join(self.radice, "opt", ".sovereignvpn-install.lock"))
        codice, _, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 1)
        self.assertIn("un'altra installazione", err)
        self.assertIn("senza PID", err)  # di una versione di prima: si dice come toglierlo, non si toglie
        self.assertTrue(os.path.isdir(os.path.join(self.radice, "opt", ".sovereignvpn-install.lock")))  # non e' suo: resta


if __name__ == "__main__":
    unittest.main()
