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
        primo = albero(self.radice)
        codice, _, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 0, err)
        self.assertEqual(albero(self.radice), primo)
        avanzi = [p for p in primo if any(x in p for x in (".nuovo", ".vecchio", ".lock", "__pycache__"))]
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
        self.assertIn("5. installare l'unita'", lancia("--radice", self.radice, "--dry-run")[1])

    def test_input_non_valido_esce_con_2(self):
        for argomenti, voce in ((["--colore"], "--colore"), (["--radice"], "--radice"),
                                (["--radice", "/non/esiste/davvero"], "--radice")):
            with self.subTest(argomenti=argomenti):
                codice, _, err = lancia(*argomenti)
                self.assertEqual(codice, 2)
                self.assertIn(voce, err)

    def test_lucchetto_ferma_la_seconda_installazione(self):
        os.makedirs(os.path.join(self.radice, "opt", ".sovereignvpn-install.lock"))
        codice, _, err = lancia("--radice", self.radice)
        self.assertEqual(codice, 1)
        self.assertIn("un'altra installazione", err)
        self.assertTrue(os.path.isdir(os.path.join(self.radice, "opt", ".sovereignvpn-install.lock")))  # non e' suo: resta


if __name__ == "__main__":
    unittest.main()
