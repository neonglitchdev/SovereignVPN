"""Prove di `sovereignctl backup create` (FR-OPS-001, H20) con `age` sostituito da una cifratura finta e reversibile.
La cifratura vera (age) e il decrypt con la chiave giusta e sbagliata si provano sul runner (prova_backup_vero.sh).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, hashlib, io, json, os, pathlib, sqlite3, stat, tarfile, tempfile, unittest
from unittest import mock

from sovereignctl import backup, configurazione, peer
from test_configurazione import ESEMPIO
from test_preflight import esegui

DESTINATARIO = "age1" + "qpzry9x8gf" * 5 + "qpzry9x8"
PRIVATA = base64.b64encode(b"s" * 32).decode()
FINTO = b"AGE-FINTO\n"


class Crea(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); t = self.t = pathlib.Path(self._t.name)
        self.config, self.chiave, self.manifest = t / "server.toml", t / "wg-server.key", t / "manifest.json"
        self.db, self.out = str(t / "registro.sqlite3"), t / "backup"
        self.config.write_text(ESEMPIO.read_text())
        self.chiave.write_text(PRIVATA + "\n"); self.chiave.chmod(0o600)
        self.manifest.write_text('{"sovereignvpn": "14.0.0"}\n')
        a = peer.Archivio(self.db)
        for nome in ("uno", "due"):
            a.aggiungi(nome, base64.b64encode(os.urandom(32)).decode(), "10.66.0.0/24")
        a.db.close()
        self.patch = [mock.patch.object(backup.runtime, "CHIAVE_SERVER", str(self.chiave)),
                      mock.patch.object(backup.bootstrap, "MANIFEST", str(self.manifest)),
                      mock.patch.object(backup, "_age", self.age)]
        for p in self.patch:
            p.start()

    def tearDown(self):
        for p in self.patch:
            p.stop()
        self._t.cleanup()

    def age(self, *argomenti, ingresso):
        self.assertEqual(argomenti, ("-r", DESTINATARIO))
        return FINTO + ingresso

    def crea(self, *extra):
        return esegui(["backup", "create", "--config", str(self.config), "--db", self.db, "--out", str(self.out), *extra])

    def test_archivio_completo_cifrato_0600_col_manifest_e_senza_segreti_in_chiaro(self):
        codice, out, err = self.crea("--recipient", DESTINATARIO, "--json")
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        cifrato = pathlib.Path(r["percorso"]).read_bytes()
        self.assertEqual(r["checksum"], "sha256:" + hashlib.sha256(cifrato).hexdigest())
        for f in (r["percorso"], r["manifest"]):
            self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600, f)
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        self.assertTrue(cifrato.startswith(FINTO))
        with tarfile.open(fileobj=io.BytesIO(cifrato[len(FINTO):])) as tar:
            membri = {m.name: tar.extractfile(m).read() for m in tar.getmembers()}
        self.assertEqual(sorted(membri), ["backup-manifest.json", "etc/sovereignvpn/server.toml", "etc/sovereignvpn/wg-server.key",
                                          "var/lib/sovereignvpn/manifest.json", "var/lib/sovereignvpn/registro.sqlite3"])
        self.assertEqual(membri["etc/sovereignvpn/wg-server.key"], self.chiave.read_bytes())
        self.assertEqual(membri["etc/sovereignvpn/server.toml"], self.config.read_bytes())
        copia = sqlite3.connect(":memory:")
        copia.deserialize(membri["var/lib/sovereignvpn/registro.sqlite3"])
        self.assertEqual(copia.execute("SELECT count(*) FROM peer").fetchone()[0], 2)
        m = json.loads(membri["backup-manifest.json"])
        self.assertEqual({f["nome"]: f["sha256"] for f in m["file"]},
                         {n: hashlib.sha256(b).hexdigest() for n, b in membri.items() if n != "backup-manifest.json"})
        self.assertEqual((m["destinatario"], m["schema"]), (DESTINATARIO, 1))
        accanto = pathlib.Path(r["manifest"]).read_text()
        self.assertEqual(json.loads(accanto), m)
        self.assertNotIn(PRIVATA, accanto + out + err)

    def test_il_registro_include_le_transazioni_ancora_nel_wal(self):
        aperta = sqlite3.connect(self.db, isolation_level=None)
        aperta.execute("PRAGMA wal_autocheckpoint=0")
        aperta.execute("UPDATE peer SET nome = 'tre' WHERE nome = 'due'")  # resta nel -wal finche' la connessione vive
        self.assertGreater(os.path.getsize(self.db + "-wal"), 0)
        codice, out, err = self.crea("--recipient", DESTINATARIO, "--json")
        aperta.close()
        self.assertEqual(codice, 0, err)
        with tarfile.open(fileobj=io.BytesIO(pathlib.Path(json.loads(out)["percorso"]).read_bytes()[len(FINTO):])) as tar:
            registro = tar.extractfile("var/lib/sovereignvpn/registro.sqlite3").read()
        copia = sqlite3.connect(":memory:")
        copia.deserialize(registro)
        self.assertEqual(sorted(r[0] for r in copia.execute("SELECT nome FROM peer")), ["tre", "uno"])

    def test_destinatario_dalla_configurazione(self):
        self.config.write_text(f'backup_recipient = "{DESTINATARIO}"\n' + ESEMPIO.read_text())
        self.assertEqual(self.crea()[0], 0)

    def test_senza_destinatario_o_con_uno_sbagliato_niente(self):
        for extra in ((), ("--recipient", "age1corto"), ("--recipient", "-----BEGIN PGP PUBLIC KEY BLOCK-----")):
            with self.subTest(extra=extra):
                codice, _, err = self.crea(*extra)
                self.assertEqual(codice, 2, err)
                self.assertFalse(self.out.exists())

    def test_lo_schema_rifiuta_un_destinatario_che_non_e_age(self):
        with self.assertRaises(configurazione.InputNonValido if hasattr(configurazione, "InputNonValido") else Exception):
            configurazione.valida({**configurazione.leggi(ESEMPIO), "backup_recipient": "age1corto"})

    def test_se_age_fallisce_non_resta_niente(self):
        with mock.patch.object(backup, "_age", side_effect=RuntimeError("age non riuscito")):
            codice, _, err = self.crea("--recipient", DESTINATARIO)
        self.assertEqual(codice, 1)
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))


if __name__ == "__main__":
    unittest.main()
