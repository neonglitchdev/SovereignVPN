"""Prove di `sovereignctl backup restore` (FR-OPS-003, H21) con age, reconcile e status sostituiti.
Il restore vero, con age vero e reconcile in un network namespace, gira sul runner (prova_backup_vero.sh).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, hashlib, io, json, os, pathlib, sqlite3, tarfile, tempfile, unittest
from unittest import mock

from sovereignctl import backup, peer, ripristino
from test_configurazione import ESEMPIO
from test_preflight import esegui

DESTINATARIO = "age1" + "qpzry9x8gf" * 5 + "qpzry9x8"
FINTO = b"AGE-FINTO\n"
OK4 = [("firewall", True), ("sysctl", True), ("interfaccia", "wg0 10.66.0.1/24"), ("riconciliazione", True)]


class Restore(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); t = self.t = pathlib.Path(self._t.name)
        self.config, self.chiave, self.manifest = t / "etc/server.toml", t / "etc/wg-server.key", t / "var/manifest.json"
        self.db, self.out, self.identita = str(t / "var/registro.sqlite3"), t / "backup", t / "identita.txt"
        self.identita.write_text("giusta\n")
        self.controlli = [{"nome": "release", "esito": "OK", "dettaglio": ""}]
        self.patch = [mock.patch.object(backup.runtime, "CHIAVE_SERVER", str(self.chiave)),
                      mock.patch.object(backup.bootstrap, "MANIFEST", str(self.manifest)),
                      mock.patch.object(backup, "_age", self.age),
                      mock.patch.object(ripristino.bootstrap, "ripristina", mock.Mock(return_value=(OK4, None))),
                      mock.patch.object(ripristino.stato, "controlla", lambda cfg, db: (self.controlli, False))]
        for p in self.patch:
            p.start()
        self.stato("A", ("uno", "due"))
        codice, out, err = esegui(["backup", "create", "--config", str(self.config), "--recipient", DESTINATARIO,
                                   "--db", self.db, "--out", str(self.out), "--json"])
        self.assertEqual(codice, 0, err)
        self.file = json.loads(out)["percorso"]
        self.stato("B", ("tre",))  # lo stato vivo cambia dopo il backup

    def tearDown(self):
        for p in self.patch:
            p.stop()
        self._t.cleanup()

    def stato(self, segno, nomi):
        for f in (self.config, self.chiave, self.manifest):
            f.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text(f'wan_interface = "ens3"\n# stato {segno}\n' + ESEMPIO.read_text())
        self.chiave.write_text(base64.b64encode(segno.encode() * 32).decode() + "\n"); self.chiave.chmod(0o600)
        self.manifest.write_text(json.dumps({"sovereignvpn": "14.0.0", "stato": segno}))
        for coda in ("", "-wal", "-shm"):
            if os.path.exists(self.db + coda):
                os.unlink(self.db + coda)
        a = peer.Archivio(self.db)
        for n in nomi:
            a.aggiungi(n, base64.b64encode(os.urandom(32)).decode(), "10.66.0.0/24")
        a.db.close()

    def age(self, *argomenti, ingresso=None):
        if argomenti[:1] == ("-r",):
            return FINTO + ingresso
        if argomenti[:2] == ("-d", "-i"):
            dati = pathlib.Path(argomenti[3]).read_bytes()
            if pathlib.Path(argomenti[2]).read_text() != "giusta\n" or not dati.startswith(FINTO):
                raise backup.AgeFallito("age non riuscito")
            return dati[len(FINTO):]
        raise AssertionError(argomenti)

    def restore(self, *extra, file=None):
        return esegui(["backup", "restore", file or self.file, "--identity", str(self.identita), "--config", str(self.config),
                       "--db", self.db, "--out", str(self.out), "--json", *extra])

    def nomi(self):
        return sorted(r[0] for r in sqlite3.connect(f"file:{self.db}?mode=ro", uri=True).execute("SELECT nome FROM peer"))

    def impronta(self):
        return {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in (self.config, self.chiave, self.manifest)}, self.nomi()

    def test_ripristina_salva_prima_lo_stato_corrente_e_verifica(self):
        chiave_b = self.chiave.read_bytes()
        pathlib.Path(self.db + "-wal").write_bytes(b"wal vecchio del registro B")
        codice, out, err = self.restore("--conferma")
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        self.assertIn("# stato A", self.config.read_text())
        self.assertEqual(self.nomi(), ["due", "uno"])
        self.assertFalse(os.path.exists(self.db + "-wal") and pathlib.Path(self.db + "-wal").read_bytes() == b"wal vecchio del registro B")
        with tarfile.open(fileobj=io.BytesIO(pathlib.Path(r["stato_precedente"]).read_bytes()[len(FINTO):])) as tar:
            self.assertEqual(tar.extractfile("etc/sovereignvpn/wg-server.key").read(), chiave_b)
        ripristino.bootstrap.ripristina.assert_called_once()

    def test_senza_conferma_niente(self):
        prima = self.impronta()
        self.assertEqual(self.restore()[0], 2)
        self.assertEqual(self.impronta(), prima)

    def test_chiave_sbagliata_niente_toccato_e_niente_salvato(self):
        prima, salvati = self.impronta(), sorted(self.out.iterdir())
        self.identita.write_text("sbagliata\n")
        codice, _, err = self.restore("--conferma")
        self.assertEqual(codice, 2, err)
        self.assertEqual((self.impronta(), sorted(self.out.iterdir())), (prima, salvati))

    def riscrivi(self, cambia):
        """Un archivio rifatto a mano, ricifrato col finto age: per checksum sbagliati e voci estranee."""
        dati = pathlib.Path(self.file).read_bytes()[len(FINTO):]
        with tarfile.open(fileobj=io.BytesIO(dati)) as tar:
            membri = {m.name: tar.extractfile(m).read() for m in tar.getmembers()}
        cambia(membri)
        nuovo = io.BytesIO()
        with tarfile.open(fileobj=nuovo, mode="w") as tar:
            for n, b in membri.items():
                info = tarfile.TarInfo(n); info.size = len(b); tar.addfile(info, io.BytesIO(b))
        f = self.t / "rifatto.tar.age"; f.write_bytes(FINTO + nuovo.getvalue())
        return str(f)

    def test_checksum_diverso_e_security_gate(self):
        prima = self.impronta()
        f = self.riscrivi(lambda m: m.__setitem__("etc/sovereignvpn/server.toml", m["etc/sovereignvpn/server.toml"] + b"# aggiunta\n"))
        self.assertEqual(self.restore("--conferma", file=f)[0], 3)
        self.assertEqual(self.impronta(), prima)

    def test_voce_estranea_rifiutata(self):
        prima = self.impronta()
        f = self.riscrivi(lambda m: m.__setitem__("../../etc/cron.d/x", b"* * * * * root id\n"))
        codice, _, err = self.restore("--conferma", file=f)
        self.assertEqual(codice, 2)
        self.assertIn("voci inattese", err)
        self.assertEqual(self.impronta(), prima)

    def test_verifica_che_non_torna_rimette_lo_stato_di_prima_ed_esce_con_4(self):
        prima = self.impronta()
        self.controlli = [{"nome": "peer", "esito": "GUASTO", "dettaglio": "differenze 1"}]
        codice, out, _ = self.restore("--conferma")
        self.assertEqual(codice, 4)
        r = json.loads(out)
        self.assertEqual((r["guasti"], r["tornato_indietro"]), (["peer"], True))
        self.assertEqual(self.impronta(), prima)
        self.assertEqual(ripristino.bootstrap.ripristina.call_count, 2)  # reconcile del restore e di nuovo dopo


if __name__ == "__main__":
    unittest.main()
