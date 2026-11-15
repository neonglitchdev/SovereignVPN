"""Prove del registro dei peer (FR-PEER-001/002/003/006, ANC-0237/0238/0244/0288, H1, H2).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, json, os, pathlib, sqlite3, stat, subprocess, sys, tempfile, unittest

from sovereignctl import peer
from test_preflight import esegui

QUI = pathlib.Path(__file__).resolve().parents[1]


def chiave():
    return base64.b64encode(os.urandom(32)).decode()


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(prefix="registro-")
        self.db = os.path.join(self._t.name, "registro.sqlite3")

    def tearDown(self):
        self._t.cleanup()

    def cli(self, *argomenti):
        return esegui(["peer", *argomenti[:1], "--db", self.db, *argomenti[1:]])

    def add(self, nome, k=None, *extra):
        codice, out, err = self.cli("add", "--name", nome, "--public-key", k or chiave(), "--json", *extra)
        return codice, (json.loads(out) if codice == 0 else None), err

    def audit(self):
        db = sqlite3.connect(self.db)
        return [json.loads(r[0]) for r in db.execute("SELECT evento FROM audit ORDER BY n")]

    def forza(self, id_peer, stato):  # simula la riconciliazione, che arriva nel pezzo successivo
        db = sqlite3.connect(self.db)
        db.execute("UPDATE peer SET stato = ?, saga = 'APPLIED' WHERE id = ?", (stato, id_peer)); db.commit()


class Aggiunta(Base):
    def test_primo_peer_dopo_il_server_pending_e_saga_da_applicare(self):
        codice, p, err = self.add("Telefono")
        self.assertEqual(codice, 0, err)
        self.assertEqual((p["indirizzo"], p["stato"], p["saga"]), ("10.66.0.2", "PENDING", "PENDING_APPLY"))
        self.assertFalse(p["chiave_privata_sul_server"])
        self.assertEqual(self.add("Portatile")[1]["indirizzo"], "10.66.0.3")
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode), 0o600)

    def test_nome_duplicato_anche_con_maiuscole_e_spazi(self):
        self.add("Telefono di casa")
        codice, _, err = self.add("  telefono   DI casa ")
        self.assertEqual(codice, 2)
        self.assertIn("gia' in uso", err)
        self.assertEqual(self.audit()[-1]["outcome"], "denied")

    def test_chiave_duplicata(self):
        k = chiave(); self.add("uno", k)
        codice, _, err = self.add("due", k)
        self.assertEqual(codice, 2)
        self.assertIn("--public-key", err)

    def test_chiavi_non_valide(self):
        for k in ("non-base64!!", base64.b64encode(os.urandom(31)).decode(), base64.b64encode(os.urandom(33)).decode()):
            with self.subTest(k=k):
                codice, _, err = self.add(f"p{len(k)}", k)
                self.assertEqual(codice, 2)
                self.assertIn("--public-key", err)

    def test_nomi_non_validi(self):
        for nome in ("", "../etc/passwd", "a/b", "x" * 65, "nome;rm"):
            with self.subTest(nome=nome):
                self.assertEqual(self.add(nome)[0], 2)

    def test_ttl(self):
        self.assertEqual(self.add("zero", None, "--ttl-days", "0")[0], 2)
        self.assertEqual(self.add("troppo", None, "--ttl-days", "366")[0], 2)
        codice, p, _ = self.add("trenta", None, "--ttl-days", "30")
        self.assertEqual(codice, 0)
        self.assertTrue(p["scade"].endswith("Z"))

    def test_subnet_esaurita(self):
        cfg = os.path.join(self._t.name, "server.toml")
        pathlib.Path(cfg).write_text('schema_version = 1\nendpoint = "vpn.example.org"\nsubnet = "10.70.0.0/29"\n')
        indirizzi = [self.add(f"p{i}", None, "--config", cfg)[1]["indirizzo"] for i in range(5)]
        self.assertEqual(indirizzi, [f"10.70.0.{i}" for i in range(2, 7)])
        codice, _, err = self.add("sesto", None, "--config", cfg)
        self.assertEqual(codice, 2)
        self.assertIn("SUBNET_EXHAUSTED", err)

    def test_allocazione_concorrente_non_duplica(self):
        """FR-PEER-001: 12 processi nello stesso istante, 12 indirizzi diversi."""
        self.add("primo")  # crea lo schema prima della corsa
        processi = [subprocess.Popen([sys.executable, "-m", "sovereignctl", "peer", "add", "--db", self.db, "--name", f"corsa{i}",
                                      "--public-key", chiave(), "--json"], cwd=QUI, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for i in range(12)]
        esiti = [(p.wait(timeout=60), p.stdout.read(), p.stderr.read()) for p in processi]
        self.assertEqual([c for c, _, _ in esiti], [0] * 12, [e for _, _, e in esiti if e])
        indirizzi = [json.loads(o)["indirizzo"] for _, o, _ in esiti]
        self.assertEqual(len(set(indirizzi)), 12)


# L'oracolo della matrice, scritto dai requisiti e NON preso dal codice: FR-PEER-006 (sospensione reversibile, revoca
# irreversibile), H1 (nessun REVOKED_PENDING). Le transizioni verso ACTIVE/ERROR/EXPIRED le fa la riconciliazione.
ATTESE = {("PENDING", "revoke"): "REVOKED", ("ACTIVE", "suspend"): "SUSPENDED", ("ACTIVE", "revoke"): "REVOKED",
          ("SUSPENDED", "resume"): "ACTIVE", ("SUSPENDED", "revoke"): "REVOKED", ("EXPIRED", "revoke"): "REVOKED",
          ("ERROR", "revoke"): "REVOKED"}


class Stati(Base):
    def test_matrice_completa_delle_transizioni(self):
        """Ogni (stato, azione) fuori da TRANSIZIONI e' respinta e lascia un evento denied; quelle dentro passano."""
        for stato in peer.STATI:
            for azione in ("suspend", "resume", "revoke"):
                with self.subTest(stato=stato, azione=azione):
                    _, p, _ = self.add(f"{stato}-{azione}")
                    self.forza(p["id"], stato)
                    codice, out, err = self.cli(azione, p["id"], "--json")
                    atteso = ATTESE.get((stato, azione))
                    if atteso:
                        self.assertEqual(codice, 0, err)
                        self.assertEqual((json.loads(out)["stato"], json.loads(out)["saga"]), (atteso, "PENDING_APPLY"))
                    else:
                        self.assertEqual(codice, 2)
                        self.assertEqual(self.audit()[-1]["outcome"], "denied")

    def test_revoca_irreversibile_e_non_completata_finche_non_applicata(self):
        _, p, _ = self.add("da revocare")
        self.forza(p["id"], "ACTIVE")
        codice, out, _ = self.cli("revoke", p["id"], "--json")
        r = json.loads(out)
        self.assertEqual((r["stato"], r["saga"]), ("REVOKED", "PENDING_APPLY"))  # ANC-0288: non ancora completata
        self.assertTrue(r["revocato"].endswith("Z"))
        for azione in ("resume", "suspend", "revoke"):
            codice, _, err = self.cli(azione, p["id"])
            self.assertEqual(codice, 2)
        self.assertIn("irreversibile", err)

    def test_sospensione_reversibile(self):
        _, p, _ = self.add("sospendibile")
        self.forza(p["id"], "ACTIVE")
        self.assertEqual(json.loads(self.cli("suspend", p["id"], "--json")[1])["stato"], "SUSPENDED")
        self.assertEqual(json.loads(self.cli("resume", p["id"], "--json")[1])["stato"], "ACTIVE")


class Lettura(Base):
    def test_show_e_list_senza_segreti_e_id_sbagliati(self):
        _, p, _ = self.add("telefono")
        codice, out, _ = self.cli("list", "--json")
        self.assertEqual(codice, 0)
        self.assertNotIn("chiave_pubblica", json.loads(out)[0])  # metadati non sensibili (ANC-0254)
        self.assertEqual(self.cli("show", "non-un-uuid")[0], 2)
        codice, _, err = self.cli("show", "00000000-0000-4000-8000-000000000000")
        self.assertEqual(codice, 2)
        self.assertIn("PEER_NOT_FOUND", err)

    def test_audit_coi_campi_di_ANC_0232_e_id_registrati(self):
        _, p, _ = self.add("telefono")
        e = self.audit()[-1]
        self.assertEqual(set(e), {"id", "timestamp", "actor", "action", "target", "outcome", "request_id", "reason"})
        self.assertEqual((e["action"], e["target"], e["outcome"]), ("peer.add", p["id"], "success"))
        db = sqlite3.connect(self.db)
        self.assertEqual(db.execute("SELECT count(*) FROM id_usati WHERE id = ?", (p["id"],)).fetchone()[0], 1)

    def test_schema_sconosciuto_esce_con_1(self):
        self.add("telefono")
        db = sqlite3.connect(self.db); db.execute("UPDATE schema SET versione = 99"); db.commit()
        codice, _, err = self.cli("list")
        self.assertEqual(codice, 1)
        self.assertIn("migrazione", err)


if __name__ == "__main__":
    unittest.main()
